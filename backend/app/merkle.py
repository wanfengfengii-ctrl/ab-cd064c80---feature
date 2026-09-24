"""Binary Merkle commitment over the fixed chunk sequence of a sealed upload.

Algorithm id ``merkle-sha256-v1``. Domain-separated encoding:

  leaf: SHA256(LEAF_DOMAIN || index:uint64be || length:uint64be || chunk_sha256:32B)
  node: SHA256(NODE_DOMAIN || left:32B || right:32B)

Leaves are built in the fixed chunk order (index 0..n-1); each leaf binds the
chunk index, its actual length and its SHA-256 digest. The tree is built level
by level with one fixed padding rule for odd levels: the last node of an odd
level is duplicated as its own right sibling (``node(h, h)``). A single-leaf
tree's root is the leaf itself.

Node (level k, index j) covers the leaf interval
``[j*2^k, min((j+1)*2^k, n) - 1]``; level k holds ``ceil(n / 2^k)`` nodes.
Range proofs navigate exactly this tree, so prover and every verifier agree
on one canonical shape.
"""

from __future__ import annotations

import hashlib

ALGORITHM = "merkle-sha256-v1"

# ASCII domain separators; the trailing colon is part of the tag.
LEAF_DOMAIN = b"cryo-seal-desk/merkle/v1/leaf:"
NODE_DOMAIN = b"cryo-seal-desk/merkle/v1/node:"

ENCODING_DOC = (
    "leaf=sha256(leaf_domain|index:u64be|length:u64be|chunk_sha256); "
    "node=sha256(node_domain|left|right); "
    "levels built bottom-up, odd levels duplicate the last node; "
    "single-leaf tree root is the leaf"
)


def leaf_hash(index: int, length: int, chunk_digest: bytes) -> bytes:
    """Hash one leaf: binds chunk index, actual length and chunk digest."""
    if len(chunk_digest) != 32:
        raise ValueError("chunk digest must be 32 raw bytes")
    return hashlib.sha256(
        LEAF_DOMAIN
        + index.to_bytes(8, "big")
        + length.to_bytes(8, "big")
        + chunk_digest
    ).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash one interior node from its two (ordered) children."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("node children must be 32 raw bytes")
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def level_width(leaf_count: int, level: int) -> int:
    """Number of nodes at ``level`` for a tree of ``leaf_count`` leaves."""
    return (leaf_count + (1 << level) - 1) >> level


def tree_height(leaf_count: int) -> int:
    """Level of the root (0 for a single leaf)."""
    if leaf_count < 1:
        raise ValueError("leaf_count must be >= 1")
    return (leaf_count - 1).bit_length()


def _build_levels(leaf_hashes: list[bytes]) -> list[list[bytes]]:
    levels = [list(leaf_hashes)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        upper: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            # Fixed odd-level padding: duplicate the last node.
            right = current[i + 1] if i + 1 < len(current) else left
            upper.append(node_hash(left, right))
        levels.append(upper)
    return levels


def build_root(leaf_hashes: list[bytes]) -> bytes:
    """Root of the level-by-level tree (odd levels duplicate the last node)."""
    if not leaf_hashes:
        raise ValueError("cannot commit to an empty leaf set")
    return _build_levels(leaf_hashes)[-1][0]


def _interval(level: int, index: int, leaf_count: int) -> tuple[int, int]:
    lo = index << level
    hi = min((index + 1) << level, leaf_count) - 1
    return lo, hi


def range_proof(leaf_hashes: list[bytes], start: int, end: int) -> list[bytes]:
    """Minimal sibling proof for the inclusive leaf range [start, end].

    Emits subtree roots in deterministic pre-order (left before right): every
    maximal node whose interval is disjoint from the range contributes exactly
    one hash; nodes fully inside the range contribute nothing (the verifier
    recomputes them from the chunk digests it is given). Where the fixed
    padding rule duplicated a node, the verifier recomputes the copy itself,
    so no hash is emitted for it.
    """
    n = len(leaf_hashes)
    if not 0 <= start <= end < n:
        raise ValueError(f"invalid range [{start}, {end}] for {n} leaves")
    levels = _build_levels(leaf_hashes)
    proof: list[bytes] = []

    def collect(level: int, index: int) -> None:
        lo, hi = _interval(level, index, n)
        if start <= lo and hi <= end:
            return  # fully inside: verifier owns the data
        if hi < start or lo > end:
            proof.append(levels[level][index])  # disjoint sibling subtree
            return
        # Partial overlap: descend. An odd-level shortfall means the right
        # child is a duplicate of the left one and needs no separate entry.
        collect(level - 1, 2 * index)
        if 2 * index + 1 < len(levels[level - 1]):
            collect(level - 1, 2 * index + 1)

    collect(len(levels) - 1, 0)
    return proof


def verify_range(
    leaf_count: int,
    start: int,
    end: int,
    chunk_digests: list[bytes],
    chunk_lengths: list[int],
    proof: list[bytes],
    expected_root: bytes,
) -> bool:
    """Reference verifier: rebuild the root from range data + sibling proof."""
    if leaf_count < 1 or not 0 <= start <= end < leaf_count:
        return False
    if len(chunk_digests) != end - start + 1 or len(chunk_lengths) != end - start + 1:
        return False
    leaves = {
        start + i: leaf_hash(start + i, chunk_lengths[i], chunk_digests[i])
        for i in range(len(chunk_digests))
    }
    pos = 0

    def from_owned_leaves(level: int, index: int) -> bytes:
        if level == 0:
            return leaves[index]
        left = from_owned_leaves(level - 1, 2 * index)
        if 2 * index + 1 < level_width(leaf_count, level - 1):
            right = from_owned_leaves(level - 1, 2 * index + 1)
        else:
            right = left  # fixed odd-level duplication
        return node_hash(left, right)

    def rebuild(level: int, index: int) -> bytes:
        nonlocal pos
        lo, hi = _interval(level, index, leaf_count)
        if hi < start or lo > end:
            if pos >= len(proof):
                raise _ProofShort
            value = proof[pos]
            pos += 1
            return value
        if start <= lo and hi <= end:
            return from_owned_leaves(level, index)
        left = rebuild(level - 1, 2 * index)
        if 2 * index + 1 < level_width(leaf_count, level - 1):
            right = rebuild(level - 1, 2 * index + 1)
        else:
            right = left
        return node_hash(left, right)

    try:
        root = rebuild(tree_height(leaf_count), 0)
    except _ProofShort:
        return False
    return root == expected_root and pos == len(proof)


class _ProofShort(Exception):
    pass
