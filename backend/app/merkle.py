"""Binary Merkle commitment over the fixed-size sealing chunks.

The commitment is built in a single, fully specified order so that any
party holding the raw bytes can independently rebuild the same root:

* leaves, in ascending chunk-index order, bind **three** facts about a
  block -- its zero-based index, its actual on-disk length (the final
  block may be short) and its SHA-256 digest -- via domain-separated
  encoding;
* internal nodes are SHA-256 over a distinct domain prefix and the two
  child digests;
* an odd node count at any level is completed by promoting the lone node
  unchanged (a fixed, hash-free "duplicate last node" rule -- no sibling
  is ever fabricated, which keeps every inclusion proof minimal).

Domain prefixes make leaf and node preimages mutually disjoint, so a
32-byte leaf digest can never be reinterpreted as (or collide with) an
internal-node preimage.
"""

from __future__ import annotations

import hashlib
import json
from typing import Optional

MERKLE_ALGORITHM_VERSION = "merkle-sha256-v1"

_LEAF_DOMAIN = b"merkle-leaf:v1:"
_NODE_DOMAIN = b"merkle-node:v1:"


def leaf_digest(index: int, length: int, chunk_sha256: str) -> bytes:
    """Digest committing to one block: index + actual length + digest.

    The preimage is ``domain || JSON(canonical fields)``.  JSON with
    sort_keys and fixed separators is a deterministic byte encoding; the
    domain prefix makes it unforgeable as an internal node.
    """
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("leaf index must be a non-negative integer")
    if not isinstance(length, int) or isinstance(length, bool) or length < 0:
        raise ValueError("leaf length must be a non-negative integer")
    if not isinstance(chunk_sha256, str) or len(chunk_sha256) != 64:
        raise ValueError("chunk digest must be a 64-character hex string")
    payload = json.dumps(
        {"i": index, "l": length, "d": chunk_sha256},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(_LEAF_DOMAIN + payload).digest()


def node_digest(left: bytes, right: bytes) -> bytes:
    """Parent digest over two 32-byte children, domain-separated."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle children must be 32-byte digests")
    return hashlib.sha256(_NODE_DOMAIN + left + right).digest()


def build_root(leaves: list[bytes]) -> bytes:
    """Return the Merkle root for an ordered, non-empty list of leaves.

    Odd level: the last, unpaired node is carried up unchanged.
    """
    if not leaves:
        raise ValueError("cannot build a Merkle root from zero leaves")
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for k in range(0, len(level) - 1, 2):
            nxt.append(node_digest(level[k], level[k + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # fixed odd-node padding: promote unchanged
        level = nxt
    return level[0]


def inclusion_proof(leaves: list[bytes], index: int) -> list[dict]:
    """Minimal sibling path for ``index`` against the tree of ``leaves``.

    Each step records the sibling together with its position relative to
    the running subtree.  A promoted (unpaired) node adds no step.
    """
    if not 0 <= index < len(leaves):
        raise ValueError("proof index out of range")
    level = list(leaves)
    pos = index
    proof: list[dict] = []
    while len(level) > 1:
        if pos % 2 == 0:
            if pos + 1 < len(level):
                proof.append({"side": "right", "digest": level[pos + 1].hex()})
            # unpaired last node: promoted, no sibling
        else:
            proof.append({"side": "left", "digest": level[pos - 1].hex()})
        nxt: list[bytes] = []
        for k in range(0, len(level) - 1, 2):
            nxt.append(node_digest(level[k], level[k + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # fixed odd-node padding: promote unchanged
        level = nxt
        pos //= 2
    return proof


def evaluate_proof(
    index: int,
    length: int,
    chunk_sha256: str,
    proof: list[dict],
    leaf_count: int,
) -> bytes:
    """Rebuild a root from one leaf and its sibling path.

    Independent of the server: this is exactly what a receiver runs.  The
    leaf's expected parity at each level is derived from ``index`` and the
    known ``leaf_count``, so the ``side`` carried in the proof is only a
    hint -- the recomputed position is authoritative.
    """
    if not isinstance(leaf_count, int) or leaf_count <= 0:
        raise ValueError("leaf_count must be a positive integer")
    if not 0 <= index < leaf_count:
        raise ValueError("leaf index out of range")
    current = leaf_digest(index, length, chunk_sha256)
    pos = index
    count = leaf_count
    step = 0
    while count > 1:
        if pos % 2 == 0 and pos + 1 < count:
            if step >= len(proof):
                raise ValueError(f"proof too short: missing sibling at level {step}")
            item = proof[step]
            if item.get("side") != "right":
                raise ValueError(f"proof step {step} has wrong side")
            current = node_digest(current, _sibling_bytes(item))
            step += 1
        elif pos % 2 == 1:
            if step >= len(proof):
                raise ValueError(f"proof too short: missing sibling at level {step}")
            item = proof[step]
            if item.get("side") != "left":
                raise ValueError(f"proof step {step} has wrong side")
            current = node_digest(_sibling_bytes(item), current)
            step += 1
        # unpaired (pos even, last node): promoted, consume no proof step
        pos //= 2
        count = (count + 1) // 2
    if step != len(proof):
        raise ValueError("proof contains extra sibling steps")
    return current


def _sibling_bytes(item: dict) -> bytes:
    raw = item.get("digest")
    if not isinstance(raw, str):
        raise ValueError("proof sibling digest must be hex text")
    try:
        value = bytes.fromhex(raw)
    except ValueError:
        raise ValueError("proof sibling digest is not valid hex")
    if len(value) != 32:
        raise ValueError("proof sibling digest must be 32 bytes")
    return value


def verify_root(root_hex: Optional[str], rebuilt: bytes) -> bool:
    if not isinstance(root_hex, str):
        return False
    try:
        root = bytes.fromhex(root_hex)
    except ValueError:
        return False
    return len(root) == 32 and root == rebuilt
