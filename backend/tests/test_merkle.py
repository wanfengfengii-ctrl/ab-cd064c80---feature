"""Unit tests for the Merkle commitment module (domain encoding, fixed
padding rule, minimal range proofs, reference verifier)."""

from __future__ import annotations

import hashlib
import os

import pytest

from app import merkle


def _leaf(index: int, length: int, digest: bytes) -> bytes:
    # Independent re-implementation of the documented encoding.
    return hashlib.sha256(
        merkle.LEAF_DOMAIN
        + index.to_bytes(8, "big")
        + length.to_bytes(8, "big")
        + digest
    ).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(merkle.NODE_DOMAIN + left + right).digest()


def _leaves(n: int, length: int = 65536) -> list[bytes]:
    return [
        _leaf(i, length, hashlib.sha256(bytes([i]) * (i + 1)).digest())
        for i in range(n)
    ]


def test_leaf_binds_index_length_and_digest():
    digest = hashlib.sha256(b"payload").digest()
    base = merkle.leaf_hash(3, 100, digest)
    assert base == _leaf(3, 100, digest)
    # Any change to index, length or digest changes the leaf.
    assert merkle.leaf_hash(4, 100, digest) != base
    assert merkle.leaf_hash(3, 101, digest) != base
    assert merkle.leaf_hash(3, 100, hashlib.sha256(b"other").digest()) != base


def test_domain_separation_between_leaf_and_node():
    digest = hashlib.sha256(b"x").digest()
    leaf = merkle.leaf_hash(0, 32, digest)
    # A node over the same 64 bytes of material must differ from any leaf.
    assert merkle.node_hash(digest, digest) != leaf
    assert merkle.node_hash(digest, digest) == _node(digest, digest)


def test_single_leaf_root_is_the_leaf():
    leaves = _leaves(1)
    assert merkle.build_root(leaves) == leaves[0]


def test_known_tree_shapes_and_odd_level_padding():
    leaves = _leaves(6)
    l0, l1, l2, l3, l4, l5 = leaves

    assert merkle.build_root(leaves[:2]) == _node(l0, l1)
    # n=3: odd level duplicates the last node -> node(node(l0,l1), node(l2,l2))
    assert merkle.build_root(leaves[:3]) == _node(
        _node(l0, l1), _node(l2, l2)
    )
    # n=4: balanced
    assert merkle.build_root(leaves[:4]) == _node(
        _node(l0, l1), _node(l2, l3)
    )
    # n=5: level1 = [n01, n23, n44], level2 = [n0123, n4444], root above them
    n44 = _node(l4, l4)
    assert merkle.build_root(leaves[:5]) == _node(
        _node(_node(l0, l1), _node(l2, l3)), _node(n44, n44)
    )
    # n=6: level1 = [n01, n23, n45] (odd) -> level2 = [n0123, node(n45, n45)]
    n45 = _node(l4, l5)
    assert merkle.build_root(leaves) == _node(
        _node(_node(l0, l1), _node(l2, l3)), _node(n45, n45)
    )


def test_level_geometry():
    for n in range(1, 130):
        height = merkle.tree_height(n)
        assert merkle.level_width(n, height) == 1
        for k in range(height + 1):
            assert merkle.level_width(n, k) == -(-n // (1 << k))  # ceil
        lo, hi = merkle._interval(height, 0, n)
        assert (lo, hi) == (0, n - 1)
    with pytest.raises(ValueError):
        merkle.tree_height(0)


def _verify(n: int, start: int, end: int, digests, lengths, proof, root) -> bool:
    return merkle.verify_range(n, start, end, digests, lengths, proof, root)


def test_range_proof_roundtrip_for_all_ranges():
    for n in (1, 2, 3, 4, 5, 7, 8, 9, 16, 33):
        raw = [os.urandom(17 + i) for i in range(n)]
        digests = [hashlib.sha256(b).digest() for b in raw]
        lengths = [len(b) for b in raw]
        leaves = [merkle.leaf_hash(i, lengths[i], digests[i]) for i in range(n)]
        root = merkle.build_root(leaves)
        for start in range(n):
            for end in range(start, n):
                proof = merkle.range_proof(leaves, start, end)
                assert _verify(
                    n,
                    start,
                    end,
                    digests[start : end + 1],
                    lengths[start : end + 1],
                    proof,
                    root,
                ), (n, start, end)


def test_full_range_proof_is_empty():
    leaves = _leaves(7)
    assert merkle.range_proof(leaves, 0, 6) == []
    leaves = _leaves(1)
    assert merkle.range_proof(leaves, 0, 0) == []


def test_proof_rejects_tampered_data():
    n = 6
    digests = [hashlib.sha256(bytes([i])).digest() for i in range(n)]
    lengths = [65536] * n
    leaves = [merkle.leaf_hash(i, lengths[i], digests[i]) for i in range(n)]
    root = merkle.build_root(leaves)
    proof = merkle.range_proof(leaves, 1, 3)

    # wrong chunk digest inside the range
    bad = list(digests[1:4])
    bad[1] = hashlib.sha256(b"evil").digest()
    assert not _verify(n, 1, 3, bad, lengths[1:4], proof, root)
    # wrong length binding
    bad_len = list(lengths[1:4])
    bad_len[0] += 1
    assert not _verify(n, 1, 3, digests[1:4], bad_len, proof, root)
    # truncated / extended proof
    assert not _verify(n, 1, 3, digests[1:4], lengths[1:4], proof[:-1], root)
    assert not _verify(
        n, 1, 3, digests[1:4], lengths[1:4], proof + [b"\x00" * 32], root
    )
    # wrong expected root
    assert not _verify(
        n, 1, 3, digests[1:4], lengths[1:4], proof, b"\x01" * 32
    )
    # range shifted against the same proof
    assert not _verify(n, 2, 4, digests[1:4], lengths[1:4], proof, root)


def test_proof_is_minimal_sibling_set():
    # n=8 (perfect tree), range [2,3]: siblings are node[0,1] and node[4,7].
    leaves = _leaves(8)
    assert len(merkle.range_proof(leaves, 2, 3)) == 2
    # Single-leaf range in 8 leaves needs exactly log2(8) = 3 siblings.
    assert len(merkle.range_proof(leaves, 5, 5)) == 3
    # n=6, range [4,5]: only the left half [0,3] is needed as a sibling.
    leaves6 = _leaves(6)
    assert len(merkle.range_proof(leaves6, 4, 5)) == 1
    # n=6, range [0,0]: sibling chain is leaf1, node[2,3], node(node45,node45).
    assert len(merkle.range_proof(leaves6, 0, 0)) == 3
