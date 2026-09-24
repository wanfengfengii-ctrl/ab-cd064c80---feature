"""Tests for the Merkle commitment, range proofs and legacy-receipt migration."""

from __future__ import annotations

import hashlib
import json
import os

import pytest
from fastapi.testclient import TestClient

from app import main as web
from app import merkle
from app.storage import CHUNK_SIZE, UploadStore


@pytest.fixture()
def client(tmp_path):
    web.store = UploadStore(str(tmp_path / "data"))
    return TestClient(web.app)


def _digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _seal(client, session, blob: bytes) -> dict:
    sha = _digest(blob)
    count = (len(blob) + CHUNK_SIZE - 1) // CHUNK_SIZE
    for i in range(count):
        r = client.put(
            f"/api/uploads/{session}/chunks",
            content=blob[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE],
            headers={
                "X-Chunk-Offset": str(i * CHUNK_SIZE),
                "X-Total-Size": str(len(blob)),
                "X-Content-SHA256": sha,
            },
        )
        assert r.status_code == 200, r.text
    r = client.post(f"/api/uploads/{session}/seal")
    assert r.status_code == 200, r.text
    return r.json()


def _verify_block(block: dict, root: str, leaf_count: int) -> bytes:
    return merkle.evaluate_proof(
        block["index"], block["length"], block["sha256"], block["proof"], leaf_count
    )


# ---------------------------------------------------------------------------
# pure Merkle mechanics
# ---------------------------------------------------------------------------


def test_leaf_binds_index_length_and_digest():
    a = merkle.leaf_digest(0, 10, "a" * 64)
    assert a != merkle.leaf_digest(1, 10, "a" * 64)       # index bound
    assert a != merkle.leaf_digest(0, 11, "a" * 64)       # length bound
    assert a != merkle.leaf_digest(0, 10, "b" + "a" * 63) # digest bound
    # canonical encoding: JSON is sorted d,i,l with no spaces
    expect = hashlib.sha256(
        b"merkle-leaf:v1:"
        + json.dumps(
            {"d": "a" * 64, "i": 0, "l": 10},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).digest()
    assert a == expect


def test_domain_separation_leaf_vs_node():
    leaf = merkle.leaf_digest(0, 1, "a" * 64)
    # A node preimage is 15-byte domain + 64 bytes; a leaf preimage never is.
    node = merkle.node_digest(b"\x00" * 32, b"\x00" * 32)
    assert leaf != node


def test_odd_level_promotion_is_fixed():
    leaves = [merkle.leaf_digest(i, 1, f"{i:064d}") for i in range(3)]
    root = merkle.build_root(leaves)
    # Explicit construction: level0 = H(l0,l1); l2 promoted unchanged.
    level0 = merkle.node_digest(leaves[0], leaves[1])
    assert root == merkle.node_digest(level0, leaves[2])
    # Hashing the lone node with a fabricated duplicate gives a different root,
    # pinning down the "promote unchanged, no padding hash" rule.
    padded = merkle.node_digest(level0, merkle.node_digest(leaves[2], leaves[2]))
    assert root != padded


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17, 100])
def test_inclusion_proofs_roundtrip_for_every_index(n):
    digests = [hashlib.sha256(bytes([i])).hexdigest() for i in range(n)]
    leaves = [merkle.leaf_digest(i, 64, digests[i]) for i in range(n)]
    root = merkle.build_root(leaves).hex()
    for i in range(n):
        proof = merkle.inclusion_proof(leaves, i)
        rebuilt = merkle.evaluate_proof(i, 64, digests[i], proof, n)
        assert rebuilt.hex() == root, (n, i)
        # proof is minimal: never taller than ceil(log2(n))
        assert len(proof) <= (n - 1).bit_length()


def test_evaluate_proof_rejects_bad_side_and_length():
    leaves = [merkle.leaf_digest(i, 1, hashlib.sha256(bytes([i])).hexdigest())
              for i in range(4)]
    proof = merkle.inclusion_proof(leaves, 1)
    # wrong side hint
    bad = [{"side": "right", "digest": proof[0]["digest"]}, *proof[1:]]
    with pytest.raises(ValueError):
        merkle.evaluate_proof(1, 1, hashlib.sha256(b"\x01").hexdigest(), bad, 4)
    # truncated / over-long paths
    with pytest.raises(ValueError):
        merkle.evaluate_proof(1, 1, hashlib.sha256(b"\x01").hexdigest(), proof[:-1], 4)
    with pytest.raises(ValueError):
        merkle.evaluate_proof(1, 1, hashlib.sha256(b"\x01").hexdigest(),
                              proof + [{"side": "left", "digest": "00" * 32}], 4)
    with pytest.raises(ValueError):
        merkle.evaluate_proof(4, 1, "a" * 64, [], 4)  # index out of range


# ---------------------------------------------------------------------------
# commitment is atomically tied to a new receipt
# ---------------------------------------------------------------------------


def test_seal_writes_commitment_and_root_in_receipt(client, tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE + 5)
    receipt = _seal(client, "s1", blob)
    assert receipt["merkle_algorithm"] == "merkle-sha256-v1"
    root = receipt["merkle_root"]
    assert re_match_sha256(root)

    sdir = tmp_path / "data" / "s1"
    record = json.loads((sdir / "commitment.json").read_text())
    assert record["merkle_root"] == root
    assert record["receipt_id"] == receipt["receipt_id"]
    assert record["chunk_count"] == 4
    assert [leaf["index"] for leaf in record["leaves"]] == [0, 1, 2, 3]
    assert [leaf["length"] for leaf in record["leaves"]] == [
        CHUNK_SIZE, CHUNK_SIZE, CHUNK_SIZE, 5
    ]
    # independent rebuild over the recorded leaves reaches the same root
    rebuilt = merkle.build_root([
        merkle.leaf_digest(l["index"], l["length"], l["sha256"])
        for l in record["leaves"]
    ]).hex()
    assert rebuilt == root

    status = client.get("/api/uploads/s1").json()
    assert status["sealed"] is True
    assert status["commitment"]["merkle_root"] == root
    assert status["receipt"]["merkle_root"] == root

    # repeat seal keeps returning the SAME receipt, root included
    assert client.post("/api/uploads/s1/seal").json() == receipt


def re_match_sha256(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        ch in "0123456789abcdef" for ch in value
    )


def test_commitment_survives_restart(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 1)
    receipt = _seal(client, "dur", blob)
    web.store = UploadStore(str(tmp_path / "data"))
    again = client.post("/api/uploads/dur/seal").json()
    assert again == receipt
    r = client.get("/api/uploads/dur/proof?start=0&end=1")
    assert r.status_code == 200


def test_missing_derived_record_is_rebuilt_from_sealed_bytes(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 6)
    receipt = _seal(client, "rb1", blob)
    os.unlink(tmp_path / "data" / "rb1" / "commitment.json")
    # first proof transparently rescans and persists the derived record
    r = client.get("/api/uploads/rb1/proof?start=0&end=2")
    assert r.status_code == 200, r.text
    block = r.json()["blocks"][0]
    assert _verify_block(block, receipt["merkle_root"], 3).hex() == \
        receipt["merkle_root"]
    assert (tmp_path / "data" / "rb1" / "commitment.json").exists()


# ---------------------------------------------------------------------------
# range proofs
# ---------------------------------------------------------------------------


def test_full_and_partial_range_proofs_verify(client):
    blob = os.urandom(4 * CHUNK_SIZE + 7)  # 5 leaves
    receipt = _seal(client, "s2", blob)
    root = receipt["merkle_root"]

    r = client.get("/api/uploads/s2/proof?start=0&end=4")
    assert r.status_code == 200, r.text
    proof = r.json()
    assert proof["range"] == {"start": 0, "end": 4}
    assert proof["receipt_id"] == receipt["receipt_id"]
    assert proof["algorithm"] == "merkle-sha256-v1"
    assert proof["file_sha256"] == _digest(blob)
    assert [b["index"] for b in proof["blocks"]] == [0, 1, 2, 3, 4]
    for block in proof["blocks"]:
        assert _verify_block(block, root, 5).hex() == root
        assert block["offset"] == block["index"] * CHUNK_SIZE
        # the claimed block digest really is the digest of those bytes
        assert block["sha256"] == hashlib.sha256(
            blob[block["offset"]:block["offset"] + block["length"]]
        ).hexdigest()

    r = client.get("/api/uploads/s2/proof?start=1&end=3")
    assert r.status_code == 200
    proof = r.json()
    assert [b["index"] for b in proof["blocks"]] == [1, 2, 3]
    for block in proof["blocks"]:
        assert _verify_block(block, root, 5).hex() == root


def test_single_block_range_and_single_chunk_file(client):
    blob = os.urandom(2 * CHUNK_SIZE + 1)
    root = _seal(client, "s3", blob)["merkle_root"]
    proof = client.get("/api/uploads/s3/proof?start=2&end=2").json()
    block = proof["blocks"][0]
    assert block["length"] == 1
    assert _verify_block(block, root, 3).hex() == root

    one = _seal(client, "one", b"a")
    proof = client.get("/api/uploads/one/proof?start=0&end=0").json()
    assert proof["blocks"][0]["proof"] == []  # one leaf: root == leaf
    assert _verify_block(proof["blocks"][0], one["merkle_root"], 1).hex() == one["merkle_root"]


def test_invalid_ranges_rejected(client):
    _seal(client, "s4", os.urandom(4 * CHUNK_SIZE + 1))  # 5 chunks, indices 0..4
    bad_queries = [
        "", "?start=0", "?end=1", "?start=3&end=1", "?start=-1&end=0",
        "?start=0&end=5", "?start=01&end=4", "?start=x&end=1",
    ]
    for query in bad_queries:
        r = client.get(f"/api/uploads/s4/proof{query}")
        assert r.status_code == 400, (query, r.status_code, r.text)


def test_proof_requires_sealed_provable_session(client):
    # unknown session
    assert client.get("/api/uploads/nope/proof?start=0&end=0").status_code == 404
    # incomplete (unsealed) session
    blob = os.urandom(CHUNK_SIZE + 1)
    client.put(
        "/api/uploads/up/chunks", content=blob[:CHUNK_SIZE],
        headers={"X-Chunk-Offset": "0", "X-Total-Size": str(len(blob)),
                 "X-Content-SHA256": _digest(blob)})
    r = client.get("/api/uploads/up/proof?start=0&end=1")
    assert r.status_code == 409
    assert "not sealed" in r.json()["error"]


# ---------------------------------------------------------------------------
# legacy receipts: independent commitment via a full rescan
# ---------------------------------------------------------------------------


def _make_legacy(tmp_path, session: str) -> str:
    """Strip the Merkle fields from a fresh receipt, remove commitment.json."""
    sdir = tmp_path / "data" / session
    rp = sdir / "receipt.json"
    old = json.loads(rp.read_text())
    del old["merkle_root"]
    del old["merkle_algorithm"]
    rp.write_text(json.dumps(old, indent=2))
    (sdir / "commitment.json").unlink()
    return str(rp)


def test_legacy_receipt_proof_refused_until_rescan(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 9)
    receipt = _seal(client, "leg", blob)
    rp = _make_legacy(tmp_path, "leg")

    # no root -> cannot prove yet
    r = client.get("/api/uploads/leg/proof?start=0&end=2")
    assert r.status_code == 409
    assert "legacy receipt" in r.json()["error"]

    # full rescan builds the independent commitment; receipt is NOT rewritten
    r = client.post("/api/uploads/leg/commitment")
    assert r.status_code == 200, r.text
    record = r.json()
    assert record["merkle_root"] == receipt["merkle_root"]
    on_disk = json.loads(open(rp).read())
    assert "merkle_root" not in on_disk
    assert on_disk["receipt_id"] == receipt["receipt_id"]

    proof = client.get("/api/uploads/leg/proof?start=0&end=2").json()
    for block in proof["blocks"]:
        assert _verify_block(block, receipt["merkle_root"], 3).hex() == \
            receipt["merkle_root"]

    # rescan is idempotent and repeat sealing still returns the old receipt
    assert client.post("/api/uploads/leg/commitment").json() == record
    assert client.post("/api/uploads/leg/seal").json() == on_disk


def test_legacy_rescan_refused_on_missing_block(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 3)
    _seal(client, "leg2", blob)
    _make_legacy(tmp_path, "leg2")
    os.unlink(tmp_path / "data" / "leg2" / "chunks" / "00000001")

    r = client.post("/api/uploads/leg2/commitment")
    assert r.status_code == 409
    assert "missing" in r.json()["error"]
    assert not (tmp_path / "data" / "leg2" / "commitment.json").exists()
    # session stays sealed/non-writable
    r = client.put("/api/uploads/leg2/chunks", content=blob[CHUNK_SIZE:2 * CHUNK_SIZE],
                   headers={"X-Chunk-Offset": str(CHUNK_SIZE)})
    assert r.status_code in (409, 500)


def test_legacy_rescan_refused_on_digest_mismatch(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 3)
    receipt = _seal(client, "leg3", blob)
    rp = _make_legacy(tmp_path, "leg3")
    # tamper with a sealed block; the receipt's file digest can no longer match
    p = tmp_path / "data" / "leg3" / "chunks" / "00000001"
    p.write_bytes(b"\x00" * 3)
    r = client.post("/api/uploads/leg3/commitment")
    assert r.status_code == 409
    assert "digest" in r.json()["error"]
    assert not (tmp_path / "data" / "leg3" / "commitment.json").exists()
    # receipt untouched
    assert json.loads(open(rp).read())["receipt_id"] == receipt["receipt_id"]


def test_legacy_commitment_requires_sealed_session(client):
    assert client.post("/api/uploads/ghost/commitment").status_code == 404
    blob = os.urandom(10)
    client.put(
        "/api/uploads/u2/chunks", content=blob,
        headers={"X-Chunk-Offset": "0", "X-Total-Size": "10",
                 "X-Content-SHA256": _digest(blob)})
    assert client.post("/api/uploads/u2/commitment").status_code == 409


# ---------------------------------------------------------------------------
# corruption: proofs refused, session stays non-writable
# ---------------------------------------------------------------------------


def test_corrupt_receipt_blocks_proof_and_writes(client, tmp_path):
    blob = os.urandom(CHUNK_SIZE + 2)
    _seal(client, "corr", blob)
    rp = tmp_path / "data" / "corr" / "receipt.json"
    rp.write_text("{broken json")

    assert client.get("/api/uploads/corr/proof?start=0&end=1").status_code == 500
    assert client.get("/api/uploads/corr").status_code == 500
    # identical retransmit of an existing chunk must not be accepted as 200:
    # integrity failure takes precedence, session is not writable
    r = client.put("/api/uploads/corr/chunks", content=blob[:CHUNK_SIZE],
                   headers={"X-Chunk-Offset": "0"})
    assert r.status_code in (409, 500)
    assert r.status_code != 200


def test_proof_refused_when_sealed_bytes_corrupted_under_new_receipt(client, tmp_path):
    blob = os.urandom(2 * CHUNK_SIZE + 4)
    root = _seal(client, "c2", blob)["merkle_root"]
    # remove the derived record and corrupt a block; rebuilding must detect it
    os.unlink(tmp_path / "data" / "c2" / "commitment.json")
    p = tmp_path / "data" / "c2" / "chunks" / "00000000"
    tampered = bytearray(p.read_bytes())
    tampered[0] ^= 0xFF
    p.write_bytes(bytes(tampered))
    r = client.get("/api/uploads/c2/proof?start=0&end=2")
    assert r.status_code == 409
    assert "Merkle root" in r.json()["error"] or "digest" in r.json()["error"]
    assert root  # root stays pinned in the untouched receipt
