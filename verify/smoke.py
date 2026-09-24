"""HTTP smoke test for a running sealing-desk instance.

Exercises the whole contract over real HTTP (stdlib only):
  health + SPA, validation, out-of-order PUT, idempotent retransmission,
  409 conflicts that never mutate state, missing-range listing, atomic seal,
  identical receipt on repeated seal, sealed-session immutability, and the
  Merkle commitment/range-proof flow verified by an independent rebuild.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
CHUNK = 65536

# --- independent Merkle verifier (mirrors backend/app/merkle.py) ----------

LEAF_DOMAIN = b"merkle-leaf:v1:"
NODE_DOMAIN = b"merkle-node:v1:"


def leaf_digest(index, length, chunk_sha):
    payload = json.dumps(
        {"i": index, "l": length, "d": chunk_sha},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(LEAF_DOMAIN + payload).digest()


def node_digest(left, right):
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def evaluate_proof(block, leaf_count):
    """Rebuild the root from one proof block; raises ValueError on bad shape."""
    current = leaf_digest(block["index"], block["length"], block["sha256"])
    pos, count, step = block["index"], leaf_count, 0
    proof = block["proof"]
    while count > 1:
        if pos % 2 == 0 and pos + 1 < count:
            if step >= len(proof):
                raise ValueError(f"proof too short at level {step}")
            item = proof[step]
            if item["side"] != "right":
                raise ValueError(f"step {step} side must be right")
            current = node_digest(current, bytes.fromhex(item["digest"]))
            step += 1
        elif pos % 2 == 1:
            if step >= len(proof):
                raise ValueError(f"proof too short at level {step}")
            item = proof[step]
            if item["side"] != "left":
                raise ValueError(f"step {step} side must be left")
            current = node_digest(bytes.fromhex(item["digest"]), current)
            step += 1
        pos //= 2
        count = (count + 1) // 2
    if step != len(proof):
        raise ValueError("proof has extra steps")
    return current.hex()


def call(method: str, path: str, body: bytes | None = None, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=body,
        method=method,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode(errors="replace")}


def put(session, offset, data, total=None, sha=None):
    headers = {"X-Chunk-Offset": str(offset), "Content-Type": "application/octet-stream"}
    if total is not None:
        headers["X-Total-Size"] = str(total)
    if sha is not None:
        headers["X-Content-SHA256"] = sha
    return call("PUT", f"/api/uploads/{session}/chunks", data, headers)


def wait_healthy(timeout=30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, _ = call("GET", "/health")
            if status == 200:
                return
        except Exception as exc:  # connection refused while starting
            last = exc
        time.sleep(0.5)
    raise SystemExit(f"service never became healthy: {last}")


def check(cond, label):
    if not cond:
        raise SystemExit(f"SMOKE FAIL: {label}")
    print(f"  ok - {label}")


def main():
    wait_healthy()
    suffix = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    s = f"SMOKE{suffix}"

    print("[health + static]")
    status, body = call("GET", "/health")
    check(status == 200 and body.get("status") == "ok", "GET /health -> 200 ok")
    req = urllib.request.Request(BASE + "/")
    with urllib.request.urlopen(req, timeout=10) as resp:
        index = resp.read().decode()
    check(resp.status == 200 and 'id="root"' in index, "SPA index.html is served")

    print("[validation]")
    status, body = put("bad-id!", 0, b"x", 1, "a" * 64)
    check(status == 400, f"invalid session rejected (400), got {status}")
    bad_digest = put(s + "B", 0, b"x", 1, "Z" * 64)
    check(bad_digest[0] == 400, "uppercase digest rejected (400)")

    # 3-chunk file, last chunk short
    blob = os.urandom(2 * CHUNK + 123)
    digest = hashlib.sha256(blob).hexdigest()
    c0, c1, c2 = blob[:CHUNK], blob[CHUNK:2 * CHUNK], blob[2 * CHUNK:]

    print("[out of order arrival]")
    status, body = put(s, CHUNK, c1, len(blob), digest)
    check(status == 200 and body["confirmed_chunks"] == [1], "chunk #1 first -> 200")
    status, body = put(s, 2 * CHUNK, c2)
    check(status == 200 and set(body["confirmed_chunks"]) == {1, 2}, "chunk #2 -> 200")

    print("[located rejections before completion]")
    status, body = put(s, 1, b"x")
    check(status == 400 and "not aligned" in body["error"], "unaligned offset -> 400")
    status, body = put(s, 3 * CHUNK, b"x")
    check(status == 400 and "beyond" in body["error"], "out-of-bounds offset -> 400")
    status, body = put(s, 0, c0[:-1])
    check(status == 400 and "chunk length" in body["error"], "wrong chunk length -> 400")

    print("[seal with missing blocks]")
    status, body = call("POST", f"/api/uploads/{s}/seal")
    check(status == 409 and body["missing_ranges"] == [[0, 0]],
          f"missing ranges reported: {body}")

    print("[idempotent retransmission then completion]")
    status, body = put(s, CHUNK, c1, len(blob), digest)
    check(status == 200 and body["duplicate"] is True, "identical retransmit -> 200 duplicate")
    status, body = put(s, 0, c0)
    check(status == 200 and body["confirmed_chunks"] == [0, 1, 2], "chunk #0 completes upload")

    print("[409 conflict must not overwrite]")
    evil = bytearray(c1)
    evil[0] ^= 0xFF
    status, body = put(s, CHUNK, bytes(evil))
    check(status == 409, f"different bytes at same offset -> 409, got {status} {body}")
    status, body = put(s, CHUNK, c1)
    check(status == 200 and body["duplicate"] is True,
          "original chunk still intact and idempotent after 409")
    status, body = put(s, CHUNK, c1, len(blob) + 1, digest)
    check(status == 409, "changed total_size -> 409")
    status, body = put(s, CHUNK, c1, len(blob), "a" * 64)
    check(status == 409, "changed sha256 -> 409")

    print("[atomic seal + stable receipt]")
    status, receipt = call("POST", f"/api/uploads/{s}/seal")
    check(status == 200 and receipt["sha256"] == digest and receipt["chunks"] == 3,
          f"seal succeeds with correct digest: {receipt}")
    status, again = call("POST", f"/api/uploads/{s}/seal")
    check(status == 200 and again == receipt, "repeat seal returns the SAME receipt")

    print("[Merkle commitment on the receipt]")
    root = receipt.get("merkle_root")
    check(receipt.get("merkle_algorithm") == "merkle-sha256-v1"
          and isinstance(root, str) and len(root) == 64,
          f"receipt atomically carries merkle root + algorithm: {receipt.get('merkle_algorithm')}")
    status, st = call("GET", f"/api/uploads/{s}")
    check(status == 200 and st["commitment"]["merkle_root"] == root
          and st["commitment"]["receipt_id"] == receipt["receipt_id"],
          "commitment record shares root and receipt id")

    print("[range proofs + independent local root rebuild]")
    status, proof = call("GET", f"/api/uploads/{s}/proof?start=0&end=2")
    check(status == 200 and [b["index"] for b in proof["blocks"]] == [0, 1, 2],
          "full-range proof lists blocks 0..2")
    check(proof["chunk_size"] == CHUNK and proof["file_sha256"] == digest
          and [b["length"] for b in proof["blocks"]] == [CHUNK, CHUNK, 123],
          "proof boundaries bind actual block lengths and whole-file digest")
    for b in proof["blocks"]:
        rebuilt = evaluate_proof(b, 3)
        check(rebuilt == root, f"block #{b['index']} rebuilds the committed root")
        off, ln = b["offset"], b["length"]
        check(hashlib.sha256(blob[off:off + ln]).hexdigest() == b["sha256"],
              f"block #{b['index']} digest matches its raw bytes")
    status, sub = call("GET", f"/api/uploads/{s}/proof?start=1&end=2")
    check(status == 200 and [b["index"] for b in sub["blocks"]] == [1, 2],
          "contiguous sub-range 1..2 exported")
    for b in sub["blocks"]:
        check(evaluate_proof(b, 3) == root, f"sub-range block #{b['index']} verifies")

    print("[first-mismatch reporting on tampered proof]")
    evil = json.loads(json.dumps(proof))
    evil["blocks"][1]["proof"][0]["digest"] = "00" * 32
    check(evaluate_proof(evil["blocks"][1], 3) != root,
          "tampered sibling rebuilds a DIFFERENT root (first mismatch detectable)")
    evil2 = json.loads(json.dumps(proof))
    evil2["blocks"][0]["length"] = CHUNK - 1
    check(evaluate_proof(evil2["blocks"][0], 3) != root,
          "tampered block length rebuilds a DIFFERENT root")

    print("[proof endpoint validation]")
    for q, want in [("?start=2&end=1", 400), ("?start=0&end=3", 400),
                    ("?start=01&end=2", 400), ("", 400)]:
        status, body = call("GET", f"/api/uploads/{s}/proof{q}")
        check(status == want, f"proof{q or ' (no range)'} -> {want}, got {status}: {body}")
    status, body = call("GET", f"/api/uploads/NOPE9/proof?start=0&end=0")
    check(status == 404, f"unknown session proof -> 404, got {status}")

    print("[commitment rescan is idempotent / sealed-only]")
    status, rec = call("POST", f"/api/uploads/{s}/commitment")
    check(status == 200 and rec["merkle_root"] == root and rec["receipt_id"] == receipt["receipt_id"],
          "commitment rescan returns the same independent record")
    status, body = call("POST", "/api/uploads/NOPE9/commitment")
    check(status == 404, f"unknown session rescan -> 404, got {status}")

    print("[sealed immutability]")
    wrong0 = bytes(CHUNK)  # all-zero chunk, differs from random c0
    status, _ = put(s, 0, wrong0)
    check(status == 409, "different chunk after seal -> 409")
    status, body = put(s, 0, c0)
    check(status == 200 and body["sealed"] is True, "identical PUT after seal stays 200")

    print("[digest mismatch never seals]")
    bad = b"q" * 50
    sb = s + "D"
    status, _ = put(sb, 0, bad, len(bad), "a" * 64)
    check(status == 200, "wrong-declared digest upload accepted chunk-wise")
    status, body = call("POST", f"/api/uploads/{sb}/seal")
    check(status == 409 and "digest" in body["error"], "digest mismatch -> 409, no receipt")
    status, body = call("GET", f"/api/uploads/{sb}")
    check(status == 200 and body["sealed"] is False and body["receipt"] is None,
          "no receipt exists after digest mismatch")

    print(f"\nSMOKE OK against {BASE} (sessions {s}, {sb})")


if __name__ == "__main__":
    main()
