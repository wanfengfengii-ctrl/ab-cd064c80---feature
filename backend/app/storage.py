"""File-backed, crash-safe persistence for upload sessions.

Each session lives in a single directory holding:
  meta.json   – immutable metadata, written atomically with fsync
  chunks/NNNN – one file per confirmed chunk (raw bytes), atomically renamed
  receipt.json – present only after a successful atomic seal

A process-wide threading.RLock serializes writers within one server
process; atomic rename + fsync make the on-disk state crash-consistent,
so progress and receipts survive service restarts.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from typing import Optional

from . import merkle

CHUNK_SIZE = 65536

# Default limits; can be overridden through the environment.
MIN_SESSION_LEN = 1
MAX_SESSION_LEN = 32
MIN_TOTAL_SIZE = 1
MAX_TOTAL_SIZE = 8 * 1024 * 1024

_DIGEST_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_sha256_hex(value: str) -> bool:
    return bool(_SHA256_RE.match(value))


@dataclass
class Metadata:
    total_size: int
    sha256: str
    chunk_count: int


def _validate_session(session: str) -> str:
    if not MIN_SESSION_LEN <= len(session) <= MAX_SESSION_LEN:
        raise RejectError("session id must be 1-32 characters long")
    if not session.isascii() or not session.isalnum():
        raise RejectError("session id must contain only ASCII letters and digits")
    return session


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: str, data: bytes) -> None:
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(directory)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _read_json(path: str) -> dict:
    with open(path, "rb") as fh:
        return json.loads(fh.read())


def _missing_ranges(present: set[int], chunk_count: int) -> list[list[int]]:
    ranges: list[list[int]] = []
    start: Optional[int] = None
    prev: Optional[int] = None
    for i in range(chunk_count):
        if i not in present:
            if start is None:
                start = prev = i
            elif i == prev + 1:
                prev = i
            else:
                ranges.append([start, prev])
                start = prev = i
    if start is not None:
        ranges.append([start, prev])
    return ranges


class ConflictError(Exception):
    """Content/metadata of an idempotent retransmission does not match."""


class NotFoundError(Exception):
    """The requested session does not exist at all."""


class RejectError(Exception):
    """Chunk index/offset/length is malformed (mapped to HTTP 400)."""


class UploadStore:
    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.RLock()

    # ---- paths -----------------------------------------------------------

    def _dir(self, session: str) -> str:
        return os.path.join(self.root, session)

    def _meta_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "meta.json")

    def _chunks_dir(self, session: str) -> str:
        return os.path.join(self._dir(session), "chunks")

    def _chunk_path(self, session: str, index: int) -> str:
        return os.path.join(self._chunks_dir(session), f"{index:08d}")

    def _receipt_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "receipt.json")

    def _commitment_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "commitment.json")

    # ---- reads -----------------------------------------------------------

    def get_metadata(self, session: str) -> Optional[Metadata]:
        try:
            raw = _read_json(self._meta_path(session))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return Metadata(
            total_size=int(raw["total_size"]),
            sha256=str(raw["sha256"]),
            chunk_count=int(raw["chunk_count"]),
        )

    def _present_indices(self, session: str, chunk_count: int) -> set[int]:
        present: set[int] = set()
        try:
            names = os.listdir(self._chunks_dir(session))
        except FileNotFoundError:
            return present
        for name in names:
            if len(name) == 8 and name.isdigit():
                idx = int(name)
                if 0 <= idx < chunk_count:
                    present.add(idx)
        return present

    def status(self, session: str) -> Optional[dict]:
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                return None
            present = sorted(self._present_indices(session, meta.chunk_count))
            receipt = self._read_receipt(session)
            return {
                "session": session,
                "total_size": meta.total_size,
                "sha256": meta.sha256,
                "chunk_count": meta.chunk_count,
                "confirmed_chunks": present,
                "missing_ranges": _missing_ranges(set(present), meta.chunk_count),
                # existence marks the seal; a corrupt receipt still means sealed
                "sealed": os.path.exists(self._receipt_path(session)),
                "receipt": receipt,
            }

    def _read_receipt(self, session: str) -> Optional[dict]:
        try:
            raw = _read_json(self._receipt_path(session))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return raw

    # ---- writes ----------------------------------------------------------

    def put_chunk(
        self,
        session: str,
        offset: int,
        data: bytes,
        total_size: Optional[int],
        sha256: Optional[str],
    ) -> dict:
        _validate_session(session)
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise RejectError("offset must be an integer")
        if offset < 0:
            raise RejectError("offset must be >= 0")
        if not isinstance(data, (bytes, bytearray)):
            raise RejectError("chunk payload must be raw bytes")
        data = bytes(data)

        with self._lock:
            existing = self.get_metadata(session)
            if existing is None:
                # Build + validate in memory first; nothing touches disk until
                # every shape check has passed.
                meta = self._build_metadata(total_size, sha256)
            else:
                meta = existing
                if total_size is not None and total_size != meta.total_size:
                    raise ConflictError(
                        f"total_size mismatch: session pinned to {meta.total_size}"
                    )
                if sha256 is not None and sha256 != meta.sha256:
                    raise ConflictError("sha256 mismatch: session digest is pinned")

            if offset % CHUNK_SIZE != 0:
                raise RejectError(f"offset {offset} is not aligned to {CHUNK_SIZE}")
            if offset >= meta.total_size:
                raise RejectError(
                    f"offset {offset} is beyond total_size {meta.total_size}"
                )
            expected_size = self._expected_chunk_size(meta, offset)
            if len(data) != expected_size:
                raise RejectError(
                    f"chunk length {len(data)} at offset {offset} must be {expected_size}"
                )
            index = offset // CHUNK_SIZE

            # All checks passed: pin the metadata on the first valid chunk.
            if existing is None:
                os.makedirs(self._chunks_dir(session), exist_ok=True)
                _atomic_write(
                    self._meta_path(session),
                    json.dumps(
                        {
                            "total_size": meta.total_size,
                            "sha256": meta.sha256,
                            "chunk_count": meta.chunk_count,
                        },
                        indent=2,
                    ).encode(),
                )

            # receipt.json existing at all means sealed, even if its content
            # is unreadable: a corrupt receipt must keep the session frozen.
            sealed = os.path.exists(self._receipt_path(session))
            path = self._chunk_path(session, index)
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    stored = fh.read()
                if stored != data:
                    raise ConflictError(
                        f"chunk at offset {offset} already confirmed with different bytes"
                    )
                duplicate = True
            else:
                if sealed:
                    raise ConflictError("session is already sealed; no new chunks accepted")
                _atomic_write(path, data)
                duplicate = False

            present = self._present_indices(session, meta.chunk_count)
            return {
                "session": session,
                "offset": offset,
                "index": index,
                "size": len(data),
                "duplicate": duplicate,
                "confirmed_chunks": sorted(present),
                "chunk_count": meta.chunk_count,
                "missing_ranges": _missing_ranges(present, meta.chunk_count),
                "sealed": sealed,
            }

    def _build_metadata(
        self, total_size: Optional[int], sha256: Optional[str]
    ) -> Metadata:
        if total_size is None or sha256 is None:
            raise RejectError(
                "total_size and sha256 are required for the first chunk of a session"
            )
        if not isinstance(total_size, int) or isinstance(total_size, bool):
            raise RejectError("total_size must be an integer")
        if not MIN_TOTAL_SIZE <= total_size <= MAX_TOTAL_SIZE:
            raise RejectError(
                f"total_size must be between {MIN_TOTAL_SIZE} and {MAX_TOTAL_SIZE} bytes"
            )
        if not isinstance(sha256, str) or not _is_sha256_hex(sha256):
            raise RejectError("sha256 must be 64 lowercase hex characters")

        chunk_count = (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        return Metadata(
            total_size=total_size, sha256=sha256, chunk_count=chunk_count
        )

    @staticmethod
    def _expected_chunk_size(meta: Metadata, offset: int) -> int:
        remaining = meta.total_size - offset
        if remaining <= 0:
            return 0
        return min(CHUNK_SIZE, remaining)

    def seal(self, session: str) -> tuple[dict, bool, Optional[list[list[int]]]]:
        """Return (receipt_or_status, ok, missing_ranges).

        ok=True  -> receipt dict (possibly an identical prior receipt)
        ok=False -> digest mismatch; missing_ranges is None
        missing -> blocks missing; receipt is None and missing_ranges set
        """
        _validate_session(session)
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                raise RejectError("unknown session; upload at least one chunk first")

            prior = self._read_receipt(session)
            if prior is not None:
                return prior, True, None
            if os.path.exists(self._receipt_path(session)):
                # A receipt file exists but is unreadable: never overwrite it.
                raise ConflictError(
                    "sealed receipt is corrupt; refusing to modify the session"
                )

            present = self._present_indices(session, meta.chunk_count)
            missing = _missing_ranges(present, meta.chunk_count)
            if missing:
                return {}, False, missing

            digest = hashlib.sha256()
            chunk_digests: list[bytes] = []
            chunk_lengths: list[int] = []
            for i in range(meta.chunk_count):
                with open(self._chunk_path(session, i), "rb") as fh:
                    data = fh.read()
                digest.update(data)
                chunk_digests.append(hashlib.sha256(data).digest())
                chunk_lengths.append(len(data))
            actual = digest.hexdigest()
            if actual != meta.sha256:
                raise ConflictError(
                    f"server digest {actual} does not match declared {meta.sha256}"
                )

            receipt_id = _DIGEST_PREFIX + actual
            commitment = self._build_commitment(
                session, meta, actual, receipt_id, chunk_digests, chunk_lengths
            )
            # The commitment lands first; the receipt (whose appearance marks
            # the session as sealed) is written last, inside the same lock, so
            # a visible receipt always implies its commitment is on disk.
            _atomic_write(
                self._commitment_path(session),
                json.dumps(commitment, indent=2).encode(),
            )

            receipt = {
                "receipt_id": receipt_id,
                "session": session,
                "total_size": meta.total_size,
                "sha256": actual,
                "chunks": meta.chunk_count,
                "chunk_size": CHUNK_SIZE,
                "sealed_at": datetime.datetime.now(datetime.timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "commitment": {
                    "algorithm": commitment["algorithm"],
                    "root": commitment["root"],
                    "leaf_count": commitment["leaf_count"],
                },
            }
            seal_marker = json.dumps(receipt, indent=2).encode()
            # Write the receipt atomically; from this instant the session is sealed.
            _atomic_write(self._receipt_path(session), seal_marker)
            return receipt, True, None

    # ---- Merkle commitment & range proofs ---------------------------------

    @staticmethod
    def _build_commitment(
        session: str,
        meta: Metadata,
        file_sha256: str,
        receipt_id: str,
        chunk_digests: list[bytes],
        chunk_lengths: list[int],
    ) -> dict:
        leaf_hashes = [
            merkle.leaf_hash(i, chunk_lengths[i], chunk_digests[i])
            for i in range(meta.chunk_count)
        ]
        return {
            "algorithm": merkle.ALGORITHM,
            "root": merkle.build_root(leaf_hashes).hex(),
            "leaf_count": meta.chunk_count,
            "chunk_size": CHUNK_SIZE,
            "total_size": meta.total_size,
            "file_sha256": file_sha256,
            "receipt_id": receipt_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
        }

    def _read_commitment(self, session: str) -> Optional[dict]:
        try:
            raw = _read_json(self._commitment_path(session))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict):
            return None
        required = ("algorithm", "root", "leaf_count", "receipt_id")
        if any(field not in raw for field in required):
            return None
        if raw["algorithm"] != merkle.ALGORITHM:
            return None
        return raw

    def _read_receipt_strict(self, session: str) -> Optional[dict]:
        """Receipt for proof purposes; any corruption is a hard 409."""
        try:
            raw = _read_json(self._receipt_path(session))
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ConflictError("sealed receipt is corrupt: not valid JSON")
        if not isinstance(raw, dict):
            raise ConflictError("sealed receipt is corrupt: not a JSON object")
        for field in ("receipt_id", "session", "total_size", "sha256", "chunks"):
            if field not in raw:
                raise ConflictError(
                    f"sealed receipt is corrupt: missing field {field!r}"
                )
        return raw

    def _sealed_state(self, session: str) -> tuple[Metadata, dict]:
        """(meta, receipt) of a provably sealed session, or raise."""
        meta = self.get_metadata(session)
        if meta is None:
            raise NotFoundError("no such session")
        receipt = self._read_receipt_strict(session)
        if receipt is None:
            raise ConflictError(
                "session is not sealed; proofs only exist for sealed sessions"
            )
        if (
            not isinstance(receipt.get("chunks"), int)
            or not isinstance(receipt.get("total_size"), int)
            or receipt["chunks"] != meta.chunk_count
            or receipt["total_size"] != meta.total_size
        ):
            raise ConflictError(
                "sealed receipt is corrupt: inconsistent with stored metadata"
            )
        return meta, receipt

    def _scan_chunks(
        self, session: str, meta: Metadata
    ) -> tuple[list[bytes], list[int], str]:
        """Full scan: per-chunk digests, lengths and whole-file digest."""
        chunk_digests: list[bytes] = []
        chunk_lengths: list[int] = []
        digest = hashlib.sha256()
        missing: list[int] = []
        for i in range(meta.chunk_count):
            path = self._chunk_path(session, i)
            if not os.path.exists(path):
                missing.append(i)
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            digest.update(data)
            chunk_digests.append(hashlib.sha256(data).digest())
            chunk_lengths.append(len(data))
        if missing:
            raise ConflictError(
                f"cannot prove: {len(missing)} chunk(s) missing on disk "
                f"(first missing index {missing[0]})"
            )
        return chunk_digests, chunk_lengths, digest.hexdigest()

    def _ensure_commitment(
        self, session: str, meta: Metadata, receipt: dict
    ) -> dict:
        """Return the commitment record, building it for legacy receipts.

        A legacy receipt (no embedded commitment root) is upgraded to a
        standalone commitment.json only after a full chunk scan whose
        recomputed whole-file digest matches the receipt. The legacy receipt
        itself is never rewritten.
        """
        embedded = receipt.get("commitment")
        embedded_root: Optional[str] = None
        if embedded is not None:
            if not isinstance(embedded, dict) or not _is_sha256_hex(
                str(embedded.get("root", ""))
            ):
                raise ConflictError(
                    "sealed receipt is corrupt: malformed commitment field"
                )
            embedded_root = embedded["root"]

        stored = self._read_commitment(session)
        if stored is not None:
            if embedded_root is not None and stored["root"] != embedded_root:
                raise ConflictError(
                    "commitment record does not match the sealed receipt"
                )
            return stored

        chunk_digests, chunk_lengths, actual = self._scan_chunks(session, meta)
        if actual != receipt["sha256"]:
            raise ConflictError(
                "recomputed whole-file digest does not match the sealed "
                "receipt; refusing to build a commitment"
            )
        commitment = self._build_commitment(
            session,
            meta,
            actual,
            str(receipt["receipt_id"]),
            chunk_digests,
            chunk_lengths,
        )
        if embedded_root is not None and commitment["root"] != embedded_root:
            raise ConflictError(
                "chunk data no longer matches the committed root in the receipt"
            )
        _atomic_write(
            self._commitment_path(session),
            json.dumps(commitment, indent=2).encode(),
        )
        return commitment

    def get_commitment(self, session: str) -> dict:
        _validate_session(session)
        with self._lock:
            meta, receipt = self._sealed_state(session)
            return self._ensure_commitment(session, meta, receipt)

    def get_proof(
        self, session: str, start: Optional[int], end: Optional[int]
    ) -> dict:
        """Verifiable delivery proof for a continuous chunk range."""
        _validate_session(session)
        with self._lock:
            meta, receipt = self._sealed_state(session)
            commitment = self._ensure_commitment(session, meta, receipt)

            n = meta.chunk_count
            lo = 0 if start is None else start
            hi = n - 1 if end is None else end
            for name, value in (("start", lo), ("end", hi)):
                if not isinstance(value, int) or isinstance(value, bool):
                    raise RejectError(f"range {name} must be an integer")
            if lo < 0:
                raise RejectError("range start must be >= 0")
            if hi > n - 1:
                raise RejectError(
                    f"range end {hi} is beyond the last chunk index {n - 1}"
                )
            if lo > hi:
                raise RejectError(
                    f"range start {lo} is after range end {hi}; "
                    "only continuous non-empty ranges are provable"
                )

            # Every proof is built from a fresh full scan and checked against
            # the committed root: missing chunks or drifted bytes are refused.
            chunk_digests, chunk_lengths, actual = self._scan_chunks(session, meta)
            if actual != receipt["sha256"]:
                raise ConflictError(
                    "recomputed whole-file digest does not match the sealed "
                    "receipt; refusing to prove"
                )
            leaf_hashes = [
                merkle.leaf_hash(i, chunk_lengths[i], chunk_digests[i])
                for i in range(n)
            ]
            root = merkle.build_root(leaf_hashes).hex()
            if root != commitment["root"]:
                raise ConflictError(
                    "chunk data no longer matches the committed Merkle root"
                )

            proof = merkle.range_proof(leaf_hashes, lo, hi)
            return {
                "session": session,
                "algorithm": merkle.ALGORITHM,
                "receipt_id": commitment["receipt_id"],
                "root": commitment["root"],
                "chunk_size": CHUNK_SIZE,
                "chunk_count": n,
                "total_size": meta.total_size,
                "file_sha256": actual,
                "range": {"start": lo, "end": hi},
                "boundaries": [
                    {
                        "index": i,
                        "offset": i * CHUNK_SIZE,
                        "length": chunk_lengths[i],
                    }
                    for i in range(lo, hi + 1)
                ],
                "chunk_digests": [
                    chunk_digests[i].hex() for i in range(lo, hi + 1)
                ],
                "proof": [h.hex() for h in proof],
                "domains": {
                    "leaf": merkle.LEAF_DOMAIN.decode("ascii"),
                    "node": merkle.NODE_DOMAIN.decode("ascii"),
                },
                "encoding": merkle.ENCODING_DOC,
            }
