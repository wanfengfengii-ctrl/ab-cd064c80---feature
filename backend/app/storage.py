"""File-backed, crash-safe persistence for upload sessions.

Each session lives in a single directory holding:
  meta.json       – immutable metadata, written atomically with fsync
  chunks/NNNN     – one file per confirmed chunk (raw bytes), atomically renamed
  receipt.json    – present only after a successful atomic seal; for sessions
                    sealed by current code it also embeds the Merkle commitment
  commitment.json – the Merkle commitment record; written together with a new
                    receipt, or produced later by a full legacy-receipt scan

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
from .merkle import MERKLE_ALGORITHM_VERSION

CHUNK_SIZE = 65536

# Default limits; can be overridden through the environment.
MIN_SESSION_LEN = 1
MAX_SESSION_LEN = 32
MIN_TOTAL_SIZE = 1
MAX_TOTAL_SIZE = 8 * 1024 * 1024

_DIGEST_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_RECEIPT_FIELDS = (
    "receipt_id",
    "session",
    "total_size",
    "sha256",
    "chunks",
    "chunk_size",
    "sealed_at",
)


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


class RejectError(Exception):
    """Chunk index/offset/length is malformed (mapped to HTTP 400)."""


class ProofError(Exception):
    """A proof/commitment cannot be produced (invalid range or state).

    ``status`` is the suggested HTTP status: 400 for a malformed range,
    404 for an unknown session and 409 for a state that cannot prove.
    """

    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


class ReceiptIntegrityError(Exception):
    """A persisted receipt exists but is malformed or internally inconsistent."""


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
            receipt = self._read_receipt(session, meta)
            return {
                "session": session,
                "total_size": meta.total_size,
                "sha256": meta.sha256,
                "chunk_count": meta.chunk_count,
                "confirmed_chunks": present,
                "missing_ranges": _missing_ranges(set(present), meta.chunk_count),
                "sealed": receipt is not None,
                "receipt": receipt,
                "commitment": self._read_commitment(session),
            }

    def _read_receipt(
        self, session: str, meta: Optional[Metadata] = None
    ) -> Optional[dict]:
        """Read and strictly validate the sealed receipt.

        A present but malformed/internally inconsistent receipt is a
        corruption event: ReceiptIntegrityError propagates so the session
        stays non-writable and every proof request is refused.  A legacy
        receipt without the embedded Merkle fields is valid but old.
        """
        try:
            raw = _read_json(self._receipt_path(session))
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as exc:
            raise ReceiptIntegrityError(f"receipt.json is not valid JSON: {exc}")

        if not isinstance(raw, dict):
            raise ReceiptIntegrityError("receipt.json must contain a JSON object")
        missing = [f for f in _RECEIPT_FIELDS if f not in raw]
        if missing:
            raise ReceiptIntegrityError(
                f"receipt.json is missing fields: {', '.join(missing)}"
            )
        sha = raw.get("sha256")
        if not isinstance(sha, str) or not _is_sha256_hex(sha):
            raise ReceiptIntegrityError("receipt sha256 is invalid")
        if raw.get("receipt_id") != _DIGEST_PREFIX + sha:
            raise ReceiptIntegrityError("receipt_id is inconsistent with sha256")
        if not isinstance(raw.get("session"), str) or raw["session"] != session:
            raise ReceiptIntegrityError("receipt session does not match path")
        try:
            total_size = int(raw["total_size"])
            chunks = int(raw["chunks"])
            chunk_size = int(raw["chunk_size"])
        except (TypeError, ValueError):
            raise ReceiptIntegrityError("receipt numeric fields are invalid")
        if total_size < 1 or chunks < 1 or chunk_size != CHUNK_SIZE:
            raise ReceiptIntegrityError("receipt size fields are invalid")
        if not isinstance(raw.get("sealed_at"), str) or not raw["sealed_at"]:
            raise ReceiptIntegrityError("receipt sealed_at is invalid")
        if meta is not None:
            if total_size != meta.total_size or chunks != meta.chunk_count:
                raise ReceiptIntegrityError(
                    "receipt is inconsistent with the pinned meta.json"
                )
            if sha != meta.sha256:
                raise ReceiptIntegrityError(
                    "receipt digest is inconsistent with the pinned meta.json"
                )

        root = raw.get("merkle_root")
        algo = raw.get("merkle_algorithm")
        if (root is None) != (algo is None):
            raise ReceiptIntegrityError(
                "receipt has a partially populated Merkle commitment"
            )
        if root is not None:
            if not isinstance(root, str) or not _is_sha256_hex(root):
                raise ReceiptIntegrityError("receipt merkle_root is invalid")
            if algo != MERKLE_ALGORITHM_VERSION:
                raise ReceiptIntegrityError(
                    f"unsupported merkle algorithm version: {algo!r}"
                )
        return raw

    def _read_commitment(self, session: str) -> Optional[dict]:
        """Read the standalone commitment record; absent/invalid -> None.

        The commitment is a derived record (the receipt remains the source
        of truth), so an unreadable one is simply rebuilt on demand.
        """
        try:
            raw = _read_json(self._commitment_path(session))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        required = (
            "algorithm",
            "merkle_root",
            "receipt_id",
            "session",
            "chunk_size",
            "chunk_count",
            "total_size",
            "file_sha256",
            "leaves",
        )
        if not isinstance(raw, dict) or any(f not in raw for f in required):
            return None
        if raw.get("algorithm") != MERKLE_ALGORITHM_VERSION:
            return None
        root = raw.get("merkle_root")
        if not isinstance(root, str) or not _is_sha256_hex(root):
            return None
        leaves = raw.get("leaves")
        if not isinstance(leaves, list) or len(leaves) != raw.get("chunk_count"):
            return None
        for item in leaves:
            if not isinstance(item, dict):
                return None
            if not (
                isinstance(item.get("index"), int)
                and isinstance(item.get("length"), int)
                and isinstance(item.get("sha256"), str)
                and _is_sha256_hex(item["sha256"])
            ):
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

            sealed = self._read_receipt(session, meta) is not None
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

            prior = self._read_receipt(session, meta)
            if prior is not None:
                return prior, True, None

            present = self._present_indices(session, meta.chunk_count)
            missing = _missing_ranges(present, meta.chunk_count)
            if missing:
                return {}, False, missing

            file_digest = hashlib.sha256()
            leaf_rows: list[dict] = []
            leaves: list[bytes] = []
            for i in range(meta.chunk_count):
                with open(self._chunk_path(session, i), "rb") as fh:
                    block = fh.read()
                file_digest.update(block)
                block_sha = hashlib.sha256(block).hexdigest()
                leaf_rows.append({"index": i, "length": len(block), "sha256": block_sha})
                leaves.append(merkle.leaf_digest(i, len(block), block_sha))
            actual = file_digest.hexdigest()
            if actual != meta.sha256:
                raise ConflictError(
                    f"server digest {actual} does not match declared {meta.sha256}"
                )

            root = merkle.build_root(leaves).hex()
            receipt = {
                "receipt_id": _DIGEST_PREFIX + actual,
                "session": session,
                "total_size": meta.total_size,
                "sha256": actual,
                "chunks": meta.chunk_count,
                "chunk_size": CHUNK_SIZE,
                "sealed_at": datetime.datetime.now(datetime.timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                # Merkle commitment, atomically associated with this receipt:
                "merkle_root": root,
                "merkle_algorithm": MERKLE_ALGORITHM_VERSION,
            }
            commitment = {
                "algorithm": MERKLE_ALGORITHM_VERSION,
                "merkle_root": root,
                "receipt_id": receipt["receipt_id"],
                "session": session,
                "chunk_size": CHUNK_SIZE,
                "chunk_count": meta.chunk_count,
                "total_size": meta.total_size,
                "file_sha256": actual,
                "leaves": leaf_rows,
            }
            # Persist the derived commitment first, then the receipt: from the
            # instant the receipt appears, its embedded root is backed by the
            # standalone record.  Both writes are atomic and crash-consistent.
            _atomic_write(
                self._commitment_path(session),
                json.dumps(commitment, indent=2).encode(),
            )
            seal_marker = json.dumps(receipt, indent=2).encode()
            # Write the receipt atomically; from this instant the session is sealed.
            _atomic_write(self._receipt_path(session), seal_marker)
            return receipt, True, None

    # ---- Merkle proofs ---------------------------------------------------

    @staticmethod
    def _expected_block_length(meta: Metadata, index: int) -> int:
        offset = index * CHUNK_SIZE
        remaining = meta.total_size - offset
        return min(CHUNK_SIZE, remaining)

    def _load_commitment(self, session: str, meta: Metadata, receipt: dict) -> dict:
        """Return a trustworthy commitment for a sealed session.

        New receipts embed the root; the standalone commitment.json supplies
        the per-leaf index/length/digest table.  A legacy receipt (no root)
        has no record until a full rescan is explicitly requested.
        """
        root = receipt.get("merkle_root")
        record = self._read_commitment(session)
        if record is not None:
            if (
                record["receipt_id"] != receipt["receipt_id"]
                or record["chunk_count"] != meta.chunk_count
                or record["file_sha256"] != receipt["sha256"]
            ):
                raise ProofError("commitment record is inconsistent with the receipt")
            # A new receipt embeds the root and must agree with the record; a
            # legacy receipt carries none and is backed solely by the record.
            if root is not None and record["merkle_root"] != root:
                raise ProofError("commitment record is inconsistent with the receipt")
            return record

        if root is None:
            raise ProofError(
                "legacy receipt has no Merkle root; rescan the sealed file to "
                "build an independent commitment record"
            )

        # Missing standalone record next to a new receipt: rebuild it from the
        # sealed chunks (they are protected by the receipt's file digest).
        rebuilt = self._rescan_commitment(session, meta, receipt)
        if rebuilt["merkle_root"] != root:
            raise ProofError(
                "rebuilt Merkle root does not match the receipt; sealed bytes "
                "may be corrupted"
            )
        _atomic_write(
            self._commitment_path(session),
            json.dumps(rebuilt, indent=2).encode(),
        )
        return rebuilt

    def _rescan_commitment(
        self, session: str, meta: Metadata, receipt: Optional[dict] = None
    ) -> dict:
        """Full ordered scan: verify every block + whole-file digest, build root.

        Raises ProofError if any block is missing, has an unexpected length,
        the whole-file digest differs from the pinned metadata/receipt, or a
        computed commitment would contradict a root the receipt already carries.
        """
        file_digest = hashlib.sha256()
        leaf_rows: list[dict] = []
        leaves: list[bytes] = []
        for i in range(meta.chunk_count):
            path = self._chunk_path(session, i)
            if not os.path.exists(path):
                raise ProofError(f"sealed chunk {i} is missing; proof refused")
            with open(path, "rb") as fh:
                block = fh.read()
            expected_len = self._expected_block_length(meta, i)
            if len(block) != expected_len:
                raise ProofError(
                    f"sealed chunk {i} has length {len(block)}, expected "
                    f"{expected_len}; proof refused"
                )
            file_digest.update(block)
            block_sha = hashlib.sha256(block).hexdigest()
            leaf_rows.append({"index": i, "length": len(block), "sha256": block_sha})
            leaves.append(merkle.leaf_digest(i, len(block), block_sha))
        actual = file_digest.hexdigest()
        declared = receipt["sha256"] if receipt is not None else meta.sha256
        if actual != declared:
            raise ProofError(
                f"whole-file digest {actual} does not match receipt {declared}; "
                "proof refused"
            )
        root = merkle.build_root(leaves).hex()
        receipt_id = (
            receipt["receipt_id"]
            if receipt is not None
            else _DIGEST_PREFIX + declared
        )
        return {
            "algorithm": MERKLE_ALGORITHM_VERSION,
            "merkle_root": root,
            "receipt_id": receipt_id,
            "session": session,
            "chunk_size": CHUNK_SIZE,
            "chunk_count": meta.chunk_count,
            "total_size": meta.total_size,
            "file_sha256": actual,
            "leaves": leaf_rows,
        }

    def rescan_legacy_commitment(self, session: str) -> dict:
        """Build a standalone commitment for a legacy receipt.

        The old receipt is never rewritten.  A complete, ordered scan must
        find every block with its expected length and recompute the exact
        whole-file digest recorded by the receipt; only then is an
        independent commitment.json written.
        """
        _validate_session(session)
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                raise ProofError("unknown session", 404)
            receipt = self._read_receipt(session, meta)
            if receipt is None:
                raise ProofError("session is not sealed", 409)

            existing = self._read_commitment(session)
            if existing is not None:
                return existing
            record = self._rescan_commitment(session, meta, receipt)
            if receipt.get("merkle_root") is not None:
                # New receipt: the embedded root must agree.
                if record["merkle_root"] != receipt["merkle_root"]:
                    raise ProofError(
                        "rebuilt Merkle root does not match the receipt"
                    )
            _atomic_write(
                self._commitment_path(session),
                json.dumps(record, indent=2).encode(),
            )
            return record

    def _parse_range(
        self, raw_start: Optional[str], raw_end: Optional[str], count: int
    ) -> tuple[int, int]:
        def one(name: str, raw: Optional[str]) -> int:
            if raw is None or raw == "":
                raise ProofError(f"{name} block index is required", 400)
            try:
                value = int(raw, 10)
            except (TypeError, ValueError):
                raise ProofError(f"{name} must be an integer", 400)
            if str(value) != raw:
                raise ProofError(f"{name} must be a canonical integer", 400)
            return value

        start = one("start", raw_start)
        end = one("end", raw_end)
        if start < 0 or end < 0:
            raise ProofError("block indices must be >= 0", 400)
        if start > end:
            raise ProofError(f"range start {start} must be <= end {end}", 400)
        if end >= count:
            raise ProofError(
                f"range end {end} is out of bounds for {count} blocks (0..{count - 1})",
                400,
            )
        return start, end

    def proof(
        self, session: str, raw_start: Optional[str], raw_end: Optional[str]
    ) -> dict:
        """Produce a verifiable export proof for a contiguous block range."""
        _validate_session(session)
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                raise ProofError("unknown session", 404)
            receipt = self._read_receipt(session, meta)
            if receipt is None:
                raise ProofError("session is not sealed", 409)
            start, end = self._parse_range(raw_start, raw_end, meta.chunk_count)
            record = self._load_commitment(session, meta, receipt)
            leaves_by_index = {item["index"]: item for item in record["leaves"]}
            if set(leaves_by_index) != set(range(meta.chunk_count)):
                raise ProofError("commitment leaf table is incomplete")

            leaf_digests = [
                merkle.leaf_digest(
                    i,
                    leaves_by_index[i]["length"],
                    leaves_by_index[i]["sha256"],
                )
                for i in range(meta.chunk_count)
            ]
            blocks: list[dict] = []
            for i in range(start, end + 1):
                info = leaves_by_index[i]
                if info["length"] != self._expected_block_length(meta, i):
                    raise ProofError(f"committed length for chunk {i} is invalid")
                blocks.append(
                    {
                        "index": i,
                        "offset": i * CHUNK_SIZE,
                        "length": info["length"],
                        "sha256": info["sha256"],
                        "proof": merkle.inclusion_proof(leaf_digests, i),
                    }
                )
            return {
                "session": session,
                "algorithm": record["algorithm"],
                "merkle_root": record["merkle_root"],
                "receipt_id": record["receipt_id"],
                "file_sha256": record["file_sha256"],
                "chunk_size": record["chunk_size"],
                "chunk_count": record["chunk_count"],
                "range": {"start": start, "end": end},
                "blocks": blocks,
            }
