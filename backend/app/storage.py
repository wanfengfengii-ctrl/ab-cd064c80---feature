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
                "sealed": receipt is not None,
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

            sealed = self._read_receipt(session) is not None
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

            present = self._present_indices(session, meta.chunk_count)
            missing = _missing_ranges(present, meta.chunk_count)
            if missing:
                return {}, False, missing

            digest = hashlib.sha256()
            for i in range(meta.chunk_count):
                with open(self._chunk_path(session, i), "rb") as fh:
                    digest.update(fh.read())
            actual = digest.hexdigest()
            if actual != meta.sha256:
                raise ConflictError(
                    f"server digest {actual} does not match declared {meta.sha256}"
                )

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
            }
            seal_marker = json.dumps(receipt, indent=2).encode()
            # Write the receipt atomically; from this instant the session is sealed.
            _atomic_write(self._receipt_path(session), seal_marker)
            return receipt, True, None
