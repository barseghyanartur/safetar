"""Phase C — The Streamer: runtime byte monitoring during extraction.

Because TAR compression is applied to the whole archive stream rather
than to individual members, ratio monitoring is *aggregate* (archive-
level) rather than per-member.
"""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "ExtractionMonitor",
    "extract_member_streaming",
    "compute_archive_hash",
)

import contextlib
import hashlib
import logging
import os
import random
import tarfile
from pathlib import Path
from typing import BinaryIO

from safetar._exceptions import (
    CompressionRatioError,
    FileSizeExceededError,
    MalformedArchiveError,
    TotalSizeExceededError,
)

log = logging.getLogger("safetar.security")

# Chunk size for streaming extraction.
_CHUNK_SIZE = 65536


class ExtractionMonitor:
    """Tracks per-member and archive-level byte counts during extraction."""

    def __init__(
        self,
        *,
        max_file_size: int,
        max_total_size: int,
        max_ratio: float,
        archive_size: int,
    ) -> None:
        self._max_file_size = max_file_size
        self._max_total_size = max_total_size
        self._max_ratio = max_ratio
        self._archive_size = archive_size

        self._member_bytes: int = 0
        self._total_bytes: int = 0

    def reset_member(self) -> None:
        """Reset per-member counters for the next member."""
        self._member_bytes = 0

    def account(self, n: int) -> None:
        """Record *n* bytes written and enforce all limits."""
        self._member_bytes += n
        self._total_bytes += n

        if self._member_bytes > self._max_file_size:
            raise FileSizeExceededError(
                f"Member exceeds max_file_size ({self._max_file_size}): "
                f"{self._member_bytes} bytes written"
            )

        if self._total_bytes > self._max_total_size:
            raise TotalSizeExceededError(
                f"Cumulative extraction exceeds max_total_size "
                f"({self._max_total_size}): {self._total_bytes} bytes written"
            )

        self._check_ratio()

    def _check_ratio(self) -> None:
        """Check archive-level compression ratio.

        Uses the total archive size (compressed on disk) as the
        denominator.  This is simpler and more reliable than trying to
        track the compressed stream position through CPython's internal
        decompressor wrapper chain.
        """
        if self._archive_size <= 0:
            return

        ratio = self._total_bytes / self._archive_size
        if ratio > self._max_ratio:
            raise CompressionRatioError(
                f"Archive compression ratio ({ratio:.1f}:1) exceeds "
                f"max_ratio ({self._max_ratio}:1)"
            )

    @property
    def total_bytes(self) -> int:
        return self._total_bytes


def extract_member_streaming(
    tf: tarfile.TarFile,
    info: tarfile.TarInfo,
    dest_path: Path,
    monitor: ExtractionMonitor,
) -> None:
    """Extract a single regular-file member with byte-level monitoring.

    Uses atomic writes: content is written to a temporary file and
    renamed to the final destination only on success.
    """
    monitor.reset_member()

    # Prepare temp path.
    suffix = f".safetar_tmp_{os.getpid()}_{random.randint(0, 999999):06d}"
    temp_path = dest_path.with_name(dest_path.name + suffix)

    try:
        # Ensure parent directory exists.
        temp_path.parent.mkdir(parents=True, exist_ok=True)

        source = tf.extractfile(info)
        if source is None:
            # No data to extract (zero-length or special).
            temp_path.touch()
            temp_path.rename(dest_path)
            return

        with source, open(temp_path, "wb") as out:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                out.write(chunk)
                monitor.account(len(chunk))

        # Success — atomic rename.
        temp_path.rename(dest_path)

    except (tarfile.TarError, EOFError) as exc:
        # Truncated or structurally corrupt stream — wrap as MalformedArchiveError.
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        raise MalformedArchiveError(
            f"Archive stream error during extraction: {exc}"
        ) from exc
    except Exception:
        # Cleanup temp file on any other failure (size limits, I/O, etc.).
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        raise


def compute_archive_hash(fileobj: BinaryIO) -> str:
    """Return the first 16 hex chars of the SHA-256 of the archive.

    Reads the file, then seeks back to the original position.
    """
    pos = fileobj.tell()
    h = hashlib.sha256()
    while True:
        chunk = fileobj.read(65536)
        if not chunk:
            break
        h.update(chunk)
    fileobj.seek(pos)
    return h.hexdigest()[:16]
