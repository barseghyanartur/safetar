"""Phase A — The Guard: per-entry header validation and file-count pre-scan.

The Guard validates each ``TarInfo`` header before a single byte of that
member's content reaches the filesystem.  For the file-count limit a
dedicated pre-scan pass is performed using a counted ``next()`` loop
(never ``getmembers()``, to avoid memory exhaustion).
"""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "ensure_seekable",
    "pre_scan_file_count",
    "validate_entry_type",
    "validate_filename",
    "validate_pax_path",
)

import logging
import os
import tarfile
import tempfile
from typing import BinaryIO

from safetar._events import HardlinkPolicy, SparsePolicy, SymlinkPolicy
from safetar._exceptions import (
    FileCountExceededError,
    MalformedArchiveError,
    TotalSizeExceededError,
    UnsafeEntryError,
    UnsafeEntryTypeError,
)

log = logging.getLogger("safetar.security")

# TAR type codes we recognise as safe (given the right policy settings).
_REGULAR_TYPES = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE}
_DIR_TYPE = {tarfile.DIRTYPE}
_SYMLINK_TYPE = {tarfile.SYMTYPE}
_HARDLINK_TYPE = {tarfile.LNKTYPE}
_FORBIDDEN_TYPES = {tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE}

# GNU sparse type code (matches tarfile.GNUTYPE_SPARSE == b"S").
_GNUTYPE_SPARSE = tarfile.GNUTYPE_SPARSE

# Maximum filename length we accept (conservative cross-platform limit).
MAX_PATH = 4096


def _is_sparse(info: tarfile.TarInfo) -> bool:
    """Return True if *info* represents a GNU sparse file entry."""
    # Python's tarfile sets info.sparse to a non-empty list for sparse
    # entries; the attribute always exists on TarInfo.
    if getattr(info, "sparse", None):
        return True
    # Fallback: check the raw type byte (b"S") for any sparse entries
    # that slip through without the sparse attribute.
    if info.type == _GNUTYPE_SPARSE:
        return True
    # Some GNU extensions use REGTYPE but annotate via PAX headers.
    pax = getattr(info, "pax_headers", None) or {}
    return "GNU.sparse.major" in pax or "GNU.sparse.size" in pax


def ensure_seekable(
    file: str | os.PathLike[str] | BinaryIO,
    max_total_size: int,
) -> tuple[BinaryIO, bool]:
    """Return a seekable binary file object for *file*.

    If *file* is a path, open it in binary mode (always seekable).
    If *file* is a file-like object that is already seekable, return it
    as-is.  Otherwise buffer into a ``SpooledTemporaryFile``.

    Returns ``(fileobj, was_buffered)`` so the caller knows whether it
    owns the object.
    """
    if isinstance(file, (str, os.PathLike)):
        return open(file, "rb"), True  # noqa: SIM115

    fobj: BinaryIO = file  # type: ignore[assignment]
    if hasattr(fobj, "seekable") and fobj.seekable():
        return fobj, False

    # Non-seekable — buffer into a SpooledTemporaryFile.
    spool: BinaryIO = tempfile.SpooledTemporaryFile(  # type: ignore[assignment]  # noqa: SIM115
        max_size=max_total_size,
    )
    total = 0
    while True:
        chunk = fobj.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_total_size:
            spool.close()
            raise TotalSizeExceededError(
                f"Input stream exceeds max_total_size ({max_total_size}) "
                "during buffering"
            )
        spool.write(chunk)
    spool.seek(0)
    return spool, True


def pre_scan_file_count(
    fileobj: BinaryIO,
    mode: str,
    max_files: int,
) -> None:
    """Iterate archive headers and raise if the count exceeds *max_files*.

    Uses a counted ``next()`` loop rather than ``getmembers()`` to avoid
    loading millions of ``TarInfo`` objects into memory.

    After the scan the caller must ``fileobj.seek(0)`` before opening
    the archive again for extraction.
    """
    try:
        with tarfile.open(fileobj=fileobj, mode=mode) as tf:
            count = 0
            while True:
                member = tf.next()
                if member is None:
                    break
                count += 1
                if count > max_files:
                    raise FileCountExceededError(
                        f"Archive contains more than {max_files} entries"
                    )
    except (tarfile.TarError, EOFError, OSError) as exc:
        # tarfile.TarError covers structural defects caught by tarfile itself.
        # EOFError is raised directly by the gzip/bz2/lzma decompressor when
        # the stream is truncated; tarfile.next() only catches HeaderError
        # (a TarError subclass) and lets EOFError propagate uncaught on all
        # supported Python versions.
        # OSError covers underlying I/O failures.
        if isinstance(exc.__context__, FileCountExceededError):
            raise exc.__context__ from None
        raise MalformedArchiveError(str(exc)) from exc
    except FileCountExceededError:
        raise
    finally:
        fileobj.seek(0)


def validate_entry_type(
    info: tarfile.TarInfo,
    *,
    symlink_policy: SymlinkPolicy,
    hardlink_policy: HardlinkPolicy,
    sparse_policy: SparsePolicy,
) -> str:
    """Validate *info*'s type code against the allowed whitelist.

    Returns a disposition string: ``"extract"``, ``"skip"`` (for
    ``SYMLINK_IGNORE``), or ``"defer_symlink"``.

    Raises ``UnsafeEntryTypeError`` or ``UnsafeEntryError`` for
    forbidden types.
    """
    # --- sparse (check first — sparse entries may have REGTYPE) ---
    if _is_sparse(info):
        if sparse_policy is SparsePolicy.REJECT:
            raise UnsafeEntryTypeError(f"Sparse file entry rejected: {info.name!r}")
        # MATERIALISE — fall through to regular-file handling.
        return "extract"

    # --- regular files ---
    if info.type in _REGULAR_TYPES:
        return "extract"

    # --- directories ---
    if info.type in _DIR_TYPE:
        return "extract"

    # --- symlinks ---
    if info.type in _SYMLINK_TYPE:
        match symlink_policy:
            case SymlinkPolicy.REJECT:
                raise UnsafeEntryError(
                    f"Symlink entry rejected (policy=REJECT): {info.name!r}"
                )
            case SymlinkPolicy.IGNORE:
                return "skip"
            case SymlinkPolicy.RESOLVE_INTERNAL:
                return "defer_symlink"

    # --- hardlinks ---
    if info.type in _HARDLINK_TYPE:
        match hardlink_policy:
            case HardlinkPolicy.REJECT:
                raise UnsafeEntryError(
                    f"Hardlink entry rejected (policy=REJECT): {info.name!r}"
                )
            case HardlinkPolicy.INTERNAL:
                return "extract"

    # --- explicitly forbidden types ---
    if info.type in _FORBIDDEN_TYPES:
        _type_names = {
            tarfile.CHRTYPE: "character device",
            tarfile.BLKTYPE: "block device",
            tarfile.FIFOTYPE: "FIFO",
        }
        label = _type_names.get(info.type, "forbidden")
        raise UnsafeEntryTypeError(f"Forbidden entry type ({label}): {info.name!r}")

    # --- anything else: unknown type code ---
    raise UnsafeEntryTypeError(
        f"Unrecognised TAR type code {info.type!r}: {info.name!r}"
    )


def validate_filename(info: tarfile.TarInfo) -> str:
    """Validate *info*'s effective filename for basic sanity.

    Returns the effective name (accounting for PAX overrides).

    Raises ``UnsafeEntryError`` for null bytes, empty names, or
    over-length names.
    """
    name = _effective_name(info)

    if not name or name.strip() == "":
        raise UnsafeEntryError("Empty member filename")

    if "\x00" in name:
        raise UnsafeEntryError(f"Null byte in member filename: {name[:256]!r}")

    if len(name) > MAX_PATH:
        raise UnsafeEntryError(
            f"Filename length ({len(name)}) exceeds MAX_PATH ({MAX_PATH}): "
            f"{name[:256]!r}..."
        )

    return name


def validate_pax_path(info: tarfile.TarInfo) -> str | None:
    """If *info* has a PAX ``path`` override, validate it independently.

    Returns the PAX path if present (for the Sandbox to check), or
    ``None`` if no override exists.
    """
    pax = getattr(info, "pax_headers", None) or {}
    pax_path = pax.get("path")
    if pax_path is None:
        return None

    if "\x00" in pax_path:
        raise UnsafeEntryError(f"Null byte in PAX path override: {pax_path[:256]!r}")

    if len(pax_path) > MAX_PATH:
        raise UnsafeEntryError(
            f"PAX path override length ({len(pax_path)}) exceeds MAX_PATH"
        )

    return pax_path


def _effective_name(info: tarfile.TarInfo) -> str:
    """Return the filename that ``tarfile`` will use for extraction.

    PAX ``path`` overrides and GNU long-name reassembly are already
    reflected in ``info.name`` by Python's ``tarfile`` module.
    """
    return info.name
