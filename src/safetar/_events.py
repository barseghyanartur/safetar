"""Policy enums and security event dataclass for safetar."""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"

from dataclasses import dataclass
from enum import Enum


class SymlinkPolicy(Enum):
    """Controls how symlink entries in the archive are handled.

    ``REJECT``
        Any symlink entry raises ``UnsafeEntryError``.  *(default)*
    ``IGNORE``
        Symlink entries are silently skipped.
    ``RESOLVE_INTERNAL``
        Symlinks whose entire target chain stays inside the extraction
        root are permitted and created as real OS symlinks.  Extraction
        is deferred until after all regular files to prevent TOCTOU.
    """

    REJECT = "reject"
    IGNORE = "ignore"
    RESOLVE_INTERNAL = "resolve_internal"


class HardlinkPolicy(Enum):
    """Controls how hardlink entries in the archive are handled.

    ``REJECT``
        Any hardlink entry raises ``UnsafeEntryError``.  *(default)*
    ``INTERNAL``
        Hardlinks are permitted only if the target resolves inside the
        extraction root **and** already exists on disk.
    """

    REJECT = "reject"
    INTERNAL = "internal"


class SparsePolicy(Enum):
    """Controls how GNU sparse file entries are handled.

    ``REJECT``
        Any sparse entry raises ``UnsafeEntryTypeError``.  *(default)*
    ``MATERIALISE``
        Sparse entries are extracted as fully dense (zero-filled) files.
        The per-member and total size monitors apply to the materialised
        (dense) size.
    """

    REJECT = "reject"
    MATERIALISE = "materialise"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Immutable record of a security event detected during extraction.

    Deliberately excludes filenames, paths, and member names so that
    forwarding an event to a third-party service does not leak
    confidential filesystem information.
    """

    event_type: str
    """Type identifier, e.g. ``"tar_slip_detected"``, ``"ratio_exceeded"``."""

    archive_hash: str
    """First 16 hex characters of the SHA-256 of the archive."""

    timestamp: float
    """``time.time()`` at the moment of detection."""
