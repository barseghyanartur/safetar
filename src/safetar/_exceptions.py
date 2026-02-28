"""Exception hierarchy for safetar.

All exceptions inherit from ``SafetarError`` so callers can catch the
package's entire error surface with a single ``except`` clause.
"""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


class SafetarError(Exception):
    """Base exception for all safetar security violations."""


class UnsafeEntryError(SafetarError):
    """A member's path escapes the extraction root.

    Raised for path traversal (``../``), absolute paths (``/etc/passwd``),
    symlink or hardlink policy violations, and PAX header path overrides
    that resolve outside the base directory.
    """


class UnsafeEntryTypeError(SafetarError):
    """A member's type is not on the allowed whitelist.

    Raised for character devices, block devices, FIFOs, sparse entries
    (when ``sparse_policy=REJECT``), and any unrecognised TAR type code.
    """


class FileSizeExceededError(SafetarError):
    """A single member's decompressed size exceeds ``max_file_size``."""


class TotalSizeExceededError(SafetarError):
    """Cumulative extraction size exceeds ``max_total_size``."""


class CompressionRatioError(SafetarError):
    """Archive-level decompression ratio exceeds ``max_ratio``."""


class FileCountExceededError(SafetarError):
    """The archive contains more members than ``max_files``."""


class NestingDepthError(SafetarError):
    """Nested archive depth exceeds ``max_nesting_depth``."""


class MalformedArchiveError(SafetarError):
    """The archive is structurally invalid.

    Raised for unreadable headers, truncated streams, PAX/GNU
    inconsistencies, and other structural defects.
    """
