"""safetar — Hardened TAR extraction for Python.

Secure by default.  Zero dependencies.  Python 3.10+.
"""

from __future__ import annotations

__title__ = "safetar"
__version__ = "0.1"
__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"

from safetar._events import (
    HardlinkPolicy,
    SecurityEvent,
    SparsePolicy,
    SymlinkPolicy,
)
from safetar._exceptions import (
    CompressionRatioError,
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
    NestingDepthError,
    SafetarError,
    TotalSizeExceededError,
    UnsafeEntryError,
    UnsafeEntryTypeError,
)

# Deferred imports to avoid circular dependency — _core imports from
# _events and _exceptions, so we import _core lazily here.


def __getattr__(name: str) -> object:
    if name in ("SafeTarFile", "safe_extract"):
        from safetar._core import SafeTarFile, safe_extract

        globals()["SafeTarFile"] = SafeTarFile
        globals()["safe_extract"] = safe_extract
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Core
    "SafeTarFile",
    "safe_extract",
    # Exceptions
    "SafetarError",
    "UnsafeEntryError",
    "UnsafeEntryTypeError",
    "FileSizeExceededError",
    "TotalSizeExceededError",
    "CompressionRatioError",
    "FileCountExceededError",
    "NestingDepthError",
    "MalformedArchiveError",
    # Events & Policies
    "SecurityEvent",
    "SymlinkPolicy",
    "HardlinkPolicy",
    "SparsePolicy",
]
