"""Phase B — The Sandbox: path resolution, type-policy enforcement,
and permission/ownership/timestamp sanitisation.

Every candidate extraction path is resolved against a strictly enforced
base directory.  Entry-type policies (symlinks, hardlinks, sparse) and
metadata sanitisation are also handled here.
"""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "resolve_member_path",
    "verify_symlink_chain",
    "verify_hardlink_target",
    "sanitise_mode",
    "sanitise_ownership",
    "sanitise_mtime",
)

import contextlib
import os
import stat
import time
import unicodedata
from pathlib import Path

from safetar._exceptions import UnsafeEntryError

# Maximum filename length (must match _guard.MAX_PATH).
MAX_PATH = 4096


# ---- path resolution -------------------------------------------------------


def resolve_member_path(
    base_dir: str | os.PathLike[str],
    member_name: str,
) -> Path:
    """Resolve *member_name* against *base_dir* and return a safe ``Path``.

    Pipeline (in order):

    1.  Unicode NFC normalisation.
    2.  Reject absolute paths (``/``, ``\\``, drive letter).
    3.  Resolve ``..`` components; reject if the result escapes *base_dir*.
    4.  Reject null bytes.
    5.  Reject over-length names.

    Raises ``UnsafeEntryError`` for any violation.
    """
    base = Path(base_dir).resolve()

    # 1. NFC normalise.
    normalized = unicodedata.normalize("NFC", member_name)

    # 2. Normalise separators and check for absolute paths.
    _norm = normalized.replace("\\", "/")

    # Reject absolute Unix / UNC paths.
    if _norm.startswith("/"):
        raise UnsafeEntryError(
            f"Absolute path detected in member name: {member_name!r}"
        )

    # Reject absolute Windows paths (C:/ etc.).
    if len(_norm) >= 3 and _norm[1] == ":" and _norm[2] == "/" and _norm[0].isalpha():
        raise UnsafeEntryError(
            f"Absolute Windows path detected in member name: {member_name!r}"
        )

    # 3. Split, strip empties and lone dots, reject traversals.
    parts = _norm.split("/")
    clean_parts: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise UnsafeEntryError(
                f"Path traversal component '..' in member name: {member_name!r}"
            )
        clean_parts.append(part)

    if not clean_parts:
        raise UnsafeEntryError(f"Member name resolves to empty path: {member_name!r}")

    # 4. Null-byte check (on the cleaned name).
    joined = "/".join(clean_parts)
    if "\x00" in joined:
        raise UnsafeEntryError(f"Null byte in member name: {member_name!r}")

    # 5. Length check.
    resolved = base / joined
    if len(str(resolved)) > MAX_PATH:
        raise UnsafeEntryError(f"Resolved path length exceeds MAX_PATH ({MAX_PATH})")

    # Belt-and-braces: final containment check via resolved paths.
    try:
        real = resolved.resolve()
    except OSError:
        # Parent dirs don't exist yet — that's fine, we'll create them.
        # Just verify the normalised parts stay inside base.
        real = resolved

    if not (real == base or str(real).startswith(str(base) + os.sep)):
        raise UnsafeEntryError(f"Resolved path escapes base directory: {member_name!r}")

    return resolved


# ---- symlink chain verification -------------------------------------------


def verify_symlink_chain(
    base_dir: Path,
    symlink_path: Path,
    symlink_target: str,
    *,
    max_follow: int = 10,
) -> None:
    """Verify that the entire symlink chain stays inside *base_dir*.

    *symlink_path* is where the symlink will be created.
    *symlink_target* is the raw target string from the archive entry.

    Each link in the chain is resolved iteratively.  If any link
    exits *base_dir*, ``UnsafeEntryError`` is raised.  A chain longer
    than *max_follow* hops is also rejected (infinite-loop guard).
    """
    base = base_dir.resolve()

    # Resolve the immediate target relative to the symlink's parent.
    current = symlink_path.parent / symlink_target
    with contextlib.suppress(OSError):
        current = current.resolve()  # parent doesn't exist yet; check raw path

    if not (current == base or str(current).startswith(str(base) + os.sep)):
        raise UnsafeEntryError(
            f"Symlink target escapes extraction root: {symlink_target!r}"
        )

    # Follow further links in the chain.
    for _ in range(max_follow):
        if not current.is_symlink():
            return  # end of chain — all good
        link_target = os.readlink(current)
        current = (current.parent / link_target).resolve()
        if not (current == base or str(current).startswith(str(base) + os.sep)):
            raise UnsafeEntryError(
                f"Symlink chain escapes extraction root at: {current!r}"
            )

    raise UnsafeEntryError(f"Symlink chain exceeds maximum depth ({max_follow})")


# ---- hardlink verification ------------------------------------------------


def verify_hardlink_target(
    base_dir: Path,
    link_name_resolved: Path,
    link_target: str,
    extracted_paths: set[Path],
) -> Path:
    """Verify a hardlink target is internal and already on disk.

    Returns the resolved target path.

    Raises ``UnsafeEntryError`` if the target is outside *base_dir*
    or has not yet been extracted (forward reference).
    """
    # Resolve the target the same way we resolve member names.
    target_resolved = resolve_member_path(base_dir, link_target)

    if target_resolved not in extracted_paths:
        raise UnsafeEntryError(
            f"Hardlink target not yet extracted (forward reference "
            f"rejected): {link_target!r}"
        )

    if not target_resolved.exists():
        raise UnsafeEntryError(
            f"Hardlink target does not exist on disk: {link_target!r}"
        )

    return target_resolved


# ---- permission / ownership / timestamp sanitisation -----------------------


def sanitise_mode(
    mode: int,
    *,
    strip_special_bits: bool = True,
    strip_write_bits: bool = False,
) -> int:
    """Strip dangerous permission bits from *mode*.

    By default removes setuid (``04000``), setgid (``02000``), and
    sticky (``01000``) bits.  Optionally also removes write bits.
    """
    if strip_special_bits:
        mode &= ~(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    if strip_write_bits:
        mode &= ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    return mode


def sanitise_ownership(
    uid: int,
    gid: int,
    *,
    preserve_ownership: bool = False,
) -> tuple[int, int]:
    """Clamp UID/GID to the current effective user unless preservation
    is explicitly requested.
    """
    if preserve_ownership:
        return uid, gid
    return os.getuid(), os.getgid()


def sanitise_mtime(
    mtime: float | int,
    *,
    clamp_timestamps: bool = True,
) -> float:
    """Clamp *mtime* to a safe range.

    When *clamp_timestamps* is ``True``, values outside ``[0, 2**32 - 1]``
    are replaced by the current time.
    """
    if not clamp_timestamps:
        return float(mtime)
    max_ts = 2**32 - 1
    if mtime < 0 or mtime > max_ts:
        return time.time()
    return float(mtime)
