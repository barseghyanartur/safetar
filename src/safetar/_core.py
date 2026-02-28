"""SafeTarFile — composition-based hardened TAR extraction.

``SafeTarFile`` wraps ``tarfile.TarFile`` internally and exposes only
the safe subset of its interface.  No unsafe method from the standard
library is reachable through the public API.
"""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "SafeTarFile",
    "safe_extract",
)

import contextlib
import logging
import os
import tarfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from safetar._events import (
    HardlinkPolicy,
    SecurityEvent,
    SparsePolicy,
    SymlinkPolicy,
)
from safetar._exceptions import (
    MalformedArchiveError,
    NestingDepthError,
    SafetarError,
)
from safetar._guard import (
    ensure_seekable,
    pre_scan_file_count,
    validate_entry_type,
    validate_filename,
    validate_pax_path,
)
from safetar._sandbox import (
    resolve_member_path,
    sanitise_mode,
    sanitise_mtime,
    sanitise_ownership,
    verify_hardlink_target,
    verify_symlink_chain,
)
from safetar._streamer import (
    ExtractionMonitor,
    compute_archive_hash,
    extract_member_streaming,
)

log = logging.getLogger("safetar.security")


# ---- environment-variable configuration helpers ----------------------------
# Each helper reads the relevant SAFETAR_* variable and returns its typed
# value, falling back to *fallback* on absence or parse failure.


def _env_int(name: str, fallback: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return fallback
    try:
        return int(raw)
    except ValueError:
        return fallback


def _env_float(name: str, fallback: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return fallback
    try:
        return float(raw)
    except ValueError:
        return fallback


def _env_bool(name: str, fallback: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return fallback
    return raw.lower() not in ("0", "false", "no", "off", "")


def _env_symlink_policy() -> SymlinkPolicy:
    raw = os.environ.get("SAFETAR_SYMLINK_POLICY")
    if raw is None:
        return SymlinkPolicy.REJECT
    try:
        return SymlinkPolicy(raw.lower())
    except ValueError:
        return SymlinkPolicy.REJECT


def _env_hardlink_policy() -> HardlinkPolicy:
    raw = os.environ.get("SAFETAR_HARDLINK_POLICY")
    if raw is None:
        return HardlinkPolicy.REJECT
    try:
        return HardlinkPolicy(raw.lower())
    except ValueError:
        return HardlinkPolicy.REJECT


def _env_sparse_policy() -> SparsePolicy:
    raw = os.environ.get("SAFETAR_SPARSE_POLICY")
    if raw is None:
        return SparsePolicy.REJECT
    try:
        return SparsePolicy(raw.lower())
    except ValueError:
        return SparsePolicy.REJECT


# Module-level singletons evaluated once at import time.
_DEFAULT_SYMLINK_POLICY: SymlinkPolicy = _env_symlink_policy()
_DEFAULT_HARDLINK_POLICY: HardlinkPolicy = _env_hardlink_policy()
_DEFAULT_SPARSE_POLICY: SparsePolicy = _env_sparse_policy()


class SafeTarFile:
    """Hardened TAR extraction wrapper.

    Wraps ``tarfile.TarFile`` via composition.  Only safe, read-only
    methods are exposed.

    :param file: Path to the archive or an open binary file object.
    :param mode: Read mode string.  Default ``"r:*"`` (auto-detect
        compression).  Only read modes are accepted.
    :param max_file_size: Maximum decompressed size per member (bytes).
    :param max_total_size: Maximum cumulative decompressed size (bytes).
    :param max_files: Maximum number of entries in the archive.
    :param max_ratio: Maximum archive-level decompression ratio.
    :param max_nesting_depth: Maximum allowed nesting depth for recursive
        extraction.
    :param symlink_policy: How to handle symlink entries.
    :param hardlink_policy: How to handle hardlink entries.
    :param sparse_policy: How to handle GNU sparse file entries.
    :param strip_special_bits: Strip setuid/setgid/sticky bits from
        extracted files.
    :param strip_write_bits: Additionally strip write bits from extracted
        files.
    :param preserve_ownership: Preserve archived UID/GID (requires root).
    :param clamp_timestamps: Clamp mtime to ``[0, 2**32 - 1]``.
    :param on_security_event: Optional callback invoked on every security
        event.
    :param _nesting_depth: Internal nesting depth counter (not part of
        the public API).
    :raises ValueError: If a write mode (``"w"``, ``"a"``, ``"x"``) is
        passed as *mode*.
    :raises NestingDepthError: If *_nesting_depth* exceeds
        *max_nesting_depth*.
    :raises MalformedArchiveError: If the archive cannot be opened
        (unreadable or structurally invalid).
    """

    def __init__(
        self,
        file: str | os.PathLike[str] | BinaryIO,
        mode: str = "r:*",
        *,
        max_file_size: int = _env_int("SAFETAR_MAX_FILE_SIZE", 1 * 1024**3),
        max_total_size: int = _env_int("SAFETAR_MAX_TOTAL_SIZE", 5 * 1024**3),
        max_files: int = _env_int("SAFETAR_MAX_FILES", 10_000),
        max_ratio: float = _env_float("SAFETAR_MAX_RATIO", 200.0),
        max_nesting_depth: int = _env_int("SAFETAR_MAX_NESTING_DEPTH", 3),
        symlink_policy: SymlinkPolicy = _DEFAULT_SYMLINK_POLICY,
        hardlink_policy: HardlinkPolicy = _DEFAULT_HARDLINK_POLICY,
        sparse_policy: SparsePolicy = _DEFAULT_SPARSE_POLICY,
        strip_special_bits: bool = _env_bool("SAFETAR_STRIP_SPECIAL_BITS", True),
        strip_write_bits: bool = False,
        preserve_ownership: bool = _env_bool("SAFETAR_PRESERVE_OWNERSHIP", False),
        clamp_timestamps: bool = _env_bool("SAFETAR_CLAMP_TIMESTAMPS", True),
        on_security_event: Callable[[SecurityEvent], None] | None = None,
        _nesting_depth: int = 0,
    ) -> None:
        # --- reject write modes ---
        if any(mode.startswith(p) for p in ("w", "a", "x")):
            raise ValueError(
                f"SafeTarFile is extraction-only; write mode {mode!r} is not permitted"
            )

        # --- nesting depth ---
        if _nesting_depth > max_nesting_depth:
            raise NestingDepthError(
                f"Nesting depth ({_nesting_depth}) exceeds "
                f"max_nesting_depth ({max_nesting_depth})"
            )

        self._max_file_size = max_file_size
        self._max_total_size = max_total_size
        self._max_files = max_files
        self._max_ratio = max_ratio
        self._max_nesting_depth = max_nesting_depth
        self._symlink_policy = symlink_policy
        self._hardlink_policy = hardlink_policy
        self._sparse_policy = sparse_policy
        self._strip_special_bits = strip_special_bits
        self._strip_write_bits = strip_write_bits
        self._preserve_ownership = preserve_ownership
        self._clamp_timestamps = clamp_timestamps
        self._on_security_event = on_security_event
        self._nesting_depth = _nesting_depth

        # --- ensure seekable input ---
        # Convert streaming modes to seekable equivalents for pre-scan.
        self._scan_mode = mode.replace("|", ":")
        fileobj, self._owns_fileobj = ensure_seekable(file, max_total_size)
        self._fileobj: BinaryIO = fileobj

        # --- compute archive hash and size for SecurityEvent / ratio ---
        self._archive_hash = compute_archive_hash(self._fileobj)
        # Archive size is used for compression ratio monitoring.
        pos = self._fileobj.tell()
        self._fileobj.seek(0, 2)  # seek to end
        self._archive_size = self._fileobj.tell()
        self._fileobj.seek(pos)

        # --- pre-scan: file count ---
        pre_scan_file_count(self._fileobj, self._scan_mode, self._max_files)

        # --- open for extraction ---
        try:
            self._tf = tarfile.open(fileobj=self._fileobj, mode=self._scan_mode)  # noqa: SIM115
        except tarfile.TarError as exc:
            raise MalformedArchiveError(str(exc)) from exc

        # Apply Python 3.12+ stdlib filter as an additional defensive layer.
        if hasattr(tarfile.TarFile, "extraction_filter"):
            self._tf.extraction_filter = tarfile.data_filter  # type: ignore[attr-defined]

    # ---- context manager ---------------------------------------------------

    def __enter__(self) -> SafeTarFile:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the archive."""
        try:
            self._tf.close()
        finally:
            if self._owns_fileobj:
                with contextlib.suppress(Exception):
                    self._fileobj.close()

    # ---- read-only proxies -------------------------------------------------

    def getmembers(self) -> list[tarfile.TarInfo]:
        return self._tf.getmembers()

    def getnames(self) -> list[str]:
        return self._tf.getnames()

    def getmember(self, name: str) -> tarfile.TarInfo:
        return self._tf.getmember(name)

    def namelist(self) -> list[str]:
        """Alias for ``getnames()`` (consistency with safezip)."""
        return self._tf.getnames()

    # ---- extraction --------------------------------------------------------

    def extractall(
        self,
        path: str | os.PathLike[str],
        members: list[str | tarfile.TarInfo] | None = None,
    ) -> None:
        """Extract all (or selected) members to *path*.

        *path* is required and must not be ``None``.

        Raises ``TypeError`` if *path* is omitted.
        """
        if path is None:
            raise TypeError(
                "SafeTarFile.extractall() requires an explicit 'path' "
                "argument; extraction to the current working directory "
                "is not permitted"
            )

        base_dir = Path(path).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)

        # Resolve member list.
        if members is not None:
            infos: list[tarfile.TarInfo] = []
            for m in members:
                if isinstance(m, str):
                    infos.append(self._tf.getmember(m))
                else:
                    infos.append(m)
        else:
            infos = self._tf.getmembers()

        # Set up monitors.
        monitor = ExtractionMonitor(
            max_file_size=self._max_file_size,
            max_total_size=self._max_total_size,
            max_ratio=self._max_ratio,
            archive_size=self._archive_size,
        )

        deferred_symlinks: list[tuple[Path, str]] = []
        deferred_dirs: list[tuple[tarfile.TarInfo, Path]] = []
        extracted_paths: set[Path] = set()

        for info in infos:
            self._extract_one(
                info,
                base_dir,
                monitor,
                deferred_symlinks,
                deferred_dirs,
                extracted_paths,
            )

        # --- deferred symlink creation (TOCTOU defence) ---
        for sym_path, sym_target in deferred_symlinks:
            verify_symlink_chain(base_dir, sym_path, sym_target)
            sym_path.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(sym_target, sym_path)

        # --- deferred directory metadata (after all files extracted) ---
        for dir_info, dir_path in deferred_dirs:
            self._apply_metadata(dir_info, dir_path)

    def extract(
        self,
        member: str | tarfile.TarInfo,
        path: str | os.PathLike[str],
    ) -> None:
        """Extract a single *member* to *path*."""
        if isinstance(member, str):
            member = self._tf.getmember(member)
        self.extractall(path, members=[member])

    # ---- internal ----------------------------------------------------------

    def _extract_one(
        self,
        info: tarfile.TarInfo,
        base_dir: Path,
        monitor: ExtractionMonitor,
        deferred_symlinks: list[tuple[Path, str]],
        deferred_dirs: list[tuple[tarfile.TarInfo, Path]],
        extracted_paths: set[Path],
    ) -> None:
        """Run Guard → Sandbox → Streamer for a single member."""
        try:
            self._extract_one_inner(
                info,
                base_dir,
                monitor,
                deferred_symlinks,
                deferred_dirs,
                extracted_paths,
            )
        except SafetarError:
            self._fire_event(info)
            raise

    def _extract_one_inner(
        self,
        info: tarfile.TarInfo,
        base_dir: Path,
        monitor: ExtractionMonitor,
        deferred_symlinks: list[tuple[Path, str]],
        deferred_dirs: list[tuple[tarfile.TarInfo, Path]],
        extracted_paths: set[Path],
    ) -> None:
        # ---- Guard phase ----
        disposition = validate_entry_type(
            info,
            symlink_policy=self._symlink_policy,
            hardlink_policy=self._hardlink_policy,
            sparse_policy=self._sparse_policy,
        )
        if disposition == "skip":
            return

        effective_name = validate_filename(info)
        pax_path = validate_pax_path(info)

        # ---- Sandbox phase: path resolution ----
        # Check the effective name (which tarfile uses for extraction).
        dest_path = resolve_member_path(base_dir, effective_name)

        # If there's a PAX path override, also validate it.
        if pax_path is not None and pax_path != effective_name:
            resolve_member_path(base_dir, pax_path)

        # ---- Sandbox phase: type-specific handling ----

        if disposition == "defer_symlink":
            # RESOLVE_INTERNAL — defer to post-extraction batch.
            deferred_symlinks.append((dest_path, info.linkname))
            return

        if info.isdir():
            dest_path.mkdir(parents=True, exist_ok=True)
            # Defer directory metadata until after all files are
            # extracted, so restrictive permissions don't block
            # extraction of files inside the directory.
            deferred_dirs.append((info, dest_path))
            extracted_paths.add(dest_path)
            return

        if info.islnk():
            # Hardlink — INTERNAL policy (REJECT already raised in Guard).
            target_path = verify_hardlink_target(
                base_dir, dest_path, info.linkname, extracted_paths
            )
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            os.link(target_path, dest_path)
            extracted_paths.add(dest_path)
            return

        # ---- Streamer phase: regular file extraction ----
        extract_member_streaming(self._tf, info, dest_path, monitor)
        self._apply_metadata(info, dest_path)
        extracted_paths.add(dest_path)

    def _apply_metadata(self, info: tarfile.TarInfo, dest_path: Path) -> None:
        """Apply sanitised permissions, ownership, and timestamps.

        Order matters: ownership must be applied before permissions.
        On POSIX, chown(2) is permitted to clear setuid/setgid bits
        (and does so unconditionally in Linux user-namespace containers
        that lack CAP_FSETID at the host level).  Setting chmod last
        ensures the final mode matches what was requested.
        """
        # Ownership first — chown can clear setuid/setgid on some kernels.
        # Only call os.chown() when the caller explicitly opts in to
        # preserving archived UID/GID; otherwise leave the file owned by
        # the current process (the default, per the plan).
        if self._preserve_ownership:
            uid, gid = sanitise_ownership(
                info.uid,
                info.gid,
                preserve_ownership=True,
            )
            with contextlib.suppress(OSError):
                os.chown(dest_path, uid, gid)

        # Permissions after ownership — chmod must come last so that
        # setuid/setgid bits survive the chown call above.
        if info.mode is not None:
            safe_mode = sanitise_mode(
                info.mode,
                strip_special_bits=self._strip_special_bits,
                strip_write_bits=self._strip_write_bits,
            )
            with contextlib.suppress(OSError):
                os.chmod(dest_path, safe_mode)

        # Timestamps.
        mtime = sanitise_mtime(info.mtime, clamp_timestamps=self._clamp_timestamps)
        with contextlib.suppress(OSError):
            os.utime(dest_path, (mtime, mtime))

    def _fire_event(self, info: tarfile.TarInfo) -> None:
        """Invoke the on_security_event callback if configured."""
        if self._on_security_event is None:
            return

        event = SecurityEvent(
            event_type=_event_type_for(info),
            archive_hash=self._archive_hash,
            timestamp=time.time(),
        )
        try:
            self._on_security_event(event)
        except Exception:
            log.exception("on_security_event callback raised an exception")


def _event_type_for(info: tarfile.TarInfo) -> str:
    """Derive a security event type string from the member."""
    if info.issym():
        return "symlink_violation"
    if info.islnk():
        return "hardlink_violation"
    if info.isdir():
        return "directory_violation"
    return "security_violation"


def safe_extract(
    archive: str | os.PathLike[str] | BinaryIO,
    destination: str | os.PathLike[str],
    **kwargs: object,
) -> None:
    """Extract *archive* to *destination* using ``SafeTarFile`` defaults.

    All keyword arguments are forwarded to the ``SafeTarFile`` constructor.
    """
    with SafeTarFile(archive, **kwargs) as stf:  # type: ignore[arg-type]
        stf.extractall(destination)
