"""Tests for Phase B — The Sandbox (path resolution and policies)."""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"

import os
import stat

import pytest

from safetar import (
    HardlinkPolicy,
    SafeTarFile,
    SymlinkPolicy,
    UnsafeEntryError,
)
from safetar._sandbox import (
    resolve_member_path,
    sanitise_mode,
    sanitise_mtime,
    sanitise_ownership,
)


class TestPathTraversal:
    """Path normalisation and traversal rejection."""

    def test_dotdot_relative(self, traversal_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError, match="traversal"),
            SafeTarFile(traversal_archive) as stf,
        ):
            stf.extractall(dest)

    def test_absolute_unix_path(self, absolute_path_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError, match="Absolute path"),
            SafeTarFile(absolute_path_archive) as stf,
        ):
            stf.extractall(dest)

    def test_traversal_leaves_no_files(self, traversal_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        try:
            with SafeTarFile(traversal_archive) as stf:
                stf.extractall(dest)
        except UnsafeEntryError:
            pass
        # No files should have been written outside dest.
        assert list(dest.iterdir()) == []

    def test_pax_path_override_blocked(self, pax_traversal_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError),
            SafeTarFile(pax_traversal_archive) as stf,
        ):
            stf.extractall(dest)

    def test_gnu_longname_traversal(self, gnu_longname_traversal_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError, match="traversal"),
            SafeTarFile(gnu_longname_traversal_archive) as stf,
        ):
            stf.extractall(dest)

    def test_unicode_fullwidth_dots_extracted_safely(
        self, unicode_traversal_archive, tmp_path
    ):
        # Fullwidth dots (U+FF0E) do NOT canonically decompose to ASCII dots
        # under NFC normalisation, so they are not a traversal component.
        # The archive should extract safely to a subdirectory with the
        # fullwidth name rather than raise UnsafeEntryError.
        dest = tmp_path / "out"
        with SafeTarFile(unicode_traversal_archive) as stf:
            stf.extractall(dest)
        assert any(dest.rglob("evil.txt"))


class TestResolverUnit:
    """Unit tests for resolve_member_path()."""

    def test_simple_filename(self, tmp_path):
        result = resolve_member_path(tmp_path, "hello.txt")
        assert result.name == "hello.txt"
        assert str(result).startswith(str(tmp_path))

    def test_nested_filename(self, tmp_path):
        result = resolve_member_path(tmp_path, "a/b/c.txt")
        assert result.name == "c.txt"

    def test_dotdot_rejected(self, tmp_path):
        with pytest.raises(UnsafeEntryError, match="traversal"):
            resolve_member_path(tmp_path, "../escape.txt")

    def test_absolute_rejected(self, tmp_path):
        with pytest.raises(UnsafeEntryError, match="Absolute"):
            resolve_member_path(tmp_path, "/etc/passwd")

    def test_null_byte_rejected(self, tmp_path):
        with pytest.raises(UnsafeEntryError, match="Null byte"):
            resolve_member_path(tmp_path, "safe\x00evil")

    def test_empty_rejected(self, tmp_path):
        with pytest.raises(UnsafeEntryError, match="empty"):
            resolve_member_path(tmp_path, "")

    def test_dot_only_rejected(self, tmp_path):
        with pytest.raises(UnsafeEntryError, match="empty"):
            resolve_member_path(tmp_path, ".")

    def test_windows_absolute_rejected(self, tmp_path):
        with pytest.raises(UnsafeEntryError, match="Absolute Windows"):
            resolve_member_path(tmp_path, "C:/Windows/system32")


class TestSymlinkPolicy:
    """Symlink policy enforcement end-to-end."""

    def test_reject_is_default(self, symlink_escape_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError, match="Symlink"),
            SafeTarFile(symlink_escape_archive) as stf,
        ):
            stf.extractall(dest)

    def test_reject_explicit(self, symlink_escape_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError),
            SafeTarFile(
                symlink_escape_archive,
                symlink_policy=SymlinkPolicy.REJECT,
            ) as stf,
        ):
            stf.extractall(dest)

    def test_ignore_skips_symlink(self, symlink_with_regular_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(
            symlink_with_regular_archive,
            symlink_policy=SymlinkPolicy.IGNORE,
        ) as stf:
            stf.extractall(dest)
        # Regular file should be extracted; symlink should be skipped.
        assert (dest / "readme.txt").exists()
        assert not (dest / "link.txt").exists()

    def test_ignore_preserves_regular_files(
        self, symlink_with_regular_archive, tmp_path
    ):
        dest = tmp_path / "out"
        with SafeTarFile(
            symlink_with_regular_archive,
            symlink_policy=SymlinkPolicy.IGNORE,
        ) as stf:
            stf.extractall(dest)
        assert (dest / "readme.txt").read_bytes() == b"safe content\n"

    def test_resolve_internal_allows_safe_symlink(
        self, symlink_internal_archive, tmp_path
    ):
        dest = tmp_path / "out"
        with SafeTarFile(
            symlink_internal_archive,
            symlink_policy=SymlinkPolicy.RESOLVE_INTERNAL,
        ) as stf:
            stf.extractall(dest)
        assert (dest / "target.txt").exists()
        assert (dest / "internal_link.txt").is_symlink()

    def test_resolve_internal_rejects_escape(self, symlink_escape_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError, match="escapes"),
            SafeTarFile(
                symlink_escape_archive,
                symlink_policy=SymlinkPolicy.RESOLVE_INTERNAL,
            ) as stf,
        ):
            stf.extractall(dest)

    def test_resolve_internal_chain_escape(self, symlink_chain_archive, tmp_path):
        # link_b's target ("../../../etc") escapes the root even after
        # link_a (an internal symlink) has been successfully created.
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError),
            SafeTarFile(
                symlink_chain_archive,
                symlink_policy=SymlinkPolicy.RESOLVE_INTERNAL,
            ) as stf,
        ):
            stf.extractall(dest)


class TestHardlinkPolicy:
    """Hardlink policy enforcement end-to-end."""

    def test_reject_is_default(self, hardlink_external_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError, match="Hardlink"),
            SafeTarFile(hardlink_external_archive) as stf,
        ):
            stf.extractall(dest)

    def test_internal_valid(self, hardlink_internal_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(
            hardlink_internal_archive,
            hardlink_policy=HardlinkPolicy.INTERNAL,
        ) as stf:
            stf.extractall(dest)
        assert (dest / "original.txt").exists()
        assert (dest / "copy.txt").exists()
        # They should share the same inode.
        assert (
            os.stat(dest / "original.txt").st_ino == os.stat(dest / "copy.txt").st_ino
        )

    def test_forward_reference_rejected(self, hardlink_forward_ref_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError, match="forward reference"),
            SafeTarFile(
                hardlink_forward_ref_archive,
                hardlink_policy=HardlinkPolicy.INTERNAL,
            ) as stf,
        ):
            stf.extractall(dest)


class TestPermissionSanitisation:
    """setuid/setgid/sticky bit stripping."""

    def test_setuid_stripped_by_default(self, setuid_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(setuid_archive) as stf:
            stf.extractall(dest)
        mode = (dest / "suid_binary").stat().st_mode
        assert not (mode & stat.S_ISUID)  # setuid stripped
        assert mode & stat.S_IXUSR  # execute bit preserved

    @pytest.mark.skipif(os.getuid() != 0, reason="setuid requires root privileges")
    def test_setuid_preserved_opt_in(self, setuid_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(setuid_archive, strip_special_bits=False) as stf:
            stf.extractall(dest)
        mode = (dest / "suid_binary").stat().st_mode
        assert mode & stat.S_ISUID  # setuid preserved


class TestSanitisationUnits:
    """Unit tests for sanitisation functions."""

    def test_sanitise_mode_strips_suid(self):
        assert sanitise_mode(0o4755) == 0o0755

    def test_sanitise_mode_strips_sgid(self):
        assert sanitise_mode(0o2755) == 0o0755

    def test_sanitise_mode_strips_sticky(self):
        assert sanitise_mode(0o1755) == 0o0755

    def test_sanitise_mode_preserves_when_off(self):
        assert sanitise_mode(0o4755, strip_special_bits=False) == 0o4755

    def test_sanitise_ownership_clamps(self):
        uid, gid = sanitise_ownership(0, 0)
        assert uid == os.getuid()
        assert gid == os.getgid()

    def test_sanitise_ownership_preserves(self):
        uid, gid = sanitise_ownership(1000, 1000, preserve_ownership=True)
        assert uid == 1000
        assert gid == 1000

    def test_sanitise_mtime_clamps_negative(self):
        result = sanitise_mtime(-1)
        assert result > 0  # replaced with current time

    def test_sanitise_mtime_clamps_far_future(self):
        result = sanitise_mtime(2**40)
        assert result < 2**40  # replaced with current time

    def test_sanitise_mtime_passes_valid(self):
        assert sanitise_mtime(1000000) == 1000000.0

    def test_sanitise_mtime_preserves_when_off(self):
        result = sanitise_mtime(-1, clamp_timestamps=False)
        assert result == -1.0
