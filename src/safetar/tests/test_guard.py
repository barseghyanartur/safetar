"""Tests for Phase A — The Guard (header validation and pre-scan)."""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"

import pytest

from safetar import (
    FileCountExceededError,
    SafeTarFile,
    UnsafeEntryTypeError,
)


class TestFileCountLimit:
    """Pre-scan file count enforcement."""

    def test_file_count_at_limit_passes(self, many_files_archive):
        # The fixture has 101 entries — setting limit to 101 should pass.
        with SafeTarFile(many_files_archive, max_files=101) as stf:
            assert len(stf.getnames()) == 101

    def test_file_count_one_over_raises(self, many_files_archive):
        # 101 entries, limit 100.
        with pytest.raises(FileCountExceededError):
            SafeTarFile(many_files_archive, max_files=100)

    def test_legitimate_archive_passes(self, legitimate_archive):
        with SafeTarFile(legitimate_archive) as stf:
            names = stf.getnames()
        assert len(names) > 0


class TestEntryTypeWhitelist:
    """Guard-phase entry type validation."""

    def test_char_device_rejected(self, char_device_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryTypeError, match="character device"),
            SafeTarFile(char_device_archive) as stf,
        ):
            stf.extractall(dest)

    def test_block_device_rejected(self, block_device_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryTypeError, match="block device"),
            SafeTarFile(block_device_archive) as stf,
        ):
            stf.extractall(dest)

    def test_fifo_rejected(self, fifo_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryTypeError, match="FIFO"),
            SafeTarFile(fifo_archive) as stf,
        ):
            stf.extractall(dest)

    def test_unknown_type_rejected(self, unknown_type_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryTypeError, match="Unrecognised"),
            SafeTarFile(unknown_type_archive) as stf,
        ):
            stf.extractall(dest)


class TestFilenameSanity:
    """Guard-phase filename validation."""

    def test_legitimate_names_accessible(self, legitimate_archive):
        with SafeTarFile(legitimate_archive) as stf:
            names = stf.getnames()
        assert "readme.txt" in names
