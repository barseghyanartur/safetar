"""Tests for Phase C — The Streamer (runtime byte monitoring)."""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"

import pytest

from safetar import (
    CompressionRatioError,
    FileSizeExceededError,
    SafeTarFile,
    TotalSizeExceededError,
)


class TestFileSizeLimit:
    """Per-member size enforcement."""

    def test_size_exceeded_raises(self, large_member_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(FileSizeExceededError),
            SafeTarFile(large_member_archive, max_file_size=500_000) as stf,
        ):
            stf.extractall(dest)

    def test_no_partial_file_after_failure(self, large_member_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        try:
            with SafeTarFile(large_member_archive, max_file_size=500_000) as stf:
                stf.extractall(dest)
        except FileSizeExceededError:
            pass
        # No temp files should remain.
        remaining = list(dest.rglob("*.safetar_tmp_*"))
        assert remaining == []

    def test_size_at_limit_passes(self, large_member_archive, tmp_path):
        dest = tmp_path / "out"
        # 2 MiB member — set limit to exactly 2 MiB.
        with SafeTarFile(large_member_archive, max_file_size=2 * 1024 * 1024) as stf:
            stf.extractall(dest)
        assert (dest / "big.bin").exists()


class TestTotalSizeLimit:
    """Cumulative size enforcement."""

    def test_total_size_exceeded(self, large_member_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(TotalSizeExceededError),
            SafeTarFile(large_member_archive, max_total_size=500_000) as stf,
        ):
            stf.extractall(dest)


class TestCompressionRatioLimit:
    """Archive-level compression ratio enforcement."""

    def test_gz_ratio_exceeded(self, bomb_gz_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(CompressionRatioError),
            SafeTarFile(bomb_gz_archive, max_ratio=5.0) as stf,
        ):
            stf.extractall(dest)

    def test_bz2_ratio_exceeded(self, bomb_bz2_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(CompressionRatioError),
            SafeTarFile(bomb_bz2_archive, max_ratio=5.0) as stf,
        ):
            stf.extractall(dest)

    def test_xz_ratio_exceeded(self, bomb_xz_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(CompressionRatioError),
            SafeTarFile(bomb_xz_archive, max_ratio=5.0) as stf,
        ):
            stf.extractall(dest)

    def test_generous_ratio_passes(self, bomb_gz_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(
            bomb_gz_archive,
            max_ratio=50000.0,
            max_file_size=20 * 1024 * 1024,
            max_total_size=20 * 1024 * 1024,
        ) as stf:
            stf.extractall(dest)
        assert (dest / "zeros.bin").exists()


class TestAtomicWrite:
    """Atomic write contract."""

    def test_successful_extraction_creates_file(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(legitimate_archive) as stf:
            stf.extractall(dest)
        assert (dest / "readme.txt").exists()
        assert (dest / "readme.txt").read_bytes() == b"Hello, world!\n"

    def test_no_temp_files_after_success(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(legitimate_archive) as stf:
            stf.extractall(dest)
        remaining = list(dest.rglob("*.safetar_tmp_*"))
        assert remaining == []
