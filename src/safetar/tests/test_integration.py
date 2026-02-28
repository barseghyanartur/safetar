"""End-to-end integration tests for safetar."""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"

import os

import pytest

from safetar import (
    MalformedArchiveError,
    NestingDepthError,
    SafeTarFile,
    SecurityEvent,
    UnsafeEntryError,
    safe_extract,
)


class TestLegitimateExtraction:
    """Legitimate archives extract correctly."""

    def test_all_files_extracted(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(legitimate_archive) as stf:
            stf.extractall(dest)
        assert (dest / "readme.txt").exists()
        assert (dest / "data" / "report.csv").exists()
        assert (dest / "data" / "notes.txt").exists()

    def test_safe_extract_convenience(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        safe_extract(legitimate_archive, dest)
        assert (dest / "readme.txt").read_bytes() == b"Hello, world!\n"

    def test_gz_extraction(self, legitimate_gz_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(legitimate_gz_archive) as stf:
            stf.extractall(dest)
        assert (dest / "hello.txt").read_bytes() == b"Hello from gzip!\n"

    def test_context_manager_closes_properly(self, legitimate_archive):
        stf = SafeTarFile(legitimate_archive)
        stf.__enter__()
        stf.__exit__(None, None, None)
        # After close, the internal tarfile's fileobj should be closed.
        assert stf._tf.fileobj is None or stf._tf.fileobj.closed


class TestExplicitPathRequirement:
    """extractall() requires an explicit path."""

    def test_extractall_requires_path(self, legitimate_archive):
        with (
            SafeTarFile(legitimate_archive) as stf,
            pytest.raises(TypeError, match="explicit"),
        ):
            stf.extractall(None)  # type: ignore[arg-type]


class TestSecurityEventCallback:
    """on_security_event callback behaviour."""

    def test_callback_called_on_event(self, traversal_archive, tmp_path):
        events: list[SecurityEvent] = []
        dest = tmp_path / "out"
        try:
            with SafeTarFile(traversal_archive, on_security_event=events.append) as stf:
                stf.extractall(dest)
        except UnsafeEntryError:
            pass
        assert len(events) == 1
        assert events[0].event_type == "security_violation"
        assert len(events[0].archive_hash) == 16

    def test_callback_exception_does_not_swallow_error(
        self, traversal_archive, tmp_path
    ):
        def bad_callback(event: SecurityEvent) -> None:
            raise RuntimeError("callback boom")

        dest = tmp_path / "out"
        with (
            pytest.raises(UnsafeEntryError),
            SafeTarFile(traversal_archive, on_security_event=bad_callback) as stf,
        ):
            stf.extractall(dest)


class TestNestingDepth:
    """Nesting depth enforcement."""

    def test_nesting_depth_exceeded(self, legitimate_archive):
        with pytest.raises(NestingDepthError):
            SafeTarFile(
                legitimate_archive,
                max_nesting_depth=3,
                _nesting_depth=4,
            )

    def test_nesting_depth_at_limit_passes(self, legitimate_archive):
        with SafeTarFile(
            legitimate_archive,
            max_nesting_depth=3,
            _nesting_depth=3,
        ) as stf:
            assert len(stf.getnames()) > 0


class TestTruncatedArchive:
    """Truncated archives raise MalformedArchiveError."""

    def test_truncated_gz_raises(self, truncated_archive, tmp_path):
        dest = tmp_path / "out"
        with (
            pytest.raises(MalformedArchiveError),
            SafeTarFile(truncated_archive) as stf,
        ):
            stf.extractall(dest)


class TestTimestampSanitisation:
    """Timestamp clamping end-to-end."""

    def test_timestamps_clamped(self, extreme_timestamp_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(extreme_timestamp_archive) as stf:
            stf.extractall(dest)
        # epoch_zero.txt: mtime=0 is inside [0, 2**32-1], so it is
        # preserved as-is (not replaced by the current time).
        zero_mtime = os.path.getmtime(dest / "epoch_zero.txt")
        assert zero_mtime == 0.0
        # far_future.txt should have mtime clamped (not 2**40).
        future_mtime = os.path.getmtime(dest / "far_future.txt")
        assert future_mtime < 2**40


class TestOwnershipSanitisation:
    """UID/GID clamping end-to-end."""

    def test_uid_gid_clamped(self, setuid_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(setuid_archive) as stf:
            stf.extractall(dest)
        st = os.stat(dest / "suid_binary")
        assert st.st_uid == os.getuid()
        assert st.st_gid == os.getgid()


class TestWriteModeRejected:
    """Write modes are rejected at construction."""

    def test_write_mode_raises(self, tmp_path):
        with pytest.raises(ValueError, match="write mode"):
            SafeTarFile(tmp_path / "nonexistent.tar", mode="w")

    def test_append_mode_raises(self, tmp_path):
        with pytest.raises(ValueError, match="write mode"):
            SafeTarFile(tmp_path / "nonexistent.tar", mode="a")


class TestSingleMemberExtract:
    """extract() for a single member."""

    def test_extract_single_member(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        with SafeTarFile(legitimate_archive) as stf:
            stf.extract("readme.txt", dest)
        assert (dest / "readme.txt").exists()
        assert not (dest / "data").exists()
