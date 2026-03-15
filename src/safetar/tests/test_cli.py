"""Tests for the safetar CLI."""

import io
import tarfile
from unittest.mock import patch

import pytest

from safetar.cli._main import main

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


@pytest.fixture()
def simple_archive(tmp_path):
    """A simple valid TAR archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="file1.txt")
        data = b"content1\n"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        info2 = tarfile.TarInfo(name="dir/file2.txt")
        data2 = b"content2\n"
        info2.size = len(data2)
        tf.addfile(info2, io.BytesIO(data2))
    p = tmp_path / "simple.tar"
    p.write_bytes(buf.getvalue())
    return p


class TestExtractCommand:
    """Tests for the extract command."""

    def test_extract_basic(self, simple_archive, tmp_path, capsys):
        """Basic extraction works."""
        dest = tmp_path / "out"
        with patch("sys.argv", ["safetar", "extract", str(simple_archive), str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").read_text() == "content1\n"
        assert (dest / "dir" / "file2.txt").read_text() == "content2\n"
        captured = capsys.readouterr()
        assert "Extracted to" in captured.out

    def test_extract_with_max_file_size(self, simple_archive, tmp_path):
        """Extract with --max-file-size flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safetar",
                "extract",
                str(simple_archive),
                str(dest),
                "--max-file-size",
                "1000",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_with_max_files(self, simple_archive, tmp_path):
        """Extract with --max-files flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safetar",
                "extract",
                str(simple_archive),
                str(dest),
                "--max-files",
                "10",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_with_symlink_policy(self, simple_archive, tmp_path):
        """Extract with --symlink-policy flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safetar",
                "extract",
                str(simple_archive),
                str(dest),
                "--symlink-policy",
                "reject",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_with_recursive_flag(self, simple_archive, tmp_path):
        """Extract with --recursive flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safetar",
                "extract",
                str(simple_archive),
                str(dest),
                "--recursive",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_nonexistent_archive(self, tmp_path, capsys):
        """Extract fails with nonexistent archive."""
        dest = tmp_path / "out"
        with patch("sys.argv", ["safetar", "extract", "/nonexistent.tar", str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err

    def test_extract_creates_destination(self, simple_archive, tmp_path):
        """Extract creates destination directory if it doesn't exist."""
        dest = tmp_path / "nested" / "out"
        with patch("sys.argv", ["safetar", "extract", str(simple_archive), str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert dest.exists()
        assert (dest / "file1.txt").exists()

    def test_extract_tarslip_rejected(self, tmp_path, capsys):
        """Extract rejects path traversal archive."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(name="../../evil.txt")
            data = b"evil content"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        p = tmp_path / "tarslip.tar"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        with patch("sys.argv", ["safetar", "extract", str(p), str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err


class TestListCommand:
    """Tests for the list command."""

    def test_list_basic(self, simple_archive, capsys):
        """List command shows archive members."""
        with patch("sys.argv", ["safetar", "list", str(simple_archive)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "file1.txt" in captured.out
        assert "dir/file2.txt" in captured.out

    def test_list_nonexistent_archive(self, capsys):
        """List fails with nonexistent archive."""
        with patch("sys.argv", ["safetar", "list", "/nonexistent.tar"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err


class TestVersionFlag:
    """Tests for --version flag."""

    def test_version_flag(self, capsys):
        """--version flag displays version."""
        with patch("sys.argv", ["safetar", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "safetar" in captured.out
