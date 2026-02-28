"""Archive factory fixtures for safetar tests.

Every fixture generates a real, crafted archive programmatically using
Python's ``tarfile`` module.  No mocks, no stubs.
"""

from __future__ import annotations

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"

import bz2
import gzip
import io
import lzma
import tarfile

import pytest

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _tar_bytes(callback, *, mode: str = "w") -> bytes:
    """Create a TAR archive in memory via *callback(tf)* and return bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        callback(tf)
    return buf.getvalue()


def _write_to_path(tmp_path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _add_regular(tf, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    tf.addfile(info, io.BytesIO(content))


def _add_symlink(tf, name: str, target: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    tf.addfile(info)


def _add_hardlink(tf, name: str, target: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.LNKTYPE
    info.linkname = target
    tf.addfile(info)


def _add_device(tf, name: str, devtype: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = devtype
    info.devmajor = 1
    info.devminor = 3
    tf.addfile(info)


# ---------------------------------------------------------------------------
# path traversal archives
# ---------------------------------------------------------------------------


@pytest.fixture()
def traversal_archive(tmp_path):
    """Archive with a relative path traversal entry ``../../evil.txt``."""

    def build(tf):
        _add_regular(tf, "../../evil.txt", b"pwned")

    return _write_to_path(tmp_path, "traversal.tar", _tar_bytes(build))


@pytest.fixture()
def absolute_path_archive(tmp_path):
    """Archive with an absolute path entry ``/etc/passwd``."""

    def build(tf):
        _add_regular(tf, "/etc/passwd", b"root:x:0:0:")

    return _write_to_path(tmp_path, "absolute.tar", _tar_bytes(build))


@pytest.fixture()
def unicode_traversal_archive(tmp_path):
    """Archive with a Unicode-normalised traversal entry."""
    # Use fullwidth dots and slashes that NFC-normalise to ASCII.
    name = "\uff0e\uff0e/\uff0e\uff0e/evil.txt"

    def build(tf):
        _add_regular(tf, name, b"pwned")

    return _write_to_path(tmp_path, "unicode_traversal.tar", _tar_bytes(build))


@pytest.fixture()
def pax_traversal_archive(tmp_path):
    """Archive with a safe ustar name but malicious PAX path override."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo(name="safe.txt")
        info.size = 5
        info.pax_headers = {"path": "../../etc/cron.d/evil"}
        tf.addfile(info, io.BytesIO(b"pwned"))
    return _write_to_path(tmp_path, "pax_traversal.tar", buf.getvalue())


# ---------------------------------------------------------------------------
# decompression bomb archives
# ---------------------------------------------------------------------------


def _make_bomb_tar(size: int = 10 * 1024 * 1024) -> bytes:
    """Create an uncompressed TAR with a single large zero-filled member."""

    def build(tf):
        _add_regular(tf, "zeros.bin", b"\x00" * size)

    return _tar_bytes(build)


@pytest.fixture()
def bomb_gz_archive(tmp_path):
    """A .tar.gz with a high compression ratio (zeros compress extremely)."""
    tar_data = _make_bomb_tar()
    gz_data = gzip.compress(tar_data, compresslevel=9)
    return _write_to_path(tmp_path, "bomb.tar.gz", gz_data)


@pytest.fixture()
def bomb_bz2_archive(tmp_path):
    """A .tar.bz2 decompression bomb."""
    tar_data = _make_bomb_tar()
    bz2_data = bz2.compress(tar_data, compresslevel=9)
    return _write_to_path(tmp_path, "bomb.tar.bz2", bz2_data)


@pytest.fixture()
def bomb_xz_archive(tmp_path):
    """A .tar.xz decompression bomb."""
    tar_data = _make_bomb_tar()
    xz_data = lzma.compress(tar_data, format=lzma.FORMAT_XZ)
    return _write_to_path(tmp_path, "bomb.tar.xz", xz_data)


# ---------------------------------------------------------------------------
# size limit archives
# ---------------------------------------------------------------------------


@pytest.fixture()
def large_member_archive(tmp_path):
    """Archive with a single 2 MiB member (for testing max_file_size)."""

    def build(tf):
        _add_regular(tf, "big.bin", b"A" * (2 * 1024 * 1024))

    return _write_to_path(tmp_path, "large_member.tar", _tar_bytes(build))


@pytest.fixture()
def many_files_archive(tmp_path):
    """Archive with 101 entries (for testing max_files=100)."""

    def build(tf):
        for i in range(101):
            _add_regular(tf, f"file_{i:04d}.txt", b"x")

    return _write_to_path(tmp_path, "many_files.tar", _tar_bytes(build))


# ---------------------------------------------------------------------------
# symlink archives
# ---------------------------------------------------------------------------


@pytest.fixture()
def symlink_escape_archive(tmp_path):
    """Archive with a symlink pointing outside the extraction root."""

    def build(tf):
        _add_regular(tf, "readme.txt", b"safe content\n")
        _add_symlink(tf, "escape_link", "../../../etc/passwd")

    return _write_to_path(tmp_path, "symlink_escape.tar", _tar_bytes(build))


@pytest.fixture()
def symlink_chain_archive(tmp_path):
    """Archive with a two-hop symlink chain that escapes the root.

    link_a → subdir (internal)
    link_b → ../../etc (escapes via resolved link_a)
    """

    def build(tf):
        info_dir = tarfile.TarInfo(name="subdir/")
        info_dir.type = tarfile.DIRTYPE
        tf.addfile(info_dir)
        _add_regular(tf, "subdir/safe.txt", b"ok")
        _add_symlink(tf, "link_a", "subdir")
        _add_symlink(tf, "link_b", "../../../etc")

    return _write_to_path(tmp_path, "symlink_chain.tar", _tar_bytes(build))


@pytest.fixture()
def symlink_with_regular_archive(tmp_path):
    """Archive with both a symlink and a regular file."""

    def build(tf):
        _add_regular(tf, "readme.txt", b"safe content\n")
        _add_symlink(tf, "link.txt", "../escape.txt")

    return _write_to_path(tmp_path, "symlink_with_regular.tar", _tar_bytes(build))


@pytest.fixture()
def symlink_internal_archive(tmp_path):
    """Archive with a symlink that stays inside the extraction root."""

    def build(tf):
        _add_regular(tf, "target.txt", b"target content\n")
        _add_symlink(tf, "internal_link.txt", "target.txt")

    return _write_to_path(tmp_path, "symlink_internal.tar", _tar_bytes(build))


# ---------------------------------------------------------------------------
# hardlink archives
# ---------------------------------------------------------------------------


@pytest.fixture()
def hardlink_external_archive(tmp_path):
    """Archive with a hardlink pointing outside the extraction root."""

    def build(tf):
        _add_hardlink(tf, "evil_link.txt", "/etc/shadow")

    return _write_to_path(tmp_path, "hardlink_external.tar", _tar_bytes(build))


@pytest.fixture()
def hardlink_internal_archive(tmp_path):
    """Archive with a valid internal hardlink (target first)."""

    def build(tf):
        _add_regular(tf, "original.txt", b"original content\n")
        _add_hardlink(tf, "copy.txt", "original.txt")

    return _write_to_path(tmp_path, "hardlink_internal.tar", _tar_bytes(build))


@pytest.fixture()
def hardlink_forward_ref_archive(tmp_path):
    """Archive where the hardlink appears before its target."""

    def build(tf):
        _add_hardlink(tf, "link_first.txt", "target_later.txt")
        _add_regular(tf, "target_later.txt", b"target content\n")

    return _write_to_path(tmp_path, "hardlink_forward.tar", _tar_bytes(build))


# ---------------------------------------------------------------------------
# forbidden entry type archives
# ---------------------------------------------------------------------------


@pytest.fixture()
def char_device_archive(tmp_path):
    """Archive containing a character device entry."""

    def build(tf):
        _add_device(tf, "dev_null", tarfile.CHRTYPE)

    return _write_to_path(tmp_path, "chrdev.tar", _tar_bytes(build))


@pytest.fixture()
def block_device_archive(tmp_path):
    """Archive containing a block device entry."""

    def build(tf):
        _add_device(tf, "dev_sda", tarfile.BLKTYPE)

    return _write_to_path(tmp_path, "blkdev.tar", _tar_bytes(build))


@pytest.fixture()
def fifo_archive(tmp_path):
    """Archive containing a FIFO entry."""

    def build(tf):
        info = tarfile.TarInfo(name="my_fifo")
        info.type = tarfile.FIFOTYPE
        tf.addfile(info)

    return _write_to_path(tmp_path, "fifo.tar", _tar_bytes(build))


@pytest.fixture()
def unknown_type_archive(tmp_path):
    """Archive containing an entry with an unrecognised type code.

    We build a normal archive and then patch the raw bytes to inject a
    non-standard type code, because ``tarfile`` validates the type during
    serialisation.
    """

    def build(tf):
        info = tarfile.TarInfo(name="mystery")
        info.size = 0
        tf.addfile(info)

    raw = bytearray(_tar_bytes(build))
    # TAR header type field is at offset 156 (single byte).
    raw[156] = ord("9")
    # Recalculate the unsigned header checksum (offsets 148-155).
    # The checksum is computed over the entire 512-byte header block,
    # treating the checksum field itself as eight spaces (0x20).
    header = bytearray(raw[:512])
    header[148:156] = b"        "  # eight spaces
    chksum = sum(header)
    # Write the checksum as a six-digit zero-padded octal, then NUL + space.
    raw[148:156] = b"%-7o\0" % chksum
    return _write_to_path(tmp_path, "unknown_type.tar", bytes(raw))


# ---------------------------------------------------------------------------
# setuid / permission archives
# ---------------------------------------------------------------------------


@pytest.fixture()
def setuid_archive(tmp_path):
    """Archive with a regular file that has setuid bit (04755)."""

    def build(tf):
        info = tarfile.TarInfo(name="suid_binary")
        info.size = 4
        info.mode = 0o4755
        tf.addfile(info, io.BytesIO(b"ELF\x00"))

    return _write_to_path(tmp_path, "setuid.tar", _tar_bytes(build))


@pytest.fixture()
def extreme_timestamp_archive(tmp_path):
    """Archive with extreme mtime values (epoch zero and far future)."""

    def build(tf):
        info_zero = tarfile.TarInfo(name="epoch_zero.txt")
        info_zero.size = 3
        info_zero.mtime = 0
        tf.addfile(info_zero, io.BytesIO(b"old"))

        info_future = tarfile.TarInfo(name="far_future.txt")
        info_future.size = 6
        info_future.mtime = 2**40
        tf.addfile(info_future, io.BytesIO(b"future"))

    return _write_to_path(tmp_path, "extreme_timestamps.tar", _tar_bytes(build))


# ---------------------------------------------------------------------------
# truncated archive
# ---------------------------------------------------------------------------


@pytest.fixture()
def truncated_archive(tmp_path):
    """A .tar.gz archive truncated mid-member."""
    tar_data = _make_bomb_tar(size=100_000)
    gz_data = gzip.compress(tar_data, compresslevel=1)
    # Truncate at roughly half.
    truncated = gz_data[: len(gz_data) // 2]
    return _write_to_path(tmp_path, "truncated.tar.gz", truncated)


# ---------------------------------------------------------------------------
# GNU long-name traversal
# ---------------------------------------------------------------------------


@pytest.fixture()
def gnu_longname_traversal_archive(tmp_path):
    """Archive using GNU LONGNAME whose reassembled name contains ``../``."""
    # Build using GNU format which handles long names via L/K entries.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        long_name = "a" * 150 + "/../../etc/passwd"
        info = tarfile.TarInfo(name=long_name)
        info.size = 5
        tf.addfile(info, io.BytesIO(b"pwned"))
    return _write_to_path(tmp_path, "gnu_longname.tar", buf.getvalue())


# ---------------------------------------------------------------------------
# legitimate archives
# ---------------------------------------------------------------------------


@pytest.fixture()
def legitimate_archive(tmp_path):
    """A perfectly safe multi-file archive."""

    def build(tf):
        _add_regular(tf, "readme.txt", b"Hello, world!\n")
        info_dir = tarfile.TarInfo(name="data/")
        info_dir.type = tarfile.DIRTYPE
        info_dir.mode = 0o755
        tf.addfile(info_dir)
        _add_regular(tf, "data/report.csv", b"a,b,c\n1,2,3\n")
        _add_regular(tf, "data/notes.txt", b"Some notes.\n")

    return _write_to_path(tmp_path, "legitimate.tar", _tar_bytes(build))


@pytest.fixture()
def legitimate_gz_archive(tmp_path):
    """A safe .tar.gz archive."""

    def build(tf):
        _add_regular(tf, "hello.txt", b"Hello from gzip!\n")

    tar_data = _tar_bytes(build)
    gz_data = gzip.compress(tar_data)
    return _write_to_path(tmp_path, "legitimate.tar.gz", gz_data)
