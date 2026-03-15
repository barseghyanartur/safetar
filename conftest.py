"""
Pytest fixtures for documentation testing.

DO NOT ADD OTHER FIXTURES HERE.
"""

import gzip
import io
import tarfile
from pathlib import Path

import pytest


@pytest.fixture()
def file_tar_gz(tmp_path):
    """A valid .tar.gz file named upload.tar.gz."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="hello.txt")
        data = b"Hello, world!\n"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    tar_data = buf.getvalue()
    gz_data = gzip.compress(tar_data)
    p = Path("path/to") / "upload.tar.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(gz_data)
    return p


@pytest.fixture()
def nested_tar_archive(tmp_path):
    """A tar archive containing a nested tar archive."""
    inner_buf = io.BytesIO()
    with tarfile.open(fileobj=inner_buf, mode="w") as inner_tf:
        info = tarfile.TarInfo(name="inner_file.txt")
        data = b"Content from inner tar\n"
        info.size = len(data)
        inner_tf.addfile(info, io.BytesIO(data))
    inner_data = inner_buf.getvalue()

    outer_buf = io.BytesIO()
    with tarfile.open(fileobj=outer_buf, mode="w") as outer_tf:
        info = tarfile.TarInfo(name="inner.tar")
        info.size = len(inner_data)
        outer_tf.addfile(info, io.BytesIO(inner_data))
        info2 = tarfile.TarInfo(name="outer_file.txt")
        data2 = b"Content from outer tar\n"
        info2.size = len(data2)
        outer_tf.addfile(info2, io.BytesIO(data2))

    p = Path("path/to") / "archive.tar.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(outer_buf.getvalue())
    return p
