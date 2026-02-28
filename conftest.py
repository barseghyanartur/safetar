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
