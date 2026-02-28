=======
safetar
=======
.. image:: https://raw.githubusercontent.com/barseghyanartur/safetar/main/docs/_static/safetar_logo.webp
   :alt: SafeTar Logo
   :align: center

Hardened TAR extraction for Python - secure by default.

.. image:: https://img.shields.io/pypi/v/safetar.svg
   :target: https://pypi.python.org/pypi/safetar
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/pyversions/safetar.svg
   :target: https://pypi.python.org/pypi/safetar/
   :alt: Supported Python versions

.. image:: https://github.com/barseghyanartur/safetar/actions/workflows/test.yml/badge.svg?branch=main
   :target: https://github.com/barseghyanartur/safetar/actions
   :alt: Build Status

.. image:: https://readthedocs.org/projects/safetar/badge/?version=latest
    :target: http://safetar.readthedocs.io
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/docs-llms.txt-blue
    :target: https://safetar.readthedocs.io/en/latest/llms.txt
    :alt: llms.txt - documentation for LLMs

.. image:: https://img.shields.io/badge/license-MIT-blue.svg
   :target: https://github.com/barseghyanartur/safetar/#License
   :alt: MIT

.. image:: https://coveralls.io/repos/github/barseghyanartur/safetar/badge.svg?branch=main&service=github
    :target: https://coveralls.io/github/barseghyanartur/safetar?branch=main
    :alt: Coverage

``safetar`` is a zero-dependency, production-grade wrapper around Python's
``tarfile`` module that defends against the most common TAR-based attacks:
TarSlip path traversal, decompression bombs, symlink/hardlink attacks,
device file injection, and crafted archives.

Features
========

- **TarSlip protection** - relative traversal, absolute paths, Unicode
  NFC normalisation attacks, PAX path overrides, GNU long-name reassembly,
  and null bytes in filenames are all blocked.
- **Decompression bomb protection** - archive-level compression ratio
  monitoring across GZ, BZ2, and XZ streams aborts extraction before
  runaway decompression can exhaust disk or memory.
- **File size limits** - per-member and total extraction size limits enforced
  at stream time (not based on untrusted header values).
- **Symlink policy** - configurable: ``REJECT`` (default), ``IGNORE``, or
  ``RESOLVE_INTERNAL`` (full chain verification with TOCTOU defence via
  deferred batch creation).
- **Hardlink policy** - configurable: ``REJECT`` (default) or ``INTERNAL``
  (target must exist on disk; forward references rejected).
- **Forbidden entry types** - character devices, block devices, FIFOs, and
  unknown type codes are always rejected.
- **setuid/setgid/sticky bit stripping** - dangerous permission bits are
  removed by default.
- **UID/GID ownership clamping** - archived ownership is clamped to the
  current user by default.
- **Timestamp sanitisation** - mtime values are clamped to ``[0, 2**32 - 1]``.
- **Sparse file policy** - ``REJECT`` (default) or ``MATERIALISE`` (extract
  as dense).
- **Atomic writes** - every member is written to a temporary file first;
  the destination is only created after all checks pass.  No partial files
  are left on disk after a security abort.
- **Secure by default** - all limits are active without any configuration.
- **Zero dependencies** - standard library only.
- **Python 3.12 data_filter** - applied as an additional defensive layer
  when available.

Prerequisites
=============

Python 3.10 or later.  No additional packages required.

Installation
============
With ``uv``:

.. code-block:: sh

    uv pip install safetar

Or with ``pip``:

.. code-block:: sh

    pip install safetar

Quick start
===========

Drop-in replacement for the common ``tarfile`` extraction pattern:

.. pytestfixture: file_tar_gz
.. code-block:: python
    :name: test_safe_extract

    from safetar import safe_extract

    safe_extract("path/to/upload.tar.gz", "/var/files/extracted/")

Or use the ``SafeTarFile`` context manager for more control:

.. pytestfixture: file_tar_gz
.. code-block:: python
    :name: test_safe_tarfile

    from safetar import SafeTarFile

    with SafeTarFile("path/to/upload.tar.gz") as stf:
        print(stf.getnames())
        stf.extractall("/var/files/extracted/")

Custom limits
=============

.. pytestfixture: file_tar_gz
.. code-block:: python
    :name: test_custom_limits

    from safetar import SafeTarFile, SymlinkPolicy, HardlinkPolicy

    with SafeTarFile(
        "path/to/upload.tar.gz",
        max_file_size=100 * 1024 * 1024,   # 100 MiB per member
        max_total_size=500 * 1024 * 1024,   # 500 MiB total
        max_files=1_000,
        max_ratio=50.0,
        symlink_policy=SymlinkPolicy.RESOLVE_INTERNAL,
        hardlink_policy=HardlinkPolicy.INTERNAL,
    ) as stf:
        stf.extractall("/var/files/extracted/")

Security event monitoring
=========================

.. pytestfixture: file_tar_gz
.. code-block:: python
    :name: test_security_event_monitoring

    from safetar import SafeTarFile, SecurityEvent

    def my_monitor(event: SecurityEvent) -> None:
        print(f"[safetar] {event.event_type} archive={event.archive_hash}")

    with SafeTarFile(
        "path/to/upload.tar.gz", on_security_event=my_monitor
    ) as stf:
        stf.extractall("/var/files/extracted/")

Default limits
==============

+--------------------------+------------------+
| Parameter                | Default          |
+==========================+==================+
| ``max_file_size``        | 1 GiB            |
+--------------------------+------------------+
| ``max_total_size``       | 5 GiB            |
+--------------------------+------------------+
| ``max_files``            | 10 000           |
+--------------------------+------------------+
| ``max_ratio``            | 200              |
+--------------------------+------------------+
| ``max_nesting_depth``    | 3                |
+--------------------------+------------------+
| ``symlink_policy``       | REJECT           |
+--------------------------+------------------+
| ``hardlink_policy``      | REJECT           |
+--------------------------+------------------+
| ``sparse_policy``        | REJECT           |
+--------------------------+------------------+
| ``strip_special_bits``   | True             |
+--------------------------+------------------+
| ``preserve_ownership``   | False            |
+--------------------------+------------------+
| ``clamp_timestamps``     | True             |
+--------------------------+------------------+

Environment variable configuration
===================================

Every default can be overridden at process start via environment variables,
without modifying call sites.  Explicit constructor arguments always take
precedence over environment variables.

+---------------------------------------+---------------------------+
| Environment variable                  | Parameter                 |
+=======================================+===========================+
| ``SAFETAR_MAX_FILE_SIZE``             | ``max_file_size``         |
+---------------------------------------+---------------------------+
| ``SAFETAR_MAX_TOTAL_SIZE``            | ``max_total_size``        |
+---------------------------------------+---------------------------+
| ``SAFETAR_MAX_FILES``                 | ``max_files``             |
+---------------------------------------+---------------------------+
| ``SAFETAR_MAX_RATIO``                 | ``max_ratio``             |
+---------------------------------------+---------------------------+
| ``SAFETAR_MAX_NESTING_DEPTH``         | ``max_nesting_depth``     |
+---------------------------------------+---------------------------+
| ``SAFETAR_SYMLINK_POLICY``            | ``symlink_policy``        |
+---------------------------------------+---------------------------+
| ``SAFETAR_HARDLINK_POLICY``           | ``hardlink_policy``       |
+---------------------------------------+---------------------------+
| ``SAFETAR_SPARSE_POLICY``             | ``sparse_policy``         |
+---------------------------------------+---------------------------+
| ``SAFETAR_STRIP_SPECIAL_BITS``        | ``strip_special_bits``    |
+---------------------------------------+---------------------------+
| ``SAFETAR_PRESERVE_OWNERSHIP``        | ``preserve_ownership``    |
+---------------------------------------+---------------------------+
| ``SAFETAR_CLAMP_TIMESTAMPS``          | ``clamp_timestamps``      |
+---------------------------------------+---------------------------+

Integer and float variables accept standard numeric strings.  Boolean
variables accept ``1`` / ``true`` / ``yes`` / ``on`` (truthy) or
``0`` / ``false`` / ``no`` / ``off`` (falsy), case-insensitively.
Policy variables accept the lower-case enum value names (e.g.
``SAFETAR_SYMLINK_POLICY=resolve_internal``).  Unrecognised or unparseable
values are silently ignored and the built-in default is used instead.

Testing
=======

All tests run inside Docker to prevent accidental pollution of the host system:

.. code-block:: sh

    make test

To test a specific Python version:

.. code-block:: sh

    make test-env ENV=py312

Writing documentation
=====================

Keep the following hierarchy:

.. code-block:: text

    =====
    title
    =====

    header
    ======

    sub-header
    ----------

    sub-sub-header
    ~~~~~~~~~~~~~~

    sub-sub-sub-header
    ^^^^^^^^^^^^^^^^^^

    sub-sub-sub-sub-header
    ++++++++++++++++++++++

    sub-sub-sub-sub-sub-header
    **************************

License
=======

MIT

Support
=======
For security issues contact me at the e-mail given in the `Author`_ section.

For overall issues, go
to `GitHub <https://github.com/barseghyanartur/safetar/issues>`_.

Author
======

Artur Barseghyan <artur.barseghyan@gmail.com>
