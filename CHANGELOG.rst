Release history and notes
=========================
.. Internal references

.. _Armenian genocide: https://en.wikipedia.org/wiki/Armenian_genocide

`Sequence based identifiers
<http://en.wikipedia.org/wiki/Software_versioning#Sequence-based_identifiers>`_
are used for versioning (schema follows below):

.. code-block:: text

    major.minor[.revision]

- It is always safe to upgrade within the same minor version (for example,
  from 0.3 to 0.3.4).
- Minor version changes might be backwards incompatible. Read the
  release notes carefully before upgrading (for example, when upgrading from
  0.3.4 to 0.4).
- All backwards incompatible changes are mentioned in this document.

0.1.1
-----
2026-03-15

- **Recursive extraction**:
  `SafeTarFile(..., recursive=True, max_nesting_depth=3)` (and `safe_extract`)
  auto-descends into nested `.tar*` files, extracting them into subdirectories.
  All safety limits apply at every level.
- **CLI**: New `safetar` command (`extract` + `list` subcommands) with full
  support for all security limits, passwords, symlink policies, and
  recursive mode.
- **Nesting protection**: `max_nesting_depth` guard + `NestingDepthError`
  prevents deep tar-bomb recursion.
- **Docs & tests**: Updated README.rst/AGENTS.md with examples,
  complete CLI + recursive integration test suites.
- **Misc**: Simplified `Makefile`, `.gitignore` cleanup.

0.1
-----
2026-02-28

- Initial beta release.
