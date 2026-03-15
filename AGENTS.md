# AGENTS.md — safetar

**Package version**: See pyproject.toml
**Repository**: https://github.com/barseghyanartur/safetar
**Maintainer**: Artur Barseghyan <artur.barseghyan@gmail.com>

This file is for AI agents and developers using AI assistants to work on or with
safetar. It covers two distinct roles: **using** the package in application code,
and **developing/extending** the package itself.

---

## 1. Project Mission (Never Deviate)

> Hardened TAR extraction for Python — secure by default, zero dependencies,
> production-grade.

- Secure defaults are never relaxed without an explicit caller decision.
- No external dependencies. Ever.
- The three-phase security model (Guard → Sandbox → Streamer) is preserved.
- No partial files on disk after a security abort.
- Recursive extraction (when enabled) applies all protections to nested archives.

---

## 2. Using safetar in Application Code

### Simple case

<!-- pytestfixture: file_tar_gz -->
```python name=test_simple_case
from safetar import safe_extract

# Secure defaults protect against all common attacks
safe_extract("path/to/upload.tar.gz", "/var/files/extracted/")
```

### With monitoring and custom limits

<!-- pytestfixture: file_tar_gz -->
```python name=test_with_monitoring_and_custom_limits
from safetar import SafeTarFile, SecurityEvent

def monitor(event: SecurityEvent) -> None:
    print(f"Security event: {event.event_type}")

with SafeTarFile(
    "path/to/upload.tar.gz",
    max_file_size=100 * 1024 * 1024,  # 100 MiB per member
    on_security_event=monitor,
) as stf:
    stf.extractall("/var/files/extracted/")
```

### With recursive extraction

<!-- pytestfixture: nested_tar_archive -->
```python name=test_recursive
from safetar import safe_extract

# Recursively extract nested tar archives
safe_extract("path/to/archive.tar.gz", "/var/files/extracted/", recursive=True)
```

### Exception handling

All safetar exceptions inherit from `SafetarError`:

<!-- pytestfixture: file_tar_gz -->
```python name=test_exception_handling
from safetar import (
    safe_extract,
    SafetarError,
    UnsafeEntryError,         # path traversal or disallowed symlink/hardlink
    CompressionRatioError,    # decompression bomb attempt
    FileSizeExceededError,    # member too large
    TotalSizeExceededError,   # cumulative size exceeded
    FileCountExceededError,   # too many entries
    MalformedArchiveError,    # structurally invalid archive
    NestingDepthError,        # nested archive depth exceeded
)

try:
    safe_extract("path/to/upload.tar.gz", "/var/files/extracted/")
except UnsafeEntryError:
    ...
except CompressionRatioError:
    ...
except SafetarError:
    # catch-all for any safetar violation
    ...
```

### Secure defaults reference

<!-- pytestfixture: file_tar_gz -->
```python name=test_secure_defaults_reference
from safetar import SafeTarFile, SymlinkPolicy, HardlinkPolicy, SparsePolicy

SafeTarFile(
    "path/to/upload.tar.gz",
    max_file_size=1 * 1024**3,       # 1 GiB per member
    max_total_size=5 * 1024**3,      # 5 GiB total
    max_files=10_000,
    max_ratio=200.0,                 # archive-level decompression ratio
    max_nesting_depth=3,             # max recursion depth for nested archives
    recursive=False,                 # extract nested tar archives automatically
    symlink_policy=SymlinkPolicy.REJECT,
    hardlink_policy=HardlinkPolicy.REJECT,
    sparse_policy=SparsePolicy.REJECT,
)
```

All limits are overridable via environment variables:

| Variable | Type | Default |
|---|---|---|
| `SAFETAR_MAX_FILE_SIZE` | int (bytes) | 1 GiB |
| `SAFETAR_MAX_TOTAL_SIZE` | int (bytes) | 5 GiB |
| `SAFETAR_MAX_FILES` | int | 10 000 |
| `SAFETAR_MAX_RATIO` | float | 200.0 |
| `SAFETAR_MAX_NESTING_DEPTH` | int | 3 |
| `SAFETAR_RECURSIVE` | bool | False |
| `SAFETAR_SYMLINK_POLICY` | str | reject |
| `SAFETAR_HARDLINK_POLICY` | str | reject |
| `SAFETAR_SPARSE_POLICY` | str | reject |
| `SAFETAR_STRIP_SPECIAL_BITS` | bool | True |
| `SAFETAR_PRESERVE_OWNERSHIP` | bool | False |
| `SAFETAR_CLAMP_TIMESTAMPS` | bool | True |

Resolution order: constructor argument > environment variable > hardcoded default.
Invalid env values are logged and silently ignored.

### What safetar does not do

- **Write mode** — `SafeTarFile` is read-only. It does not expose `open()`,
  `read()`, or any write-mode methods from `tarfile.TarFile`.
- **Create OS symlinks** — `RESOLVE_INTERNAL` extracts symlink entries as
  regular files containing the target path as bytes. See section 5.

---

## 3. Architecture

Each extraction passes through three phases in order. Each phase owns exactly
one module. When adding a new check, identify the correct phase first.

| Phase | File | Runs | Raises |
|---|---|---|---|
| **Guard** | `_guard.py` | On `SafeTarFile.__init__()`, before any decompression | `FileCountExceededError`, `MalformedArchiveError` |
| **Sandbox** | `_sandbox.py` | Per member, before streaming begins | `UnsafeEntryError`, `UnsafeEntryTypeError` |
| **Streamer** | `_streamer.py` | Per member, during decompression | `FileSizeExceededError`, `TotalSizeExceededError`, `CompressionRatioError` |

**Guard** owns: file count limit, entry type validation, filename validation,
PAX path validation, seekable input handling.

**Sandbox** owns: path traversal detection, absolute/UNC path rejection, Unicode
NFC normalisation, null-byte rejection, path length limit, symlink/hardlink
policy enforcement (REJECT / IGNORE / RESOLVE_INTERNAL / INTERNAL).

**Streamer** owns: per-member decompressed size, cumulative total size,
compression ratio monitoring, atomic write contract (temp file → rename
on success, unlink on failure).

**Orchestration** (`_core.py`) — `SafeTarFile` and `safe_extract`. `_extract_one`
calls the three phases in order per member. Environment variable resolution,
security event emission, symlink policy dispatch, and recursive extraction
live here.

### Key files

| File | Purpose |
|---|---|
| `src/safetar/_core.py` | Public API, orchestration, env overrides, event emission, recursive extraction |
| `src/safetar/_guard.py` | Phase A: static pre-checks |
| `src/safetar/_sandbox.py` | Phase B: path resolution, symlink/hardlink/sparse policies |
| `src/safetar/_streamer.py` | Phase C: streaming extraction, atomic writes |
| `src/safetar/_exceptions.py` | Exception hierarchy (all inherit `SafetarError`) |
| `src/safetar/_events.py` | `SecurityEvent`, `SymlinkPolicy`, `HardlinkPolicy`, `SparsePolicy` |
| `src/safetar/tests/conftest.py` | All test archive fixtures |
| `pyproject.toml` | Build, ruff, mypy, pytest-cov configuration |
| `README.rst` | End-user documentation; keep in sync with code |

---

## 4. Security Principles

**1. Default limits are sacred.**
Never lower them in examples or generated code. If a user asks you to relax a
limit, warn about the tradeoff explicitly before complying.

**2. Atomicity is non-negotiable.**
Every member must follow: temp file → all checks pass → `replace()` to
destination. On any exception: `unlink(missing_ok=True)` the temp file. The
destination must never be created or modified if a check fails. No partial
files may remain on disk.

**3. Never merge phase responsibilities.**
Path checks belong in `_sandbox.py`. Static header checks in `_guard.py`.
Runtime byte checks in `_streamer.py`. Do not add path logic to the streamer
or size logic to the guard.

**4. Zero external dependencies.**
stdlib only. If you are considering adding an import that is not in the Python
standard library, the answer is no.

**5. Security events must not be suppressible.**
Exceptions raised inside `on_security_event` callbacks are caught and logged,
but the original security exception always propagates. Never let a broken
callback silently swallow a violation.

**6. Recursive extraction preserves all protections.**
When `recursive=True`, nested tar archives are extracted with the same
security protections as the outer archive: size limits, nesting depth limits,
symlink/hardlink/sparse policies, and all sanitisation apply recursively.

---

## 5. Known Intentional Behaviors — Do Not Treat as Bugs

### RESOLVE_INTERNAL extracts symlink entries as regular files

TAR entries flagged as symlinks (via type `SYMTYPE`) are written as regular
files containing the link target path as bytes. Python's `tarfile` does not
create OS symlinks during extraction. The `verify_symlink_chain` function
in `_sandbox.py` is only used for post-extraction symlink verification.

This is **safe**: a regular file containing the text `"../escape.txt"` is
harmless.

### compress_size == 0 skips the ratio check — this is correct

The ratio check in `_streamer.py` is gated on `compress_size > 0`. This is not
a vulnerability for TAR archives. The ratio is archive-level (not per-member)
because TAR compression is applied to the whole stream, not individual members.

A crafted archive with unusual properties is rejected by Python's `tarfile`
module. **Do not attempt to "fix" this skip.**

### Nested archives are extracted alongside regular files

When `recursive=False` (default), nested tar archives are extracted as regular
binary files. When `recursive=True`, they are automatically detected (using
content-based `tarfile.is_tarfile()` detection) and recursively extracted.

The `_nesting_depth` parameter and `NestingDepthError` guard against runaway
recursion.

---

## 6. Agent Workflow: Adding Features or Fixing Bugs

When asked to add a feature or fix a bug, follow these steps in order:

1. **Check the mission** — Does the change preserve zero deps, secure defaults,
   and the three-phase model?
2. **Identify the correct phase** — Guard (static/header), Sandbox (path/policy),
   or Streamer (runtime/bytes).
3. **For bug fixes: write the regression fixture first** — Add a programmatic
   archive fixture to `src/safetar/tests/conftest.py` that reproduces the bug.
   The test must fail before your fix.
4. **Implement the change** in the correct phase file.
5. **Add/update exceptions** in `_exceptions.py` if a new error type is needed
   (inherit from `SafetarError`).
6. **Add event emission** in `_core.py` (`self._fire_event(...)`) if
   the check fires inside `_extract_one`.
7. **Export** new public symbols from `__init__.py` and `__all__`.
8. **Write tests:**
   - Unit test in `test_[phase].py` (e.g., `test_streamer.py`).
   - Integration test in `test_integration.py` verifying no partial files remain.
   - Legitimate-input test confirming the happy path still works.
9. **Update `README.rst`** if the API or default limits table changed.
10. **Run tests in Docker:** `make test` or `make test-env ENV=py312`.

### Acceptable new features

- Windows reserved filename detection (Phase B / Sandbox).
- Additional event types for new violation categories.
- Real OS symlink creation under `RESOLVE_INTERNAL` (see section 5).
- Support for additional compression formats (via tarfile).

### Forbidden

- Adding any external dependency.
- Lowering default limits.
- Bypassing or merging phases.
- Writing directly to the destination path (must use temp file).
- Exposing write-mode or `open()`/`read()` methods on `SafeTarFile`.

---

## 7. Testing Rules

### All tests must run inside Docker

```sh
make test                   # full matrix (Python 3.10–3.14)
make test-env ENV=py312     # single version
make shell                  # interactive shell
```

Do not run `pytest` directly on the host machine. Malicious test archives must
not touch the host filesystem.

### Test layout

```
src/safetar/tests/
    conftest.py          — all archive fixtures (add new ones here)
    test_guard.py        — Phase A tests
    test_sandbox.py      — Phase B tests
    test_streamer.py     — Phase C tests
    test_integration.py  — end-to-end tests
```

The **root `conftest.py`** (project root) is for `pytest-codeblock` documentation
testing only. Do not add security fixtures there.

### Fixture rules

- Craft all test archives programmatically using `tarfile`. Do not
  commit pre-built `.tar` files.
- Use `tmp_path` for all output. Never write to a fixed path.

### Required assertions for every security abort test

```python
# 1. pytest.raises wraps the full operation, not just extractall
with pytest.raises(SpecificError):
    with SafeTarFile(...) as stf:
        stf.extractall(dest)

# 2. Atomicity: no partial files remain
remaining = [f for f in dest.rglob("*") if not f.is_dir()]
assert not remaining
```

### Checklist for every new security check

- [ ] Fixture in `conftest.py` that triggers the violation
- [ ] Test asserting the correct exception is raised
- [ ] Test asserting no partial files remain after abort
- [ ] Test asserting a legitimate archive still extracts correctly
- [ ] Integration test in `test_integration.py`
- [ ] Event emission tested if applicable

---

## 8. Coding Conventions

### Formatting

- Line length: **88 characters** (ruff).
- Import sorting: `isort`; `safetar` is `known-first-party`.
- Target: `py310`. Run `make ruff` to check. `ruff fix` auto-fixes on
  commit — do not fight the formatter.

### Ruff rules in effect

`B`, `C4`, `E`, `F`, `G`, `I`, `ISC`, `INP`, `N`, `PERF`, `Q`, `SIM`.

Explicitly ignored:

| Rule | Reason |
|---|---|
| `G004` | f-strings in logging calls are allowed |
| `ISC003` | implicit string concatenation across lines is allowed |
| `PERF203` | `try/except` in loops allowed in `conftest.py` only |

### Style

- Every non-test module must have `__all__`, `__author__`, `__copyright__`,
  `__license__` at module level.
- Logger: always `logging.getLogger("safetar.security")`. Never use `__name__`.
- Log member names truncated to 256 characters in `extra` dicts (privacy).
- Always chain exceptions: `raise X(...) from exc`.
- Type annotations on all public functions. Use `Optional[X]` (not `X | None`)
  to match the existing codebase.
- `SecurityEvent` must never include member names, paths, or filesystem
  information — `event_type`, `archive_hash`, and `timestamp` only.

### Pull requests

Target the `dev` branch only. Never open a PR directly to `main`.

---

## 9. Prompt Templates

**Explaining usage to a user:**
> You are an expert in secure Python file handling. Explain how to use safetar
> for [task]. Start with secure defaults. Include exception handling. Note that
> symlink entries are extracted as regular files, not OS symlinks.

**Implementing a new feature:**
> Extend safetar with [feature]. Follow the AGENTS.md agent workflow (section 6):
> identify the correct phase, implement, add tests verifying atomicity and events,
> update README. Preserve zero external dependencies and secure defaults.

**Fixing a bug:**
> Reproduce [bug] with a new programmatic fixture in conftest.py. The test must
> fail before the fix. Then fix in the correct phase file. Add tests asserting
> the correct exception, no partial files on disk, and that legitimate archives
> still extract successfully.

**Reviewing a change:**
> Review this safetar change against AGENTS.md: Does it preserve zero deps?
> Does it maintain the three-phase model? Does it follow the atomic write
> contract? Are all new checks tested with both violation and legitimate inputs?
