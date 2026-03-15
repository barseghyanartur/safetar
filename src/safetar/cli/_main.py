"""safetar CLI — hardened TAR extraction from the command line."""

import argparse
import sys
import tarfile
from pathlib import Path

from safetar import (
    HardlinkPolicy,
    SafeTarFile,
    SparsePolicy,
    SymlinkPolicy,
    safe_extract,
)
from safetar._exceptions import SafetarError

__all__ = ("main",)

_SYMLINK_POLICIES = {
    "reject": SymlinkPolicy.REJECT,
    "ignore": SymlinkPolicy.IGNORE,
    "resolve_internal": SymlinkPolicy.RESOLVE_INTERNAL,
}

_HARDLINK_POLICIES = {
    "reject": HardlinkPolicy.REJECT,
    "internal": HardlinkPolicy.INTERNAL,
}

_SPARSE_POLICIES = {
    "reject": SparsePolicy.REJECT,
    "materialise": SparsePolicy.MATERIALISE,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safetar",
        description="Hardened TAR extraction — safe by default.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_version()}",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    ext = sub.add_parser("extract", help="Extract a TAR archive safely.")
    ext.add_argument("archive", help="Path to the TAR file.")
    ext.add_argument("destination", help="Directory to extract into.")
    ext.add_argument(
        "--max-file-size",
        type=int,
        metavar="BYTES",
        help="Max uncompressed size per member (default: 1 GiB).",
    )
    ext.add_argument(
        "--max-total-size",
        type=int,
        metavar="BYTES",
        help="Max total uncompressed size (default: 5 GiB).",
    )
    ext.add_argument(
        "--max-files",
        type=int,
        metavar="N",
        help="Max number of members (default: 10 000).",
    )
    ext.add_argument(
        "--max-ratio",
        type=float,
        metavar="RATIO",
        help="Max compression ratio (default: 200).",
    )
    ext.add_argument(
        "--max-nesting-depth",
        type=int,
        metavar="N",
        help="Max nested-archive depth (default: 3).",
    )
    ext.add_argument(
        "--symlink-policy",
        choices=list(_SYMLINK_POLICIES),
        default=None,
        metavar="POLICY",
        help="How to handle symlink entries: reject (default), ignore, "
        "resolve_internal.",
    )
    ext.add_argument(
        "--hardlink-policy",
        choices=list(_HARDLINK_POLICIES),
        default=None,
        metavar="POLICY",
        help="How to handle hardlink entries: reject (default), internal.",
    )
    ext.add_argument(
        "--sparse-policy",
        choices=list(_SPARSE_POLICIES),
        default=None,
        metavar="POLICY",
        help="How to handle sparse entries: reject (default), materialise.",
    )
    ext.add_argument(
        "--no-strip-special-bits",
        action="store_true",
        help="Preserve setuid/setgid/sticky bits on extracted files.",
    )
    ext.add_argument(
        "--no-strip-write-bits",
        action="store_true",
        help="Preserve write bits (owner/group/other) on extracted files.",
    )
    ext.add_argument(
        "--preserve-ownership",
        action="store_true",
        help="Preserve archived UID/GID (requires root).",
    )
    ext.add_argument(
        "--no-clamp-timestamps",
        action="store_true",
        help="Do not clamp mtime to [0, 2**32-1].",
    )
    ext.add_argument(
        "--recursive",
        action="store_true",
        default=False,
        help="Enable recursive extraction of nested tar archives.",
    )

    lst = sub.add_parser("list", help="List members of a TAR archive.")
    lst.add_argument("archive", help="Path to the TAR file.")

    return parser


def _version() -> str:
    try:
        from safetar import __version__

        return __version__
    except ImportError:
        return "unknown"


def _cmd_extract(args: argparse.Namespace) -> int:
    kwargs: dict = {}

    for attr in (
        "max_file_size",
        "max_total_size",
        "max_files",
        "max_ratio",
        "max_nesting_depth",
        "recursive",
    ):
        val = getattr(args, attr, None)
        if val is not None:
            kwargs[attr] = val

    if args.symlink_policy is not None:
        kwargs["symlink_policy"] = _SYMLINK_POLICIES[args.symlink_policy]

    if args.hardlink_policy is not None:
        kwargs["hardlink_policy"] = _HARDLINK_POLICIES[args.hardlink_policy]

    if args.sparse_policy is not None:
        kwargs["sparse_policy"] = _SPARSE_POLICIES[args.sparse_policy]

    if args.no_strip_special_bits:
        kwargs["strip_special_bits"] = False

    if args.no_strip_write_bits:
        kwargs["strip_write_bits"] = False

    if args.preserve_ownership:
        kwargs["preserve_ownership"] = True

    if args.no_clamp_timestamps:
        kwargs["clamp_timestamps"] = False

    dest = Path(args.destination)
    dest.mkdir(parents=True, exist_ok=True)

    try:
        safe_extract(args.archive, dest, **kwargs)
    except SafetarError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except tarfile.TarError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Extracted to {dest.resolve()}")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        with SafeTarFile(args.archive) as tf:
            for name in tf.getnames():
                print(name)
    except SafetarError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except tarfile.TarError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "extract":
        sys.exit(_cmd_extract(args))
    elif args.command == "list":
        sys.exit(_cmd_list(args))
    else:  # pragma: no cover
        parser.print_help()
        sys.exit(1)
