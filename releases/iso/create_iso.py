#!/usr/bin/env python3
"""Wrapper script for building KDE ISO artifacts into the releases directory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ISO_NAME = "freedomlinux-kde.iso"
DEFAULT_ARCH = "amd64"
DEFAULT_RELEASE = "bookworm"
DEFAULT_SIZE_GB = 16
DEFAULT_HOSTNAME = "freedomlinux"
DEFAULT_USERNAME = "builder"

# Ensure the tools directory is on sys.path so we can import the builder module.
sys.path.insert(0, str(REPO_ROOT / "tools"))

from bootloader import build_kde_image  # type: ignore  # noqa: E402


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a KDE-enabled disk image and matching ISO artifact in the "
            "releases/iso directory by invoking the main builder script."
        )
    )
    parser.add_argument(
        "--arch",
        default=DEFAULT_ARCH,
        help="Target architecture to bootstrap (passed to debootstrap).",
    )
    parser.add_argument(
        "--release",
        default=DEFAULT_RELEASE,
        help="Debian release to bootstrap inside the image.",
    )
    parser.add_argument(
        "--size-gb",
        type=int,
        default=DEFAULT_SIZE_GB,
        help="Size of the generated disk image in gigabytes.",
    )
    parser.add_argument(
        "--hostname",
        default=DEFAULT_HOSTNAME,
        help="Hostname configured inside the generated system.",
    )
    parser.add_argument(
        "--user",
        default=DEFAULT_USERNAME,
        help="Non-root user created inside the generated system.",
    )
    parser.add_argument(
        "--iso-name",
        default=DEFAULT_ISO_NAME,
        help="Filename for the ISO image stored in releases/iso.",
    )
    parser.add_argument(
        "--iso-dir",
        type=Path,
        default=REPO_ROOT / "releases" / "iso",
        help="Directory where ISO release artifacts should be written.",
    )
    parser.add_argument(
        "--keep-qcow2",
        action="store_true",
        help="Preserve the intermediate QCOW2 disk image generated during the build.",
    )
    return parser.parse_args(argv)


def build_iso(args: argparse.Namespace) -> int:
    iso_dir = args.iso_dir.resolve()
    iso_dir.mkdir(parents=True, exist_ok=True)
    iso_name = Path(args.iso_name).name
    if not iso_name.endswith(".iso"):
        iso_name = f"{Path(iso_name).stem}.iso"

    qcow2_name = f"{Path(iso_name).stem}.qcow2"
    qcow2_path = iso_dir / qcow2_name

    build_args = [
        "--arch",
        args.arch,
        "--release",
        args.release,
        "--size-gb",
        str(args.size_gb),
        "--hostname",
        args.hostname,
        "--user",
        args.user,
        "--iso-dir",
        str(iso_dir),
        "--iso-name",
        iso_name,
        str(qcow2_path),
    ]

    result = build_kde_image.main(build_args)
    if result != 0:
        return result

    if not args.keep_qcow2:
        qcow2_path.unlink(missing_ok=True)

    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    return build_iso(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
