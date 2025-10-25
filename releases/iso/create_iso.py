#!/usr/bin/env python3
"""Wrapper script for building KDE ISO artifacts into the releases directory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE_NAME = "freedomlinux-kde.qcow2"
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
        "--image-name",
        default=DEFAULT_IMAGE_NAME,
        help="Filename for the QCOW2 disk image stored in releases/iso.",
    )
    parser.add_argument(
        "--iso-dir",
        type=Path,
        default=REPO_ROOT / "releases" / "iso",
        help="Directory where ISO release artifacts should be written.",
    )
    return parser.parse_args(argv)


def build_iso(args: argparse.Namespace) -> int:
    iso_dir = args.iso_dir.resolve()
    iso_dir.mkdir(parents=True, exist_ok=True)
    output_path = iso_dir / args.image_name

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
        str(output_path),
    ]

    return build_kde_image.main(build_args)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    return build_iso(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
