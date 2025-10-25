"""Utility for building a bootable disk image that boots the kernel and KDE.

This script assembles a disk image backed by a Debian root file system, adds a
bootloader (GRUB by default), and installs the KDE Plasma desktop together with
its build-time dependencies. The resulting image can be written to a block
device or launched with your favourite virtual machine manager.

The implementation intentionally limits itself to standard Linux tooling so it
can run inside a container or CI environment as long as it has ``sudo``
privileges. The heavy lifting (debootstrap, apt, grub-install, etc.) happens in
subprocesses in order to keep the Python portion easy to audit.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Callable, Iterable, Sequence


DEFAULT_ISO_DIR = Path(__file__).resolve().parents[2] / "releases" / "iso"


class CommandError(RuntimeError):
    """Raised when a subprocess exits with a non-zero return code."""


@dataclasses.dataclass(slots=True)
class Command:
    """Representation of a command to run via :mod:`subprocess`."""

    argv: Sequence[str]
    env: dict[str, str] | None = None
    cwd: Path | None = None
    sudo: bool = False
    input_data: str | bytes | None = None
    text: bool = False

    def run(self) -> None:
        """Executes the command, raising :class:`CommandError` on failure."""

        full_argv = list(self.argv)
        if self.sudo and os.geteuid() != 0:
            full_argv = ["sudo", "--"] + full_argv

        display = " ".join(shlex.quote(part) for part in full_argv)
        if self.cwd:
            display = f"(cd {self.cwd}) {display}"
        print(f"[build-kde] $ {display}")
        try:
            subprocess.run(
                full_argv,
                check=True,
                cwd=self.cwd,
                env=self.env,
                input=self.input_data,
                text=self.text,
            )
        except subprocess.CalledProcessError as exc:  # pragma: no cover - passthrough
            raise CommandError(
                f"command {display} failed with exit code {exc.returncode}"
            ) from exc


@dataclasses.dataclass(slots=True)
class BuildConfig:
    """User supplied configuration for the image build."""

    architecture: str
    release: str
    output: Path
    image_size_gb: int = 16
    hostname: str = "freedomlinux"
    username: str = "builder"
    iso_directory: Path = DEFAULT_ISO_DIR

    @property
    def work_dir(self) -> Path:
        return self.output.parent / f".{self.output.name}.work"

    @property
    def mount_dir(self) -> Path:
        return self.work_dir / "mnt"

    @property
    def root_dir(self) -> Path:
        return self.mount_dir

    @property
    def iso_path(self) -> Path:
        return self.iso_directory / f"{self.output.stem}.iso"


REQUIRED_PACKAGES: tuple[str, ...] = (
    "apt",
    "build-essential",
    "ca-certificates",
    "cmake",
    "curl",
    "devscripts",
    "dpkg-dev",
    "extra-cmake-modules",
    "git",
    "grub-common",
    "grub-efi-amd64",
    "fakeroot",
    "kde-full",
    "kdesdk-scripts",
    "kdoctools",
    "libvirt-clients",
    "libvirt-daemon-system",
    "linux-image-amd64",
    "meson",
    "calamares",
    "firefox",
    "network-manager",
    "ninja-build",
    "pkg-config",
    "python3",
    "python3-pip",
    "python3-pyqt5",
    "sudo",
    "wget",
    "xz-utils",
)

REQUIRED_HOST_TOOLS: tuple[str, ...] = (
    "debootstrap",
    "qemu-img",
    "grub-install",
    "parted",
    "mkfs.ext4",
    "mkfs.vfat",
    "losetup",
    "grub-mkrescue",
    "rsync",
    "xorriso",
    "mtools",
)


SOURCE_PACKAGES: tuple[str, ...] = (
    "pulseaudio",
    "gtk+3.0",
    "qemu",
)


def parse_args(argv: Sequence[str]) -> BuildConfig:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--arch",
        default="amd64",
        help="Target architecture (passed to debootstrap).",
    )
    parser.add_argument(
        "--release",
        default="bookworm",
        help="Debian release to bootstrap.",
    )
    parser.add_argument(
        "--size-gb",
        type=int,
        default=16,
        help="Size of the resulting disk image in gigabytes.",
    )
    parser.add_argument(
        "--hostname",
        default="freedomlinux",
        help="Hostname configured inside the image.",
    )
    parser.add_argument(
        "--user",
        default="builder",
        help="Non-root user to create inside the image.",
    )
    parser.add_argument(
        "--iso-dir",
        type=Path,
        default=DEFAULT_ISO_DIR,
        help="Directory where generated ISO images will be stored.",
    )
    parser.add_argument(
        "output",
        type=Path,
        help="Path where the disk image should be written.",
    )
    args = parser.parse_args(argv)
    return BuildConfig(
        architecture=args.arch,
        release=args.release,
        output=args.output.resolve(),
        image_size_gb=args.size_gb,
        hostname=args.hostname,
        username=args.user,
        iso_directory=args.iso_dir.resolve(),
    )


def ensure_tools_available() -> None:
    missing = [tool for tool in REQUIRED_HOST_TOOLS if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(
            "The following required host tools are missing: " + ", ".join(missing)
        )


def run_commands(commands: Iterable[Command]) -> None:
    for command in commands:
        command.run()


def write_file(path: Path, content: str) -> None:
    if os.geteuid() == 0:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return
    Command(("mkdir", "-p", str(path.parent)), sudo=True).run()
    Command(("tee", str(path)), sudo=True, input_data=content, text=True).run()


def create_image(config: BuildConfig) -> None:
    config.work_dir.mkdir(parents=True, exist_ok=True)
    Command(
        (
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            str(config.output),
            f"{config.image_size_gb}G",
        )
    ).run()


def attach_loop_device(image: Path) -> str:
    argv = ["losetup", "--find", "--show", str(image)]
    if os.geteuid() != 0:
        argv = ["sudo", "--"] + argv
    print(f"[build-kde] $ {' '.join(shlex.quote(part) for part in argv)}")
    result = subprocess.run(argv, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def partition_and_format(config: BuildConfig) -> None:
    device = attach_loop_device(config.output)
    (config.work_dir / "loopdev").write_text(device, encoding="utf-8")
    run_commands(
        (
            Command(("parted", "-s", device, "mklabel", "gpt"), sudo=True),
            Command(
                (
                    "parted",
                    "-s",
                    device,
                    "mkpart",
                    "ESP",
                    "fat32",
                    "1MiB",
                    "513MiB",
                ),
                sudo=True,
            ),
            Command(("parted", "-s", device, "set", "1", "boot", "on"), sudo=True),
            Command(
                (
                    "parted",
                    "-s",
                    device,
                    "mkpart",
                    "primary",
                    "ext4",
                    "513MiB",
                    "100%",
                ),
                sudo=True,
            ),
        )
    )
    run_commands(
        (
            Command(("mkfs.vfat", f"{device}p1"), sudo=True),
            Command(("mkfs.ext4", f"{device}p2"), sudo=True),
        )
    )
    config.mount_dir.mkdir(parents=True, exist_ok=True)
    run_commands(
        (
            Command(("mount", f"{device}p2", str(config.mount_dir)), sudo=True),
            Command(
                ("mkdir", "-p", str(config.mount_dir / "boot" / "efi")),
                sudo=True,
            ),
            Command(
                ("mount", f"{device}p1", str(config.mount_dir / "boot" / "efi")),
                sudo=True,
            ),
        )
    )


def run_debootstrap(config: BuildConfig) -> None:
    env = os.environ.copy()
    env.setdefault("DEBOOTSTRAP_DIR", "/usr/share/debootstrap")
    Command(
        (
            "debootstrap",
            "--arch",
            config.architecture,
            config.release,
            str(config.root_dir),
        ),
        sudo=True,
        env=env,
    ).run()


def compile_source_packages(chroot_cmd: Callable[..., Command]) -> None:
    run_commands((chroot_cmd("mkdir", "-p", "/usr/local/src"),))
    for package in SOURCE_PACKAGES:
        run_commands(
            (
                chroot_cmd("apt-get", "-y", "build-dep", package),
                chroot_cmd(
                    "bash",
                    "-lc",
                    textwrap.dedent(
                        f"""
                        set -euo pipefail
                        cd /usr/local/src
                        rm -rf {package}-*
                        apt-get source {package}
                        cd {package}-*/
                        dpkg-buildpackage -us -uc -b
                        cd ..
                        shopt -s nullglob
                        debs=(./*.deb)
                        if [ ${{#debs[@]}} -eq 0 ]; then
                            echo "No .deb packages were produced for {package}" >&2
                            exit 1
                        fi
                        apt-get install -y "${{debs[@]}}"
                        """
                    ),
                ),
            )
        )


def configure_system(config: BuildConfig) -> None:
    run_commands(
        (
            Command(("mount", "--bind", "/dev", str(config.root_dir / "dev")), sudo=True),
            Command(("mount", "--bind", "/proc", str(config.root_dir / "proc")), sudo=True),
            Command(("mount", "--bind", "/sys", str(config.root_dir / "sys")), sudo=True),
        )
    )

    chroot_env = os.environ.copy()
    chroot_env["DEBIAN_FRONTEND"] = "noninteractive"

    def chroot_cmd(*argv: str) -> Command:
        return Command(("chroot", str(config.root_dir), *argv), sudo=True, env=chroot_env)

    write_file(config.root_dir / "etc" / "hostname", f"{config.hostname}\n")
    write_file(
        config.root_dir / "etc" / "hosts",
        "127.0.0.1\tlocalhost\n"
        f"127.0.1.1\t{config.hostname}\n\n"
        "# IPv6 defaults\n"
        "::1\tlocalhost ip6-localhost ip6-loopback\n"
        "ff02::1\tip6-allnodes\n"
        "ff02::2\tip6-allrouters\n",
    )
    write_file(
        config.root_dir / "etc" / "apt" / "sources.list",
        textwrap.dedent(
            f"""
            deb http://deb.debian.org/debian {config.release} main contrib non-free non-free-firmware
            deb-src http://deb.debian.org/debian {config.release} main contrib non-free non-free-firmware
            deb http://deb.debian.org/debian {config.release}-updates main contrib non-free non-free-firmware
            deb-src http://deb.debian.org/debian {config.release}-updates main contrib non-free non-free-firmware
            deb http://security.debian.org/debian-security {config.release}-security main contrib non-free non-free-firmware
            deb-src http://security.debian.org/debian-security {config.release}-security main contrib non-free non-free-firmware
            """
        ),
    )

    run_commands(
        (
            chroot_cmd("apt-get", "update"),
            chroot_cmd("apt-get", "-y", "upgrade"),
            chroot_cmd("apt-get", "-y", "install", *REQUIRED_PACKAGES),
        )
    )

    compile_source_packages(chroot_cmd)

    run_commands(
        (
            chroot_cmd("systemctl", "set-default", "graphical.target"),
            chroot_cmd("systemctl", "enable", "sddm"),
            chroot_cmd("systemctl", "enable", "network-manager"),
            chroot_cmd("systemctl", "enable", "libvirtd"),
        )
    )

    run_commands(
        (
            chroot_cmd("useradd", "-m", "-s", "/bin/bash", config.username),
            chroot_cmd("passwd", "-d", config.username),
            chroot_cmd("usermod", "-aG", "sudo", config.username),
            chroot_cmd("usermod", "-aG", "netdev", config.username),
            chroot_cmd("usermod", "-aG", "libvirt", config.username),
            chroot_cmd("usermod", "-aG", "kvm", config.username),
        )
    )

    setup_script_path = config.root_dir / "usr" / "local" / "bin" / "freedomlinux-setup"
    write_file(
        setup_script_path,
        textwrap.dedent(
            """#!/usr/bin/env python3
            from __future__ import annotations

            import subprocess
            import sys
            from dataclasses import dataclass
            from datetime import datetime
            from pathlib import Path

            from PyQt5 import QtCore, QtGui, QtWidgets


            @dataclass(slots=True)
            class WifiNetwork:
                ssid: str
                security: str
                signal: str

                @property
                def requires_password(self) -> bool:
                    security = self.security.strip().lower()
                    return bool(security and security not in {"--", "none", "open"})


            class SnapshotError(RuntimeError):
                'Raised when libvirt snapshot operations fail.'


            def virsh_command(args: list[str]) -> subprocess.CompletedProcess[str]:
                try:
                    return subprocess.run(
                        ["virsh", *args],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                except FileNotFoundError as exc:  # pragma: no cover - depends on runtime
                    raise SnapshotError("virsh command is not available on this system") from exc
                except subprocess.CalledProcessError as exc:  # pragma: no cover - passthrough
                    stderr = (exc.stderr or "").strip()
                    stdout = (exc.stdout or "").strip()
                    message = stderr or stdout or (
                        f"virsh {' '.join(args)} failed with exit code {exc.returncode}"
                    )
                    raise SnapshotError(message) from exc


            def list_domains() -> list[str]:
                try:
                    result = virsh_command(["list", "--all"])
                except SnapshotError:
                    return []

                lines = result.stdout.splitlines()[2:]
                domains: list[str] = []
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    parts = stripped.split()
                    if len(parts) >= 3:
                        domains.append(parts[1])
                return domains


            def list_snapshots(domain: str) -> list[str]:
                if not domain:
                    return []
                try:
                    result = virsh_command(["snapshot-list", "--name", domain])
                except SnapshotError:
                    return []
                return [line.strip() for line in result.stdout.splitlines() if line.strip()]


            def create_snapshot(domain: str, name: str, description: str) -> None:
                args = ["snapshot-create-as", domain, name, "--atomic"]
                if description:
                    args.extend(["--description", description])
                virsh_command(args)


            def delete_snapshot(domain: str, name: str) -> None:
                virsh_command(["snapshot-delete", domain, name])


            def revert_snapshot(domain: str, name: str) -> None:
                virsh_command(["snapshot-revert", domain, name, "--running"])


            def ensure_safety_snapshot(domain: str, prefix: str, reason: str) -> bool:
                if not domain:
                    return False
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                name = f"{prefix}-{timestamp}"
                description = f"Automatic snapshot ({reason})"
                try:
                    create_snapshot(domain, name, description)
                    return True
                except SnapshotError:
                    return False


            def nmcli(args: list[str]) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["nmcli", *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )


            def scan_networks() -> list[WifiNetwork]:
                try:
                    result = nmcli(
                        [
                            "--mode",
                            "multiline",
                            "--fields",
                            "SSID,SECURITY,SIGNAL",
                            "device",
                            "wifi",
                            "list",
                        ]
                    )
                except subprocess.CalledProcessError:
                    return []

                networks: list[WifiNetwork] = []
                current: dict[str, str] = {}
                for line in result.stdout.splitlines():
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped == "--":
                        if current.get("SSID"):
                            networks.append(
                                WifiNetwork(
                                    ssid=current.get("SSID", ""),
                                    security=current.get("SECURITY", ""),
                                    signal=current.get("SIGNAL", ""),
                                )
                            )
                        current = {}
                        continue
                    key, _, value = stripped.partition(":")
                    current[key.strip().upper()] = value.strip()

                if current.get("SSID"):
                    networks.append(
                        WifiNetwork(
                            ssid=current.get("SSID", ""),
                            security=current.get("SECURITY", ""),
                            signal=current.get("SIGNAL", ""),
                        )
                    )
                seen = set()
                unique: list[WifiNetwork] = []
                for network in networks:
                    if network.ssid in seen:
                        continue
                    seen.add(network.ssid)
                    unique.append(network)
                return unique


            class SnapshotManagerWindow(QtWidgets.QDialog):
                def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
                    super().__init__(parent)
                    self.setWindowTitle("FreedomLinux Snapshot Manager")
                    self.resize(520, 420)

                    layout = QtWidgets.QVBoxLayout(self)

                    domain_label = QtWidgets.QLabel("Virtual machine")
                    layout.addWidget(domain_label)

                    self.domain_combo = QtWidgets.QComboBox()
                    self.domain_combo.currentTextChanged.connect(self.refresh_snapshots)
                    layout.addWidget(self.domain_combo)

                    self.snapshot_list = QtWidgets.QListWidget()
                    self.snapshot_list.currentItemChanged.connect(self._update_snapshot_buttons)
                    layout.addWidget(self.snapshot_list)

                    button_row = QtWidgets.QHBoxLayout()
                    self.create_button = QtWidgets.QPushButton("Create Snapshot")
                    self.create_button.clicked.connect(self.create_snapshot)
                    button_row.addWidget(self.create_button)

                    self.revert_button = QtWidgets.QPushButton("Revert to Snapshot")
                    self.revert_button.clicked.connect(self.revert_snapshot)
                    button_row.addWidget(self.revert_button)

                    self.delete_button = QtWidgets.QPushButton("Delete Snapshot")
                    self.delete_button.clicked.connect(self.delete_snapshot)
                    button_row.addWidget(self.delete_button)

                    layout.addLayout(button_row)

                    self.status_label = QtWidgets.QLabel()
                    self.status_label.setWordWrap(True)
                    layout.addWidget(self.status_label)

                    self.refresh()

                def refresh(self) -> None:
                    domains = list_domains()
                    current = self.domain_combo.currentText()

                    self.domain_combo.blockSignals(True)
                    self.domain_combo.clear()
                    if domains:
                        self.domain_combo.addItems(domains)
                    self.domain_combo.blockSignals(False)

                    if current and current in domains:
                        self.domain_combo.setCurrentText(current)

                    if not domains:
                        self.status_label.setText(
                            "No virtual machines detected or libvirt is unavailable."
                        )
                        self.create_button.setEnabled(False)
                        self.revert_button.setEnabled(False)
                        self.delete_button.setEnabled(False)
                        self.snapshot_list.clear()
                        return

                    self.create_button.setEnabled(True)
                    self.refresh_snapshots(self.domain_combo.currentText())

                def refresh_snapshots(self, domain: str) -> None:
                    snapshots = list_snapshots(domain)
                    self.snapshot_list.clear()
                    for snapshot in snapshots:
                        self.snapshot_list.addItem(snapshot)

                    if snapshots:
                        self.status_label.setText(
                            "Select a snapshot to revert or delete. Automatic safety snapshots "
                            "are created before destructive actions or when an error occurs."
                        )
                    else:
                        self.status_label.setText("No snapshots available for the selected VM.")
                    self._update_snapshot_buttons()

                def _update_snapshot_buttons(self, *_args: object) -> None:
                    has_selection = self.snapshot_list.currentItem() is not None
                    has_domain = bool(self.domain_combo.currentText())
                    self.revert_button.setEnabled(has_selection and has_domain)
                    self.delete_button.setEnabled(has_selection and has_domain)

                def create_snapshot(self) -> None:
                    domain = self.domain_combo.currentText()
                    if not domain:
                        return
                    name = f"manual-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    try:
                        create_snapshot(
                            domain,
                            name,
                            "Manual snapshot created from the FreedomLinux setup assistant.",
                        )
                        self.status_label.setText(
                            f"Snapshot '{name}' created for virtual machine '{domain}'."
                        )
                    except SnapshotError as exc:
                        ensure_safety_snapshot(domain, "bug", "after snapshot creation failure")
                        QtWidgets.QMessageBox.warning(self, "Snapshot Error", str(exc))
                    self.refresh_snapshots(domain)

                def delete_snapshot(self) -> None:
                    domain = self.domain_combo.currentText()
                    item = self.snapshot_list.currentItem()
                    if not domain or not item:
                        return
                    snapshot = item.text()
                    ensure_safety_snapshot(domain, "predelete", "before deleting a snapshot")
                    try:
                        delete_snapshot(domain, snapshot)
                        self.status_label.setText(
                            f"Snapshot '{snapshot}' removed from virtual machine '{domain}'."
                        )
                    except SnapshotError as exc:
                        ensure_safety_snapshot(domain, "bug", "after snapshot deletion failure")
                        QtWidgets.QMessageBox.warning(self, "Snapshot Error", str(exc))
                    self.refresh_snapshots(domain)

                def revert_snapshot(self) -> None:
                    domain = self.domain_combo.currentText()
                    item = self.snapshot_list.currentItem()
                    if not domain or not item:
                        return
                    snapshot = item.text()
                    ensure_safety_snapshot(domain, "prerevert", "before reverting to a snapshot")
                    try:
                        revert_snapshot(domain, snapshot)
                        self.status_label.setText(
                            f"Virtual machine '{domain}' reverted to snapshot '{snapshot}'."
                        )
                    except SnapshotError as exc:
                        ensure_safety_snapshot(domain, "bug", "after snapshot revert failure")
                        QtWidgets.QMessageBox.warning(self, "Snapshot Error", str(exc))
                    self.refresh_snapshots(domain)


            class WifiSetupWindow(QtWidgets.QWidget):
                def __init__(self) -> None:
                    super().__init__()
                    self.setWindowTitle("FreedomLinux Setup")
                    self.resize(500, 400)

                    self.networks: list[WifiNetwork] = []
                    self.process: QtCore.QProcess | None = None
                    self.snapshot_manager: SnapshotManagerWindow | None = None

                    layout = QtWidgets.QVBoxLayout(self)

                    description = QtWidgets.QLabel(
                        "Select a Wi-Fi network to connect before installing FreedomLinux."
                    )
                    description.setWordWrap(True)
                    layout.addWidget(description)

                    self.list_widget = QtWidgets.QListWidget()
                    self.list_widget.currentItemChanged.connect(self._selection_changed)
                    layout.addWidget(self.list_widget)

                    self.password_edit = QtWidgets.QLineEdit()
                    self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
                    self.password_edit.setPlaceholderText("Wi-Fi password")
                    self.password_edit.textChanged.connect(self._update_next_button)
                    self.password_edit.setEnabled(False)
                    layout.addWidget(self.password_edit)

                    button_row = QtWidgets.QHBoxLayout()
                    self.refresh_button = QtWidgets.QPushButton("Refresh Networks")
                    self.refresh_button.clicked.connect(self.refresh_networks)
                    button_row.addWidget(self.refresh_button)

                    button_row.addStretch(1)

                    self.next_button = QtWidgets.QPushButton("Next")
                    self.next_button.setEnabled(False)
                    self.next_button.clicked.connect(self._connect_and_launch)
                    button_row.addWidget(self.next_button)
                    layout.addLayout(button_row)

                    self.status_label = QtWidgets.QLabel()
                    layout.addWidget(self.status_label)

                    self.snapshot_shortcut = QtWidgets.QShortcut(
                        QtGui.QKeySequence("Alt+S"),
                        self,
                    )
                    self.snapshot_shortcut.setContext(QtCore.Qt.ApplicationShortcut)
                    self.snapshot_shortcut.activated.connect(self._show_snapshot_manager)

                    self.refresh_networks()

                def refresh_networks(self) -> None:
                    self.status_label.setText("Scanning for Wi-Fi networks…")
                    QtWidgets.QApplication.processEvents()
                    try:
                        nmcli(["device", "wifi", "rescan"])
                    except subprocess.CalledProcessError:
                        pass
                    self.networks = scan_networks()
                    self.list_widget.clear()
                    for network in self.networks:
                        item = QtWidgets.QListWidgetItem(
                            f"{network.ssid or '(Hidden SSID)'} — {network.security or 'Open'}"
                        )
                        item.setData(QtCore.Qt.UserRole, network)
                        self.list_widget.addItem(item)
                    if not self.networks:
                        self.status_label.setText("No Wi-Fi networks found. Try refreshing.")
                    else:
                        self.status_label.setText("")
                    self._update_next_button()

                def _selection_changed(self, current: QtWidgets.QListWidgetItem | None) -> None:
                    network = current.data(QtCore.Qt.UserRole) if current else None
                    if network and network.requires_password:
                        self.password_edit.setEnabled(True)
                        self.password_edit.setFocus()
                    else:
                        self.password_edit.clear()
                        self.password_edit.setEnabled(False)
                    self._update_next_button()

                def _update_next_button(self) -> None:
                    item = self.list_widget.currentItem()
                    if not item:
                        self.next_button.setEnabled(False)
                        return
                    network: WifiNetwork = item.data(QtCore.Qt.UserRole)
                    if not network.ssid:
                        self.next_button.setEnabled(False)
                        return
                    if network.requires_password and not self.password_edit.text():
                        self.next_button.setEnabled(False)
                        return
                    self.next_button.setEnabled(True)

                def _connect_and_launch(self) -> None:
                    item = self.list_widget.currentItem()
                    if not item or self.process is not None:
                        return
                    network: WifiNetwork = item.data(QtCore.Qt.UserRole)
                    password = self.password_edit.text()
                    args = ["device", "wifi", "connect", network.ssid]
                    if network.requires_password:
                        args.extend(["password", password])

                    self.status_label.setText(f"Connecting to {network.ssid}…")
                    self.next_button.setEnabled(False)
                    self.refresh_button.setEnabled(False)
                    self.process = QtCore.QProcess(self)
                    self.process.finished.connect(self._connection_finished)
                    self.process.start("nmcli", args)

                def _connection_finished(self, exit_code: int, status: QtCore.QProcess.ExitStatus) -> None:
                    self.process = None
                    if exit_code == 0 and status == QtCore.QProcess.NormalExit:
                        self.status_label.setText("Connected. Launching Calamares…")
                        self._disable_autostart()
                        QtCore.QTimer.singleShot(500, self._launch_calamares)
                    else:
                        self.status_label.setText("Failed to connect. Please verify the password.")
                        self.next_button.setEnabled(True)
                        self.refresh_button.setEnabled(True)

                def _launch_calamares(self) -> None:
                    QtCore.QProcess.startDetached("calamares")
                    self.close()

                def _disable_autostart(self) -> None:
                    autostart_entry = Path.home() / ".config" / "autostart" / "freedomlinux-setup.desktop"
                    try:
                        autostart_entry.unlink()
                    except FileNotFoundError:
                        pass

                def _show_snapshot_manager(self) -> None:
                    if self.snapshot_manager is None:
                        self.snapshot_manager = SnapshotManagerWindow(self)
                    self.snapshot_manager.refresh()
                    self.snapshot_manager.show()
                    self.snapshot_manager.raise_()
                    self.snapshot_manager.activateWindow()


            def main() -> int:
                app = QtWidgets.QApplication(sys.argv)
                window = WifiSetupWindow()
                window.show()
                return app.exec()


            if __name__ == "__main__":
                sys.exit(main())
            """
        ),
    )
    Command(("chmod", "0755", str(setup_script_path)), sudo=True).run()

    autostart_dir = Path(f"/home/{config.username}/.config/autostart")
    run_commands(
        (
            chroot_cmd(
                "install",
                "-d",
                "-m",
                "0755",
                "-o",
                config.username,
                "-g",
                config.username,
                str(autostart_dir),
            ),
        )
    )

    autostart_entry = textwrap.dedent(
        """[Desktop Entry]
        Type=Application
        Name=FreedomLinux Setup
        Exec=/usr/local/bin/freedomlinux-setup
        X-GNOME-Autostart-enabled=true
        """
    )
    autostart_path = config.root_dir / autostart_dir.relative_to("/") / "freedomlinux-setup.desktop"
    write_file(autostart_path, autostart_entry)
    Command(("chown", f"{config.username}:{config.username}", str(autostart_path)), sudo=True).run()

    write_file(
        config.root_dir / "etc" / "polkit-1" / "rules.d" / "49-freedomlinux-nm.rules",
        textwrap.dedent(
            """polkit.addRule(function(action, subject) {
                if ((action.id == "org.freedesktop.NetworkManager.settings.modify.system" ||
                     action.id == "org.freedesktop.NetworkManager.network-control") &&
                    subject.isInGroup("sudo")) {
                    return polkit.Result.YES;
                }
            });
            """
        ),
    )

    write_file(
        config.root_dir / "etc" / "sddm.conf.d" / "autologin.conf",
        textwrap.dedent(
            f"""
            [Autologin]
            User={config.username}
            Session=plasma.desktop
            """
        ),
    )

    run_commands(
        (
            chroot_cmd(
                "grub-install",
                "--target=x86_64-efi",
                "--efi-directory=/boot/efi",
                "--bootloader-id=freedomlinux",
            ),
            chroot_cmd("update-grub"),
        )
    )


def create_iso_release(config: BuildConfig) -> None:
    config.iso_directory.mkdir(parents=True, exist_ok=True)
    iso_root = config.work_dir / "iso_root"

    run_commands(
        (
            Command(("rm", "-rf", str(iso_root)), sudo=True),
            Command(("mkdir", "-p", str(iso_root)), sudo=True),
        )
    )

    run_commands(
        (
            Command(
                (
                    "rsync",
                    "-aHAX",
                    "--delete",
                    f"{config.root_dir}/",
                    str(iso_root),
                ),
                sudo=True,
            ),
        )
    )

    run_commands(
        (
            Command(
                (
                    "grub-mkrescue",
                    "-o",
                    str(config.iso_path),
                    str(iso_root),
                ),
                sudo=True,
            ),
        )
    )

    if os.geteuid() != 0:
        Command(
            (
                "chown",
                f"{os.getuid()}:{os.getgid()}",
                str(config.iso_path),
            ),
            sudo=True,
        ).run()


def cleanup(config: BuildConfig) -> None:
    targets = (
        config.root_dir / "boot" / "efi",
        config.root_dir / "sys",
        config.root_dir / "proc",
        config.root_dir / "dev",
        config.root_dir,
    )
    for mount_point in targets:
        if mount_point.exists():
            with contextlib.suppress(CommandError):
                Command(("umount", "-fl", str(mount_point)), sudo=True).run()

    loop_path = config.work_dir / "loopdev"
    if loop_path.exists():
        device = loop_path.read_text(encoding="utf-8").strip()
        if device:
            with contextlib.suppress(CommandError):
                Command(("losetup", "-d", device), sudo=True).run()

    iso_root = config.work_dir / "iso_root"
    if iso_root.exists():
        with contextlib.suppress(CommandError):
            Command(("rm", "-rf", str(iso_root)), sudo=True).run()


def main(argv: Sequence[str]) -> int:
    config = parse_args(argv)
    ensure_tools_available()
    config.work_dir.mkdir(parents=True, exist_ok=True)

    try:
        create_image(config)
        partition_and_format(config)
        run_debootstrap(config)
        configure_system(config)
        create_iso_release(config)
        print("Disk image created successfully:", config.output)
        print("ISO image created successfully:", config.iso_path)
        return 0
    except CommandError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - top level safety net
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        cleanup(config)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
