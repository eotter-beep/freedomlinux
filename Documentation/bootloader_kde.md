# Building a bootable KDE desktop image

The kernel tree now ships with a helper script that assembles a complete disk
image containing:

- a Debian based root file system with the requested release
- a GRUB bootloader pre-configured for EFI systems
- the KDE Plasma desktop and essential developer tooling
- rebuilt PulseAudio, GTK, and QEMU packages so Plasma boots with fresh user space
- desktop essentials including the `apt` package manager frontend, NetworkManager,
  the Calamares installer, and Firefox
- a first-boot setup helper that connects to Wi-Fi and launches the Calamares
  installer when networking is ready
- libvirt services and a snapshot manager that safeguards virtual machines with
  automatic checkpoints

The resulting image is suitable for development workflows that need to validate
kernel changes against a full KDE user space.

## Requirements

The script depends on a handful of host tools:

- `debootstrap`
- `qemu-img`
- `losetup`
- `parted`
- `mkfs.ext4`
- `mkfs.vfat`
- `grub-install`
- `grub-mkrescue`
- `rsync`
- `xorriso`
- `mtools`

Make sure these packages are installed on the build machine. On Debian or Ubuntu
hosts, the following command installs everything you need:

```bash
sudo apt-get update
sudo apt-get install debootstrap qemu-utils grub-efi-amd64-bin grub-common \
    dosfstools e2fsprogs parted grub2-common xorriso mtools rsync
```

## Usage

Invoke the builder with the path to the output image. Optional parameters let
you pick a Debian release, image size, hostname, default user, and the
directory where ISO release artifacts are stored:

```bash
python3 tools/bootloader/build_kde_image.py \
    --release bookworm \
    --arch amd64 \
    --size-gb 20 \
    --hostname freedomlinux-kde \
    --user developer \
    --iso-dir releases/iso \
    out/freedomlinux-kde.qcow2
```

The command performs the following steps:

1. Creates a QCOW2 disk image.
2. Partitions the image with an EFI system partition and an ext4 root partition.
3. Bootstraps a Debian root file system inside the image.
4. Installs KDE Plasma, its build dependencies, and desktop tooling such as
   NetworkManager, Calamares, Firefox, a PyQt-based first boot assistant, and a
   libvirt-powered snapshot manager.
5. Recompiles PulseAudio, GTK, and QEMU from their Debian source packages and installs
   the resulting binaries into the image.
6. Seeds the initramfs with virtio drivers and disables NetworkManager's wait-online
   service so QEMU boots quickly without stalling on device discovery.
7. Configures a non-root user with password-less login, sudo privileges, KDE
   auto-login through SDDM, and a desktop autostart entry for the setup helper.
8. Installs GRUB as the bootloader, refreshes its configuration, and sets the default
   boot target to the graphical session.

When the script finishes it prints the path to the QCOW2 disk image and the ISO
image that is copied to `releases/iso/`. The installer ISO is also copied into
the disk image at `/srv/freedomlinux/iso/<image>.iso` so the live environment
always has a bootable copy of the release artifact available locally. You can
boot the QCOW2 image with any
EFI capable hypervisor. For example, using QEMU:

```bash
qemu-system-x86_64 \
    -enable-kvm \
    -m 4096 \
    -drive file=out/freedomlinux-kde.qcow2,if=virtio,format=qcow2 \
    -display sdl
```

If you prefer a turnkey experience that always writes the artifacts to
`releases/iso/`, use the convenience wrapper that lives alongside the release
directory:

```bash
python3 releases/iso/create_iso.py --size-gb 20 --hostname plasma-lab
```

The wrapper exposes the most common configuration options and delegates the
heavy lifting to `tools/bootloader/build_kde_image.py`, so you get identical
outputs with less typing.

## First boot workflow

The autologin session starts a "FreedomLinux Setup" helper on the KDE desktop.
It scans for available Wi-Fi networks, lets you enter the passphrase for the one
you choose, and connects using NetworkManager. After a successful connection, the
assistant automatically launches the Calamares installer so you can finish
installing the system to disk. The helper removes itself from KDE's autostart
directory once it starts Calamares, so it will not appear again on subsequent
logins.

Pressing <kbd>Alt</kbd>+<kbd>S</kbd> opens a snapshot manager that talks to
libvirt. The manager lets you inspect the virtual machines present on the live
system, create manual checkpoints, and revert or delete snapshots. Before any
destructive action (such as deleting a snapshot) the tool automatically creates
an additional safety snapshot, and it attempts the same recovery snapshot if a
libvirt command fails. This ensures that a recent checkpoint is always available
even when operations hit an error.

## Customising the root file system

The generated root file system lives under `.freedomlinux-kde.qcow2.work/mnt`
while the script is running. You can modify the contents (for example, install
additional packages) before the cleanup step executes. If you want to keep the
working directory for debugging, interrupt the script before it finishes or copy
the contents elsewhere.

## Cleaning up

The builder automatically tears down loop devices and unmounts temporary
mountpoints. If your run is interrupted you can manually clean the environment
with:

```bash
sudo losetup -D
sudo umount -R .freedomlinux-kde.qcow2.work/mnt
```

Make sure no mount points from previous runs linger before starting a new
build.
