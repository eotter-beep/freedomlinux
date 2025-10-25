"""Tests for partition sizing logic in the KDE image builder."""

import unittest
from pathlib import Path
from unittest import mock

from tools.bootloader.build_kde_image import (
    determine_disk_size_bytes,
    get_image_virtual_size_bytes,
    PartitionBounds,
    calculate_partition_bounds,
)


class PartitionBoundsTest(unittest.TestCase):
    def test_calculate_partition_bounds_with_standard_disk(self) -> None:
        total_bytes = 16 * 1024**3
        esp, root = calculate_partition_bounds(total_bytes)

        self.assertEqual(PartitionBounds(1, 513), esp)
        self.assertEqual(PartitionBounds(513, 16383), root)

    def test_calculate_partition_bounds_uses_available_space(self) -> None:
        total_bytes = 10**9
        esp, root = calculate_partition_bounds(total_bytes)

        self.assertEqual(PartitionBounds(1, 513), esp)
        # 10**9 bytes is 953 MiB once truncated, so the root partition should
        # extend to the last MiB of the device without exceeding it.
        self.assertEqual(PartitionBounds(513, 952), root)

    def test_calculate_partition_bounds_rejects_too_small_images(self) -> None:
        total_bytes = 512 * 1024**2  # Only enough room for the ESP
        with self.assertRaises(ValueError):
            calculate_partition_bounds(total_bytes)


class DiskSizeHelpersTest(unittest.TestCase):
    def test_get_image_virtual_size_bytes_parses_json(self) -> None:
        payload = "{\"virtual-size\": 4096}"
        with mock.patch("subprocess.run") as run_mock:
            run_mock.return_value = mock.Mock(stdout=payload)
            size = get_image_virtual_size_bytes(Path("disk.qcow2"))

        self.assertEqual(4096, size)
        run_mock.assert_called_once()

    def test_determine_disk_size_bytes_prefers_loop_device(self) -> None:
        with mock.patch(
            "tools.bootloader.build_kde_image.get_loop_device_size_bytes",
            return_value=2 * 1024 * 1024,
        ) as loop_mock, mock.patch(
            "tools.bootloader.build_kde_image.get_image_virtual_size_bytes",
            return_value=5 * 1024 * 1024,
        ) as image_mock:
            size = determine_disk_size_bytes("/dev/loop0", Path("disk.qcow2"))

        self.assertEqual(2 * 1024 * 1024, size)
        loop_mock.assert_called_once_with("/dev/loop0")
        image_mock.assert_not_called()

    def test_determine_disk_size_bytes_uses_fallback_when_loop_tiny(self) -> None:
        with mock.patch(
            "tools.bootloader.build_kde_image.get_loop_device_size_bytes",
            return_value=512,
        ) as loop_mock, mock.patch(
            "tools.bootloader.build_kde_image.get_image_virtual_size_bytes",
            return_value=10 * 1024 * 1024,
        ) as image_mock:
            size = determine_disk_size_bytes("/dev/loop1", Path("disk.qcow2"))

        self.assertEqual(10 * 1024 * 1024, size)
        loop_mock.assert_called_once_with("/dev/loop1")
        image_mock.assert_called_once_with(Path("disk.qcow2"))


if __name__ == "__main__":  # pragma: no cover - module is executed via unittest
    unittest.main()
