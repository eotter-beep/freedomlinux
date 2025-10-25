"""Tests for partition sizing logic in the KDE image builder."""

import unittest

from tools.bootloader.build_kde_image import (
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


if __name__ == "__main__":  # pragma: no cover - module is executed via unittest
    unittest.main()
