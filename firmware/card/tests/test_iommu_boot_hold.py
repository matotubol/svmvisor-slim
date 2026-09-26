"""Offline decoding of successful physical publication with guests still held."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from read_snapshot import resident_boot_observation


class IommuBootHoldTests(unittest.TestCase):
    def decode(self, metadata=6, detail=1, count=24):
        words = [0] * 16
        words[10], words[11], words[9] = metadata, detail, count
        return resident_boot_observation(tuple(words), 0x13)

    def test_installed_does_not_mean_windows_or_guest_release(self):
        record = self.decode()
        self.assertTrue(record["encoding_valid"])
        self.assertEqual(record["stage_name"], "iommu_published_guests_held")
        self.assertTrue(record["iommu_publication_completed"])
        self.assertTrue(record["guest_release_held"])
        self.assertFalse(record["all_cpus_activated"])
        self.assertFalse(record["windows_boot_proven"])
        self.assertIsNone(record["activation_failure"])

    def test_hold_requires_its_exact_shape(self):
        for metadata, detail, count in ((6, 0, 24), (6, 2, 24), (0x10006, 1, 24),
                                        (6, 1, 0), (6, 1, 33)):
            record = self.decode(metadata, detail, count)
            self.assertFalse(record["encoding_valid"])
            self.assertIsNone(record["iommu_publication_completed"])
            self.assertIsNone(record["guest_release_held"])

    def test_admission_or_effect_failure_never_implies_successful_publication(self):
        for code in range(80, 93):
            record = self.decode(0x80, code, 24)
            self.assertTrue(record["encoding_valid"])
            self.assertIsNotNone(record["activation_failure_name"])
            self.assertEqual(record["activation_failure"], code)
            self.assertIsNone(record["iommu_publication_completed"])
            self.assertFalse(record["all_cpus_activated"])


if __name__ == "__main__":
    unittest.main()
