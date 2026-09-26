"""Offline wire and redaction checks; no transport or hardware access."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from read_snapshot import resident_boot_observation


class PublicStopTests(unittest.TestCase):
    def decode(self, metadata, detail=0, last=0):
        words = [0] * 16
        words[10], words[11], words[9] = metadata, detail, last
        return resident_boot_observation(tuple(words), 0x15)

    def test_closed_categories_do_not_claim_dma_or_windows_success(self):
        for reason in range(1, 7):
            record = self.decode(1 | (reason << 8))
            self.assertTrue(record["encoding_valid"])
            self.assertTrue(record["all_cpus_parked"])
            self.assertFalse(record["runtime_details_exported"])
            self.assertFalse(record["windows_boot_proven"])
            self.assertIsNone(record["dma_drained"])
            self.assertNotIn("guest_rip", record)
            self.assertNotIn("address", record)

    def test_unknown_versions_categories_and_extra_data_are_invalid(self):
        for args in ((0,), (1,), (0x701,), (0x102,), (0x1000101,),
                     (0x101, 1), (0x101, 0, 1), (0xffffffff,)):
            record = self.decode(*args)
            self.assertFalse(record["encoding_valid"])
            self.assertIsNone(record["reason"])
            self.assertIsNone(record["all_cpus_parked"])


if __name__ == "__main__":
    unittest.main()
