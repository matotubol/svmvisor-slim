import unittest
from read_snapshot import decode_frame
from test_snapshot_reader import frame

class SyscfgDiagnostics(unittest.TestCase):
    def decode(self, reason, mode, value, write=True, extra=0):
        meta = 0x10000085 | (23 << 8) | (reason << 13) | (mode << 21) | (int(write) << 23) | extra
        return decode_frame(frame(phase_detail=0x00080013, cpu_id=value >> 32,
            context=(meta, value & 0xffffffff)))['native_resident_observation']

    def test_exact_operands_and_readback(self):
        for reason in range(0x81, 0x86):
            r = self.decode(reason, 0, (0x740000 << 32) | 0x7c0000)
            self.assertTrue(r['encoding_valid'])
            self.assertEqual(r['requested_value'], 0x7c0000)
            self.assertEqual(r['observed_value'], 0x740000)
            self.assertEqual(r['changed_bits'], 1 << 19)
            self.assertEqual(r['observed_is_readback'], reason == 0x85)
            self.assertEqual(r['msr_index'], 0xc0010010)
            self.assertEqual(r['processor_slot'], 23)

    def test_full_width_fallback_never_invents_missing_operand(self):
        for mode in [1, 2]:
            r = self.decode(0x83, mode, 0xfedcba9876543210)
            self.assertTrue(r['encoding_valid'])
            self.assertEqual(r['requested_value'], 0xfedcba9876543210 if mode == 1 else None)
            self.assertEqual(r['observed_value'], 0xfedcba9876543210 if mode == 2 else None)
            self.assertIsNone(r['changed_bits'])
            self.assertTrue(r['operand_omitted'])
        r = self.decode(0x53, 3, 0xfffff80001234567)
        self.assertTrue(r['encoding_valid'])
        self.assertEqual(r['boundary_context'], 0xfffff80001234567)
        self.assertIsNone(r['requested_value'])

    def test_bad_shape_is_not_evidence(self):
        for reason, mode, write, extra in [(0,0,True,0), (0x86,0,True,0),
                (0x84,3,True,0), (3,0,True,0), (0x80,0,True,0),
                (0x84,0,False,0), (0x84,0,True,1 << 24)]:
            self.assertFalse(self.decode(reason,mode,0,write,extra)['encoding_valid'])

    def test_hardware_instruction_failure_names_and_context_roles(self):
        failures = (
            (0x50, 'exit_does_not_permit_candidate', 'raw_exit_info1'),
            (0x51, 'nrip_not_established', 'nrip'),
            (0x52, 'noncanonical_rip', 'guest_rip'),
            (0x53, 'noncanonical_nrip', 'nrip'),
            (0x54, 'invalid_instruction_length', 'nrip'),
            (0x55, 'unsupported_instruction_bytes', 'none'),
        )
        for reason, failure, role in failures:
            with self.subTest(reason=reason):
                value = 0 if reason == 0x55 else 0xfffff80001234567
                r = self.decode(reason, 3, value)
                self.assertTrue(r['encoding_valid'])
                self.assertEqual(r['predicate'], 'instruction_boundary')
                self.assertEqual(r['instruction_failure'], failure)
                self.assertEqual(r['instruction_evidence_source'], 'hardware_nrip')
                self.assertEqual(r['boundary_context_role'], role)
                self.assertEqual(r['boundary_context'], value)
                self.assertIsNone(r['guest_rip'])
                self.assertIsNone(r['requested_value'])
                self.assertIsNone(r['observed_value'])

    def test_instruction_metadata_requires_valid_hardware_encoding(self):
        for reason, mode, extra in [(0x54, 0, 0), (0x54, 3, 1 << 24),
                (0x14, 3, 0), (0x84, 0, 0)]:
            r = self.decode(reason, mode, 0, extra=extra)
            self.assertIsNone(r['instruction_failure'])
            self.assertIsNone(r['instruction_evidence_source'])
            self.assertIsNone(r['boundary_context_role'])

if __name__ == '__main__': unittest.main()
