"""Offline D3XX ABI, library checks and transfer failures using fake DLL functions."""
import ctypes
import hashlib
from pathlib import Path
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import ft601_d3xx as d3xx


class D3xxTests(unittest.TestCase):
    def test_structure_layout(self):
        self.assertEqual(ctypes.sizeof(d3xx.PipeInformation), 12)
        self.assertEqual(d3xx.PipeInformation.identifier.offset, 4)
        self.assertEqual(d3xx.PipeInformation.packet_bytes.offset, 6)
        self.assertEqual(ctypes.sizeof(d3xx.InterfaceDescriptor), 9)
        self.assertEqual(ctypes.sizeof(d3xx.ChipConfiguration), 152)
        self.assertEqual(d3xx.ChipConfiguration.clock.offset, 137)
        self.assertEqual(d3xx.ChipConfiguration.mode.offset, 138)
        self.assertEqual(d3xx.ChipConfiguration.channels.offset, 139)

    def test_chip_configuration_refuses_wrong_mode_clock_channel_and_device(self):
        config = d3xx.ChipConfiguration()
        config.vendor, config.product, config.channels = 0x0403, 0x601f, 2
        d3xx.validate_configuration(config)
        for field, invalid in (("clock", 1), ("mode", 1), ("channels", 0), ("product", 0x601e)):
            with self.subTest(field=field):
                old = getattr(config, field)
                setattr(config, field, invalid)
                with self.assertRaises(ValueError):
                    d3xx.validate_configuration(config)
                setattr(config, field, old)

    def test_library_hash_and_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "FTD3XX.dll"
            data = bytearray(128)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 64)
            data[64:68] = b"PE\0\0"
            struct.pack_into("<H", data, 68, 0x8664)
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(d3xx.verify_library(path, digest), path.resolve())
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                d3xx.verify_library(path, "0" * 64)
            struct.pack_into("<H", data, 68, 0x14c)
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "AMD64"):
                d3xx.verify_library(path, hashlib.sha256(data).hexdigest())

    def adapter(self):
        adapter = d3xx.D3xx.__new__(d3xx.D3xx)
        adapter.handle, adapter.closed = ctypes.c_void_p(123), False
        adapter.library = SimpleNamespace(FT_SetPipeTimeout=Mock(return_value=0),
                                         FT_Close=Mock(return_value=0), FT_AbortPipe=Mock(return_value=0))
        return adapter

    def test_timeout_finite_and_short_write_rejected(self):
        adapter = self.adapter()
        def write(handle, pipe, buffer, count, transferred, overlapped):
            transferred._obj.value = count - 1
            return 0
        adapter.library.FT_WritePipe = write
        with self.assertRaisesRegex(ValueError, "short"):
            adapter.write(bytes(64), time.monotonic() + 1)
        timeout = adapter.library.FT_SetPipeTimeout.call_args.args[-1]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 1000)
        adapter.close()
        adapter.close()
        self.assertEqual(adapter.library.FT_AbortPipe.call_count, 2)
        adapter.library.FT_Close.assert_called_once()

    def test_driver_errors_and_empty_reads_propagate(self):
        adapter = self.adapter()
        adapter.library.FT_ReadPipe = Mock(return_value=5)
        with self.assertRaisesRegex(OSError, "status 5"):
            adapter.read(64, time.monotonic() + 1)
        adapter.library.FT_ReadPipe = Mock(return_value=0)
        with self.assertRaisesRegex(ValueError, "read length"):
            adapter.read(64, time.monotonic() + 1)
        with self.assertRaises(TimeoutError):
            adapter.read(64, time.monotonic() - 1)

    def test_expired_timeout_configuration_does_not_submit_io(self):
        adapter = self.adapter()
        adapter.library.FT_ReadPipe = Mock(return_value=0)
        adapter.library.FT_WritePipe = Mock(return_value=0)
        for operation, argument in ((adapter.read, 64), (adapter.write, bytes(64))):
            with patch.object(d3xx.time, "monotonic", side_effect=[10, 11]):
                with self.assertRaises(TimeoutError):
                    operation(argument, 11)
        adapter.library.FT_ReadPipe.assert_not_called()
        adapter.library.FT_WritePipe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
