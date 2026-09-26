"""Small Windows D3XX adapter; importing this module never opens a device."""
import ctypes
import hashlib
import math
import os
from pathlib import Path
import re
import struct
import time


class PipeInformation(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint32), ("identifier", ctypes.c_uint8),
                ("packet_bytes", ctypes.c_uint16), ("interval", ctypes.c_uint8)]


class InterfaceDescriptor(ctypes.Structure):
    _pack_ = 1
    _fields_ = [(name, ctypes.c_uint8) for name in
               ("length", "kind", "number", "alternate", "endpoints", "class_code",
                "subclass", "protocol", "string_index")]


class ChipConfiguration(ctypes.Structure):
    # FT_60XCONFIGURATION, AN_379 v1.7 pp.58-59. Windows ULONG is always 32 bits.
    _fields_ = [("vendor", ctypes.c_uint16), ("product", ctypes.c_uint16),
                ("strings", ctypes.c_uint8 * 128), ("interval", ctypes.c_uint8),
                ("power_attributes", ctypes.c_uint8), ("power_consumption", ctypes.c_uint16),
                ("reserved", ctypes.c_uint8), ("clock", ctypes.c_uint8),
                ("mode", ctypes.c_uint8), ("channels", ctypes.c_uint8),
                ("features", ctypes.c_uint16), ("battery_gpio", ctypes.c_uint8),
                ("flash_detection", ctypes.c_uint8), ("msio", ctypes.c_uint32),
                ("gpio", ctypes.c_uint32)]


def validate_configuration(config):
    if (config.vendor, config.product) != (0x0403, 0x601f):
        raise ValueError("expected the board's FT601 USB identity 0403:601f")
    # FTD3XX.h enums: 100 MHz=0, synchronous FT245=0, one IN/OUT channel=2.
    if (config.clock, config.mode, config.channels) != (0, 0, 2):
        raise ValueError("FT601 must already use 100 MHz FT245 mode and one IN/OUT channel")


def verify_library(path, expected_sha256):
    path = Path(path)
    if not path.is_absolute() or path.suffix.lower() != ".dll" or not path.is_file():
        raise ValueError("an absolute existing D3XX DLL path is required")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("D3XX DLL SHA-256 must contain 64 hexadecimal digits")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256.lower():
        raise ValueError("D3XX DLL SHA-256 mismatch")
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("D3XX DLL is not a PE image")
    offset = struct.unpack_from("<I", data, 60)[0]
    if offset > len(data) - 6 or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError("D3XX DLL has no valid PE header")
    if struct.unpack_from("<H", data, offset + 4)[0] != 0x8664:
        raise ValueError("D3XX DLL must be AMD64")
    return path.resolve()


class D3xx:
    """One explicitly selected device, one synchronous request at a time.

    No EEPROM/configuration writes, stream mode, reset, flush, or reconnect.
    Finite driver timeouts supplement the bridge's separate process supervisor.
    The supervisor also bounds hangs in device creation and cleanup.
    """
    def __init__(self, path, sha256, serial):
        if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ValueError("D3XX bridge requires native 64-bit Windows Python")
        if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", serial):
            raise ValueError("an explicit ASCII FT601 serial is required")
        path = verify_library(path, sha256)
        self.library = ctypes.WinDLL(str(path), winmode=0x1100)
        pointer, u32, u8 = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint8
        functions = (
            ("FT_Create", [pointer, u32, ctypes.POINTER(pointer)]),
            ("FT_Close", [pointer]),
            ("FT_GetChipConfiguration", [pointer, ctypes.POINTER(ChipConfiguration)]),
            ("FT_GetInterfaceDescriptor", [pointer, u8, ctypes.POINTER(InterfaceDescriptor)]),
            ("FT_GetPipeInformation", [pointer, u8, u8, ctypes.POINTER(PipeInformation)]),
            ("FT_SetPipeTimeout", [pointer, u8, u32]),
            ("FT_ReadPipe", [pointer, u8, pointer, u32, ctypes.POINTER(u32), pointer]),
            ("FT_WritePipe", [pointer, u8, pointer, u32, ctypes.POINTER(u32), pointer]),
            ("FT_AbortPipe", [pointer, u8]),
        )
        for name, arguments in functions:
            function = getattr(self.library, name)
            function.argtypes, function.restype = arguments, u32
        self.handle = pointer()
        self.closed = False
        try:
            serial_buffer = ctypes.create_string_buffer(serial.encode("ascii"))
            self._check(self.library.FT_Create(serial_buffer, 1, ctypes.byref(self.handle)),
                        "open device by serial")
            if not self.handle.value:
                raise ValueError("D3XX returned a null device handle")
            config = ChipConfiguration()
            self._check(self.library.FT_GetChipConfiguration(self.handle, ctypes.byref(config)),
                        "read chip configuration")
            validate_configuration(config)
            descriptor = InterfaceDescriptor()
            self._check(self.library.FT_GetInterfaceDescriptor(
                self.handle, 1, ctypes.byref(descriptor)), "read interface descriptor")
            if descriptor.length != 9 or descriptor.kind != 4 or descriptor.endpoints != 2:
                raise ValueError("FT601 requires one bulk IN/OUT channel on interface 1")
            pipes = {}
            for index in range(2):
                info = PipeInformation()
                self._check(self.library.FT_GetPipeInformation(
                    self.handle, 1, index, ctypes.byref(info)), "read pipe information")
                if info.kind != 2 or info.packet_bytes not in (512, 1024):
                    raise ValueError("unsupported FT601 bulk endpoint")
                pipes[info.identifier] = info.packet_bytes
            if set(pipes) != {0x02, 0x82}:
                raise ValueError("expected FT601 OUT 0x02 and IN 0x82")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _check(status, operation):
        if status != 0:
            raise OSError(f"D3XX {operation} failed: status {status}")

    def _timeout(self, pipe, deadline):
        if self.closed:
            raise ValueError("D3XX device is closed")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("FT601 transaction deadline expired")
        milliseconds = min(60000, max(1, math.ceil(remaining * 1000)))
        self._check(self.library.FT_SetPipeTimeout(self.handle, pipe, milliseconds),
                    "set finite pipe timeout")
        if time.monotonic() >= deadline:
            raise TimeoutError("FT601 transaction deadline expired while setting pipe timeout")

    def write(self, data, deadline):
        self._timeout(0x02, deadline)
        buffer = ctypes.create_string_buffer(data)
        transferred = ctypes.c_uint32()
        status = self.library.FT_WritePipe(self.handle, 0x02, buffer, len(data),
                                          ctypes.byref(transferred), None)
        self._check(status, "write")
        if transferred.value != len(data):
            raise ValueError("short FT601 write; request may be partially submitted")
        if time.monotonic() >= deadline:
            raise TimeoutError("FT601 write exceeded transaction deadline")

    def read(self, length, deadline):
        self._timeout(0x82, deadline)
        buffer = ctypes.create_string_buffer(length)
        transferred = ctypes.c_uint32()
        status = self.library.FT_ReadPipe(self.handle, 0x82, buffer, length,
                                         ctypes.byref(transferred), None)
        self._check(status, "read")
        if not 0 < transferred.value <= length:
            raise ValueError("invalid FT601 read length")
        if time.monotonic() >= deadline:
            raise TimeoutError("FT601 read exceeded transaction deadline")
        return buffer.raw[:transferred.value]

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.handle.value:
            # Aborting USB pipes does not cancel an already published CPU request.
            for pipe in (0x02, 0x82):
                self.library.FT_AbortPipe(self.handle, pipe)
            self.library.FT_Close(self.handle)
            self.handle = ctypes.c_void_p()
