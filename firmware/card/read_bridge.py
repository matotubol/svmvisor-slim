"""Bounded USER4 read transport. Offline codecs are the default; --live opens JTAG."""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import secrets
import queue
import threading
import struct
import subprocess
import sys
import time
import zlib


REQUEST_MAGIC = 0x51525653
RESPONSE_MAGIC = 0x50525653
FRAME_BYTES = 64
# The bridge exclusively owns this non-inheritable handle until process teardown. Never close
# it during normal Python cleanup: this process itself belongs to the kill-on-close job.
_CHILD_JOB_HANDLE = None


def establish_child_job():
    """Contain this bridge and future subprocesses before opening any hardware (Windows only).

    The unnamed job has no breakaway flags and no inherited handle. If xtask terminates Python,
    Windows closes its sole job handle and terminates remaining OpenOCD processes. Neither the
    calling xtask nor its ancestors is assigned to this job. Nested jobs require Windows 8+.
    https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
    """
    global _CHILD_JOB_HANDLE
    if _CHILD_JOB_HANDLE is not None:
        return
    if sys.platform != "win32":
        raise OSError("live bridge child containment currently requires Windows")

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimitInformation),
                    ("IoInfo", IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                               ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = ExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel.CloseHandle(handle)
        raise error
    if not kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel.CloseHandle(handle)
        raise error
    _CHILD_JOB_HANDLE = handle


def encode_request(sequence, gpa, length, boot_id):
    if any(type(value) is not int for value in (sequence, gpa, length, boot_id)):
        raise ValueError("request fields must be integers")
    if not 0 < sequence <= 0xffffffff:
        raise ValueError("sequence must be nonzero u32")
    if not 0 < boot_id <= 0xffffffff:
        raise ValueError("boot_id must be nonzero u32")
    if not 0x100000 <= gpa < 1 << 64 or not 1 <= length <= 32:
        raise ValueError("request address or length out of range")
    if (gpa & 4095) + length > 4096 or gpa + length > 1 << 64:
        raise ValueError("request crosses a page or overflows")
    body = struct.pack("<15I", REQUEST_MAGIC, 1, sequence, 1, length,
                       gpa & 0xffffffff, gpa >> 32, boot_id, *([0] * 7))
    return body + struct.pack("<I", zlib.crc32(body))


def scan_hex(frame):
    return "0x" + frame[::-1].hex()


def parse_scan(value):
    value = value.strip().removeprefix("0x")
    if len(value) != FRAME_BYTES * 2:
        raise ValueError("expected exactly 512 scan bits")
    frame = bytes.fromhex(value)[::-1]
    if zlib.crc32(frame[:60]) != struct.unpack_from("<I", frame, 60)[0]:
        raise ValueError("frame CRC mismatch")
    return frame


def decode_response(value, sequence=None, gpa=None, length=None):
    frame = parse_scan(value)
    words = struct.unpack("<16I", frame)
    if words[0] != RESPONSE_MAGIC or words[1] != 1 or words[2] == 0:
        raise ValueError("unsupported response frame")
    if words[3] not in range(7):
        raise ValueError("unsupported response status")
    if sequence is not None and words[2] != sequence:
        raise ValueError("stale response sequence")
    address = words[5] | words[6] << 32
    if gpa is not None and address != gpa:
        raise ValueError("response address mismatch")
    count, slot = words[4] & 0xffff, words[4] >> 16
    if count > 32 or slot >= 32:
        raise ValueError("response length or CPU slot out of range")
    data = frame[28:60]
    if words[3] == 0:
        if count == 0 or (length is not None and count != length):
            raise ValueError("incomplete successful response")
    elif count != 0:
        raise ValueError("refusal contains data length")
    if any(data[count:]):
        raise ValueError("response unused bytes are not zero")
    return {"sequence": words[2], "status_code": words[3], "cpu_slot": slot,
            "gpa": hex(address), "data": data[:count].hex()}


def snapshot_identity(value):
    frame = parse_scan(value)
    words = struct.unpack("<16I", frame)
    if words[0] != 0x50414e53 or words[1] != 0x02000001 or words[6] == 0:
        raise ValueError("no valid boot snapshot")
    return words[2:7]


def execute(openocd, sequence, gpa, length, timeout_ms):
    encode_request(sequence, gpa, length, 1)
    deadline = time.monotonic() + timeout_ms / 1000
    probe = run_commands(openocd, ["irscan xc7.tap 0x03",
        'for {set n 0} {$n < 12} {incr n} {echo "BEFORE:[drscan xc7.tap 512 0]"}',
        ], deadline)
    before = last_identity(probe, "BEFORE")
    packet = scan_hex(encode_request(sequence, gpa, length, before[-1]))
    attempts = min(1000, max(1, int(timeout_ms // 3)))
    # The only instructions are USER2 and USER4; no configuration/programming commands.
    commands = [
        "irscan xc7.tap 0x03",
        'for {set n 0} {$n < 12} {incr n} {echo "BEFORE:[drscan xc7.tap 512 0]"}',
        "irscan xc7.tap 0x23",
        f"set request {packet}",
        "for {set n 0} {$n < " + str(attempts) + "} {incr n} {",
        'set value [drscan xc7.tap 512 $request]',
        'echo "READ:$value"',
        f"if {{[expr 0x[string range $value 104 111]] == {sequence}}} {{break}}",
        "sleep 2", "}",
        "irscan xc7.tap 0x03",
        'for {set n 0} {$n < 12} {incr n} {echo "AFTER:[drscan xc7.tap 512 0]"}',
    ]
    output = run_commands(openocd, commands, deadline)
    records = records_from(output)
    identities = [last_identity(output, prefix) for prefix in ("BEFORE", "AFTER")]
    if before != identities[0] or identities[0] != identities[1]:
        raise ValueError("boot identity changed during read")
    for value in reversed(records["READ"]):
        try:
            response = decode_response(value, sequence, gpa, length)
        except ValueError:
            continue
        if response["status_code"] != 0:
            raise ValueError(f"runtime refusal {response['status_code']}")
        return response["data"], identities[0]
    raise ValueError("read timed out; pending request may still complete")


class OpenOcdSession:
    """One private Tcl RPC pipe; any failed exchange permanently closes the session."""

    def __init__(self, executable):
        self.executable = executable
        self.process = None
        self.closed = False
        self.commands = queue.Queue(maxsize=1)
        self.results = queue.Queue(maxsize=1)
        self.startup_ms = 0.0

    def start(self, deadline):
        if self.closed or self.process is not None:
            raise ValueError("OpenOCD session cannot be restarted")
        if _CHILD_JOB_HANDLE is None:
            raise ValueError("child containment must be established before opening JTAG")
        started = time.monotonic()
        if started >= deadline:
            raise ValueError("startup deadline expired")
        self.process = subprocess.Popen(
            [str(self.executable), "-c", "set bridge_tcl_port pipe",
             "-f", str(Path(__file__).with_name("openocd") / "read_mailbox.cfg")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.worker = threading.Thread(target=self._exchange, daemon=True)
        self.worker.start()
        try:
            if self.command('return "bridge-ready"', deadline) != "bridge-ready":
                raise ValueError("unexpected OpenOCD startup reply")
            self.startup_ms = (time.monotonic() - started) * 1000
        except Exception:
            self.close()
            raise

    def _exchange(self):
        try:
            while True:
                script = self.commands.get()
                if script is None:
                    return
                self.process.stdin.write(script.encode("ascii") + b"\x1a")
                self.process.stdin.flush()
                output = bytearray()
                while True:
                    chunk = self.process.stdout.read1(4096)
                    if not chunk:
                        raise ValueError("OpenOCD RPC disconnected")
                    output.extend(chunk)
                    if len(output) > 262144:
                        raise ValueError("OpenOCD RPC response exceeds bound")
                    if b"\x1a" in chunk:
                        if output[-1:] != b"\x1a" or output.count(b"\x1a") != 1:
                            raise ValueError("unexpected OpenOCD RPC framing")
                        break
                self.results.put(bytes(output[:-1]).decode("ascii"))
        except Exception as error:
            self.results.put(error)

    def command(self, script, deadline):
        if self.closed or self.process is None:
            raise ValueError("OpenOCD session is not open")
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("read deadline expired")
            self.commands.put_nowait(script)
            result = self.results.get(timeout=remaining)
            if isinstance(result, Exception):
                raise result
            if time.monotonic() >= deadline:
                raise ValueError("read deadline expired")
            return result
        except queue.Empty:
            self.close()
            raise ValueError("OpenOCD RPC timeout; pending request may still complete") from None
        except Exception:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=2)
            try:
                self.commands.put_nowait(None)
            except queue.Full:
                pass  # A queued exchange will observe the terminated child.
            self.worker.join(timeout=2)
            self.process.stdin.close()
            self.process.stdout.close()


def run_commands(session, commands, deadline):
    # capture returns echo/log output over the RPC pipe, never over bridge stdout.
    script = "; ".join(commands)
    return session.command("capture {" + script + "}", deadline)


def records_from(output):
    records = {"BEFORE": [], "READ": [], "AFTER": []}
    for line in output.splitlines():
        prefix, separator, value = line.strip().partition(":")
        if separator and prefix in records:
            records[prefix].append(value.strip())
    return records


def last_identity(output, prefix):
    for value in reversed(records_from(output)[prefix]):
        try:
            return snapshot_identity(value)
        except ValueError:
            continue
    raise ValueError("boot identity unavailable")


def serve(openocd):
    session = OpenOcdSession(openocd)
    try:
        return serve_session(session)
    finally:
        session.close()


def serve_session(session):
    sequence = secrets.randbelow(0xffffffff) + 1
    identity = None
    while line := sys.stdin.readline(4097):
        identifier = None
        try:
            if len(line) > 4096:
                raise ValueError("input line exceeds bound")
            request = json.loads(line)
            identifier = request["id"]
            if type(identifier) is not int or not 0 <= identifier < 1 << 64:
                raise ValueError("id must be u64")
            gpa = int(request["gpa"], 0)
            length, timeout_ms = request["length"], request["timeout_ms"]
            if type(length) is not int or type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000:
                raise ValueError("invalid length or deadline")
            encode_request(sequence, gpa, length, 1)
            deadline = time.monotonic() + timeout_ms / 1000
            if session.process is None:
                session.start(deadline)
            started = time.monotonic()
            data, observed = execute(session, sequence, gpa, length,
                                     max(0, (deadline - started) * 1000))
            finished = time.monotonic()
            if finished >= deadline:
                raise ValueError("read deadline expired")
            round_trip_ms = (finished - started) * 1000
            if identity is not None and observed != identity:
                raise ValueError("boot identity changed across requests")
            identity = observed
            reply = {"id": identifier, "status": "complete", "data": data,
                     "startup_ms": session.startup_ms, "round_trip_ms": round_trip_ms}
            sequence = sequence % 0xffffffff + 1
        except (ValueError, TypeError, KeyError, OSError, subprocess.TimeoutExpired) as error:
            reply = {"id": identifier, "status": "error", "error": str(error)}
            print(json.dumps(reply), flush=True)
            # A timeout is not cancellation. Stop this session rather than replace its request.
            return 1
        print(json.dumps(reply), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="explicitly open the JTAG adapter")
    parser.add_argument("--openocd", type=Path)
    parser.add_argument("--encode", help='offline JSON: {"sequence":1,"gpa":"0x100000","length":8,"boot_id":1}')
    parser.add_argument("--decode", help="offline 512-bit response scan hex")
    args = parser.parse_args()
    if args.live:
        if not args.openocd or args.encode or args.decode:
            parser.error("--live requires --openocd and forbids offline modes")
        if not args.openocd.is_file() or args.openocd.suffix.lower() in (".bat", ".cmd", ".ps1"):
            parser.error("--openocd must name the executable directly, not a shell wrapper")
        try:
            establish_child_job()
        except OSError as error:
            parser.error(f"cannot contain bridge children; no hardware opened: {error}")
        return serve(args.openocd)
    if args.openocd:
        parser.error("--openocd requires explicit --live")
    if args.encode and not args.decode:
        request = json.loads(args.encode)
        print(scan_hex(encode_request(request["sequence"], int(request["gpa"], 0), request["length"], request["boot_id"])))
    elif args.decode and not args.encode:
        print(json.dumps(decode_response(args.decode)))
    else:
        parser.error("choose offline --encode or --decode, or explicitly enable --live")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
