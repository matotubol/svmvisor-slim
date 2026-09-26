"""Opt-in FT601 transport for the existing bounded physical read mailbox."""
import argparse
import json
from pathlib import Path
import queue
import secrets
import struct
import subprocess
import sys
import threading
import time
import zlib

from ft601_d3xx import D3xx
from read_bridge import (REQUEST_MAGIC, decode_response, encode_request, scan_hex,
                         snapshot_identity, establish_child_job)


def encode_identity(sequence):
    if type(sequence) is not int or not 0 < sequence <= 0xffffffff:
        raise ValueError("sequence must be nonzero u32")
    body = struct.pack("<15I", REQUEST_MAGIC, 1, sequence, 2, *([0] * 11))
    return body + struct.pack("<I", zlib.crc32(body))


def decode_identity(reply, sequence):
    if len(reply) != 128:
        raise ValueError("identity reply must contain two complete records")
    snapshot = bytearray()
    for index in range(2):
        record = decode_response(scan_hex(reply[index * 64:(index + 1) * 64]),
                                 sequence, index * 32, 32)
        if record["status_code"] != 0 or record["cpu_slot"] != 0:
            raise ValueError("FT601 identity operation refused")
        snapshot.extend(bytes.fromhex(record["data"]))
    return snapshot_identity(scan_hex(snapshot))


class Session:
    """Fixed frames, one outstanding operation, permanently closed after any error."""
    def __init__(self, transport, *, sequence=None):
        self.transport = transport
        self.sequence = sequence if sequence is not None else secrets.randbelow(0xffffff00) + 1
        if type(self.sequence) is not int or not 0 < self.sequence <= 0xffffffff:
            raise ValueError("invalid initial FT601 sequence")
        self.identity = None
        self.closed = False

    def _next(self):
        if self.closed:
            raise ValueError("FT601 session is closed")
        if self.sequence > 0xffffffff:
            raise ValueError("FT601 sequence exhausted; no wrap is permitted")
        sequence = self.sequence
        self.sequence += 1
        return sequence

    def _exchange(self, request, length, deadline):
        if time.monotonic() >= deadline:
            raise TimeoutError("FT601 transaction deadline expired")
        self.transport.write(request, deadline)
        result = bytearray()
        while len(result) < length:
            if time.monotonic() >= deadline:
                raise TimeoutError("FT601 transaction deadline expired")
            # Each FPGA FIFO transaction contains one 64-byte response record.
            # Keep driver sessions inside that boundary, including short fragments.
            count = min(64 - len(result) % 64, length - len(result))
            chunk = self.transport.read(count, deadline)
            if not isinstance(chunk, bytes) or not 0 < len(chunk) <= count:
                raise ValueError("invalid FT601 response fragment")
            result.extend(chunk)
        if time.monotonic() >= deadline:
            raise TimeoutError("FT601 transaction deadline expired")
        return bytes(result)

    def _identity(self, deadline):
        sequence = self._next()
        reply = self._exchange(encode_identity(sequence), 128, deadline)
        return decode_identity(reply, sequence)

    def sample(self, gpa, length, timeout_ms):
        try:
            if self.closed:
                raise ValueError("FT601 session is closed")
            if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000:
                raise ValueError("timeout must be 1..60000 milliseconds")
            encode_request(1, gpa, length, 1)
            deadline = time.monotonic() + timeout_ms / 1000
            before = self._identity(deadline)
            if self.identity is not None and before != self.identity:
                raise ValueError("boot identity changed across FT601 requests")
            self.identity = before
            sequence = self._next()
            request = encode_request(sequence, gpa, length, before[-1])
            raw = self._exchange(request, 64, deadline)
            reply = decode_response(scan_hex(raw), sequence, gpa, length)
            if reply["status_code"] != 0:
                raise ValueError(f"runtime refusal {reply['status_code']}")
            after = self._identity(deadline)
            if after != before:
                raise ValueError("boot identity changed during FT601 read; bytes discarded")
            return reply["data"]
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.closed:
            self.closed = True
            self.transport.close()


class Worker:
    """Supervise the DLL in a disposable process, including create/read/close hangs."""
    def __init__(self, command, *, startup_timeout_ms=10000, cleanup_seconds=1):
        self.closed, self.identifier = False, 0
        self.cleanup_seconds = cleanup_seconds
        self.replies = queue.Queue(maxsize=1)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=None, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.thread = threading.Thread(target=self._receive, daemon=True)
        self.thread.start()
        try:
            if self._reply(time.monotonic() + startup_timeout_ms / 1000) != {"status": "ready"}:
                raise ValueError("FT601 driver worker did not become ready")
        except BaseException:
            self.close(force=True)
            raise

    def _receive(self):
        try:
            while line := self.process.stdout.readline(4097):
                if len(line) > 4096 or not line.endswith(b"\n"):
                    raise ValueError("invalid driver-worker response framing")
                self.replies.put(json.loads(line))
            raise OSError("FT601 driver worker disconnected")
        except Exception as error:
            self.replies.put(error)

    def _reply(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("FT601 driver worker deadline expired")
        try:
            reply = self.replies.get(timeout=remaining)
        except queue.Empty as error:
            raise TimeoutError("FT601 driver worker deadline expired") from error
        if time.monotonic() >= deadline:
            raise TimeoutError("FT601 driver worker deadline expired")
        if isinstance(reply, Exception):
            raise reply
        return reply

    def sample(self, gpa, length, timeout_ms):
        try:
            if self.closed:
                raise ValueError("FT601 worker session is closed")
            encode_request(1, gpa, length, 1)
            if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000:
                raise ValueError("timeout must be 1..60000 milliseconds")
            self.identifier += 1
            deadline = time.monotonic() + timeout_ms / 1000
            request = dict(id=self.identifier, gpa=hex(gpa), length=length, timeout_ms=timeout_ms)
            self.process.stdin.write(json.dumps(request).encode("ascii") + b"\n")
            self.process.stdin.flush()
            reply = self._reply(deadline)
            if not isinstance(reply, dict) or type(reply.get("id")) is not int or reply["id"] != self.identifier:
                raise ValueError("driver-worker response identity mismatch")
            if reply.get("status") != "complete":
                raise ValueError(f"driver-worker read failed: {reply.get('error', 'invalid reply')}")
            data = reply.get("data")
            if not isinstance(data, str) or len(data) != length * 2 or any(c not in "0123456789abcdef" for c in data):
                raise ValueError("invalid driver-worker response bytes")
            return data
        except BaseException:
            self.close(force=True)
            raise

    def close(self, *, force=False):
        if self.closed:
            return
        self.closed = True
        if not force:
            try:
                self.process.stdin.close()
                self.process.wait(timeout=self.cleanup_seconds)
            except (OSError, subprocess.TimeoutExpired):
                force = True
        if force and self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=self.cleanup_seconds)
        except subprocess.TimeoutExpired:
            pass  # Do not wait forever even if the OS cannot reap a stuck driver call.
        if not self.process.stdin.closed:
            self.process.stdin.close()
        self.thread.join(timeout=self.cleanup_seconds)
        if not self.thread.is_alive():
            self.process.stdout.close()


def serve(session, source=sys.stdin, destination=sys.stdout, *, startup_ms=0.0):
    while line := source.readline(4097):
        identifier = None
        try:
            if len(line) > 4096 or not line.endswith("\n"):
                raise ValueError("input must be one bounded newline-terminated JSON request")
            request = json.loads(line)
            if not isinstance(request, dict) or set(request) != {"id", "gpa", "length", "timeout_ms"}:
                raise ValueError("expected id, gpa, length, timeout_ms fields")
            identifier = request["id"]
            if type(identifier) is not int or not 0 <= identifier < 1 << 64:
                raise ValueError("id must be u64")
            if not isinstance(request["gpa"], str):
                raise ValueError("gpa must be an address string")
            gpa = int(request["gpa"], 0)
            started = time.monotonic()
            data = session.sample(gpa, request["length"], request["timeout_ms"])
            reply = dict(id=identifier, status="complete", data=data, startup_ms=startup_ms,
                         round_trip_ms=(time.monotonic() - started) * 1000)
            print(json.dumps(reply), file=destination, flush=True)
        except (ValueError, TypeError, KeyError, OSError) as error:
            session.close()
            print(json.dumps(dict(id=identifier, status="error", error=str(error))),
                  file=destination, flush=True)
            return 1
    session.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--serial")
    parser.add_argument("--dll", type=Path)
    parser.add_argument("--dll-sha256")
    parser.add_argument("--driver-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--encode-identity", type=lambda value: int(value, 0))
    args = parser.parse_args()
    if args.encode_identity is not None:
        if args.live:
            parser.error("offline encoding cannot be combined with --live")
        print(encode_identity(args.encode_identity).hex())
        return 0
    if not args.live or not all((args.serial, args.dll, args.dll_sha256)):
        parser.error("--live, --serial, --dll and --dll-sha256 are required")
    started = time.monotonic()
    with_session = None
    try:
        if args.driver_worker:
            with_session = Session(D3xx(args.dll, args.dll_sha256, args.serial))
            print(json.dumps(dict(status="ready")), flush=True)
        else:
            establish_child_job()
            command = [sys.executable, "-B", str(Path(__file__).resolve()), "--live",
                       "--driver-worker", "--serial", args.serial, "--dll", str(args.dll),
                       "--dll-sha256", args.dll_sha256]
            with_session = Worker(command)
        return serve(with_session, startup_ms=(time.monotonic() - started) * 1000)
    finally:
        if with_session is not None:
            with_session.close()


if __name__ == "__main__":
    raise SystemExit(main())
