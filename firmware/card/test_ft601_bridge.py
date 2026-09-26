"""Offline FT601 framing and poisoned-session tests; no DLL or USB device is opened."""
import io
import json
from pathlib import Path
import queue
import struct
import sys
import time
import unittest
from unittest.mock import patch
import zlib

import ft601_bridge as bridge
from read_bridge import RESPONSE_MAGIC, decode_response, encode_request, scan_hex


def frame(words):
    body = struct.pack("<15I", *words)
    return body + struct.pack("<I", zlib.crc32(body))


def snapshot(boot=5):
    return frame([0x50414e53, 0x02000001, 1, 2, 3, 4, boot] + [0] * 8)


def response(sequence, address, payload, status=0):
    data = payload.ljust(32, b"\0")
    return frame([RESPONSE_MAGIC, 1, sequence, status, len(payload),
                  address & 0xffffffff, address >> 32] + list(struct.unpack("<8I", data)))


class Transport:
    def __init__(self, fragment=128):
        self.fragment = fragment
        self.writes, self.closed, self.buffer = [], False, b""
        self.boot = 5
        self.identities = 0
        self.change_after = None
        self.mutate = lambda data: data

    def write(self, data, deadline):
        self.writes.append(data)
        words = struct.unpack("<16I", data)
        sequence, operation = words[2:4]
        if operation == 2:
            self.identities += 1
            boot = self.boot + (self.change_after is not None and self.identities >= self.change_after)
            identity = snapshot(boot)
            result = response(sequence, 0, identity[:32]) + response(sequence, 32, identity[32:])
        else:
            result = response(sequence, words[5] | words[6] << 32, bytes(range(words[4])))
        self.buffer = self.mutate(result)

    def read(self, length, deadline):
        count = min(length, self.fragment)
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def close(self):
        self.closed = True


class Ft601BridgeTests(unittest.TestCase):
    def test_shared_wire_vectors(self):
        lines = (Path(__file__).parent / "tests/ft601_wire_vectors.mem").read_text().splitlines()
        words = [int(line, 16) for line in lines if line.strip() and not line.startswith("//")]
        self.assertEqual(len(words), 96)
        records = [struct.pack("<16I", *words[offset:offset + 16]) for offset in range(0, 96, 16)]
        self.assertEqual(encode_request(0x10203040, 0x12345000, 32, 0xa1b2c3d4), records[0])
        self.assertEqual(bridge.encode_identity(0x10203041), records[2])
        self.assertEqual(decode_response(scan_hex(records[1]), 0x10203040, 0x12345000, 32)["data"],
                         bytes(range(32)).hex())
        self.assertEqual(bridge.decode_identity(records[4] + records[5], 0x10203041),
                         (0x55667788, 0x11223344, 0x44332211, 0x88776655, 0xa1b2c3d4))

    def test_fragmented_frames_share_transport_and_increment_every_operation(self):
        transport = Transport(fragment=7)
        session = bridge.Session(transport, sequence=10)
        self.assertEqual(session.sample(0x100000, 32, 1000), bytes(range(32)).hex())
        self.assertEqual(session.sample(0x200000, 8, 1000), bytes(range(8)).hex())
        self.assertEqual([struct.unpack("<16I", value)[2] for value in transport.writes], list(range(10, 16)))
        self.assertEqual([struct.unpack("<16I", value)[3] for value in transport.writes], [2, 1, 2] * 2)
        self.assertFalse(transport.closed)

    def test_driver_reads_remain_inside_each_64_byte_record(self):
        for fragment in (7, 64, 128):
            transport = Transport(fragment=fragment)
            original = transport.read
            def read(length, deadline):
                remaining = len(transport.buffer) % 64 or 64
                self.assertEqual(length, remaining)
                return original(length, deadline)
            transport.read = read
            session = bridge.Session(transport, sequence=10)
            self.assertEqual(session.sample(0x100000, 8, 1000), bytes(range(8)).hex())
            session.close()

    def test_identity_change_before_or_after_read_poison_session(self):
        for change_after in (2, 3):
            with self.subTest(change_after=change_after):
                transport = Transport()
                transport.change_after = change_after
                session = bridge.Session(transport, sequence=10)
                if change_after == 3:
                    session.sample(0x100000, 32, 1000)
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    session.sample(0x100000, 32, 1000)
                count = len(transport.writes)
                with self.assertRaisesRegex(ValueError, "closed"):
                    session.sample(0x100000, 32, 1000)
                self.assertEqual(len(transport.writes), count)
                self.assertTrue(transport.closed)

    def test_bad_crc_reordered_halves_stale_sequence_and_inner_crc_rejected(self):
        def stale(data):
            words = list(struct.unpack("<16I", data[:64]))
            words[2] += 1
            return frame(words[:15]) + data[64:]
        def bad_inner(data):
            words = list(struct.unpack("<16I", data[64:]))
            words[14] ^= 1  # Snapshot CRC, with valid outer CRC.
            return data[:64] + frame(words[:15])
        mutations = (lambda data: bytes([data[0] ^ 1]) + data[1:],
                     lambda data: data[64:] + data[:64], stale, bad_inner)
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                transport = Transport()
                transport.mutate = mutate
                session = bridge.Session(transport, sequence=10)
                with self.assertRaises(ValueError):
                    session.sample(0x100000, 32, 1000)
                self.assertTrue(session.closed)
                self.assertEqual(len(transport.writes), 1)

    def test_incomplete_response_and_write_failure_close_without_retry(self):
        for action in ("read", "write"):
            transport = Transport()
            session = bridge.Session(transport)
            with patch.object(transport, action, side_effect=OSError("test failure")):
                with self.assertRaises(OSError):
                    session.sample(0x100000, 32, 1000)
            self.assertTrue(transport.closed)
            self.assertLessEqual(len(transport.writes), 1)
        transport = Transport()
        transport.mutate = lambda data: data[:10]
        with self.assertRaisesRegex(ValueError, "fragment"):
            bridge.Session(transport).sample(0x100000, 32, 1000)
        self.assertTrue(transport.closed)

    def test_sequence_exhaustion_never_wraps(self):
        transport = Transport()
        session = bridge.Session(transport, sequence=0xffffffff)
        with self.assertRaisesRegex(ValueError, "exhausted"):
            session.sample(0x100000, 32, 1000)
        self.assertEqual(len(transport.writes), 1)
        self.assertTrue(session.closed)

    def test_physical_corruption_and_refusal_do_not_trigger_another_identity_request(self):
        for failure in ("crc", "sequence", "address", "status", "timeout"):
            with self.subTest(failure=failure):
                transport = Transport()
                original = transport.write
                def write(data, deadline):
                    words = struct.unpack("<16I", data)
                    if words[3] != 1:
                        return original(data, deadline)
                    if failure == "timeout":
                        raise TimeoutError("driver timed out")
                    original(data, deadline)
                    values = list(struct.unpack("<16I", transport.buffer))
                    if failure == "crc":
                        transport.buffer = transport.buffer[:-1] + bytes([transport.buffer[-1] ^ 1])
                        return
                    if failure == "sequence":
                        values[2] += 1
                    elif failure == "address":
                        values[5] += 1
                    else:
                        values[3], values[4] = 2, 0
                        values[7:15] = [0] * 8
                    transport.buffer = frame(values[:15])
                transport.write = write
                session = bridge.Session(transport, sequence=10)
                with self.assertRaises((ValueError, TimeoutError)):
                    session.sample(0x100000, 32, 1000)
                self.assertTrue(session.closed)
                self.assertEqual(transport.identities, 1)

    def test_deadline_is_shared_by_every_operation(self):
        transport = Transport()
        session = bridge.Session(transport)
        with patch.object(bridge.time, "monotonic", side_effect=[10, 10, 10, 11]):
            with self.assertRaises(TimeoutError):
                session.sample(0x100000, 32, 500)
        self.assertTrue(session.closed)
        self.assertEqual(len(transport.writes), 1)

    def test_stdio_compatible_reply_and_terminal_invalid_input(self):
        transport = Transport()
        source = io.StringIO(json.dumps(dict(id=4, gpa="0x100000", length=8, timeout_ms=1000)) + "\n")
        output = io.StringIO()
        self.assertEqual(bridge.serve(bridge.Session(transport), source, output), 0)
        result = json.loads(output.getvalue())
        self.assertEqual((result["id"], result["status"], result["data"]), (4, "complete", bytes(range(8)).hex()))
        self.assertTrue(transport.closed)
        for line in ("{}\n", "[]\n", "x" * 4097, '{"id":true}\n', "{}"):
            transport = Transport()
            output = io.StringIO()
            self.assertEqual(bridge.serve(bridge.Session(transport), io.StringIO(line), output), 1)
            self.assertTrue(transport.closed)
            self.assertFalse(transport.writes)


class WorkerTests(unittest.TestCase):
    def command(self, body):
        return [sys.executable, "-B", "-c", body]

    def test_ready_or_read_reply_received_at_deadline_is_rejected(self):
        for reply in ({"status": "ready"}, {"id": 1, "status": "complete", "data": "01"}):
            worker = bridge.Worker.__new__(bridge.Worker)
            worker.replies = queue.Queue()
            worker.replies.put(reply)
            with patch.object(bridge.time, "monotonic", side_effect=[10, 11]):
                with self.assertRaises(TimeoutError):
                    worker._reply(11)

    def test_startup_hang_is_bounded_without_a_driver(self):
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            bridge.Worker(self.command("import time; time.sleep(30)"),
                          startup_timeout_ms=200, cleanup_seconds=.3)
        self.assertLess(time.monotonic() - started, 3)

    def test_read_hang_kills_child_and_closes_session(self):
        body = 'import time; print(\'{"status":"ready"}\', flush=True); time.sleep(30)'
        worker = bridge.Worker(self.command(body), cleanup_seconds=.3)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            worker.sample(0x100000, 8, 100)
        self.assertTrue(worker.closed)
        self.assertIsNotNone(worker.process.poll())
        self.assertLess(time.monotonic() - started, 3)

    def test_cleanup_hang_does_not_stall_parent(self):
        body = 'import sys,time; print(\'{"status":"ready"}\', flush=True); sys.stdin.read(); time.sleep(30)'
        worker = bridge.Worker(self.command(body), cleanup_seconds=.2)
        started = time.monotonic()
        worker.close()
        self.assertTrue(worker.closed)
        self.assertIsNotNone(worker.process.poll())
        self.assertLess(time.monotonic() - started, 3)

    def test_successful_child_protocol(self):
        body = ('import sys,json; print(\'{"status":"ready"}\',flush=True); '
                'r=json.loads(sys.stdin.readline()); '
                'print(json.dumps(dict(id=r["id"],status="complete",data="01"*r["length"])),flush=True); '
                'sys.stdin.read()')
        worker = bridge.Worker(self.command(body), cleanup_seconds=.3)
        self.assertEqual(worker.sample(0x100000, 8, 1000), "01" * 8)
        worker.close()
        self.assertEqual(worker.process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
