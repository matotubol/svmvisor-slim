"""Offline protocol and stdio tests. No USB adapter is opened."""
import io
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import struct
import subprocess
import queue
import sys
import tkinter
import threading
import time
import unittest
from unittest.mock import patch
import zlib

import read_bridge as bridge


def response(sequence=1, status=0, count=8, address=0x100000, tail=0):
    body = struct.pack("<15I", bridge.RESPONSE_MAGIC, 1, sequence, status, count,
                       address, 0, 0x04030201, 0x08070605, 0, 0, 0, 0, 0, tail)
    return bridge.scan_hex(body + struct.pack("<I", zlib.crc32(body)))


def snapshot(boot_id):
    body = struct.pack("<15I", 0x50414e53, 0x02000001, 1, 2, 3, 4, boot_id, *([0] * 8))
    return bridge.scan_hex(body + struct.pack("<I", zlib.crc32(body)))


class ReadBridgeTests(unittest.TestCase):
    def test_containment_failure_precedes_serve_and_hardware(self):
        with patch.object(sys, "argv", ["read_bridge.py", "--live", "--openocd", sys.executable]), \
             patch.object(bridge, "establish_child_job", side_effect=OSError("test refusal")), \
             patch.object(bridge, "serve") as serve, patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                bridge.main()
        serve.assert_not_called()
        with patch.object(bridge, "_CHILD_JOB_HANDLE", None), patch.object(subprocess, "Popen") as run:
            with self.assertRaisesRegex(ValueError, "containment"):
                bridge.OpenOcdSession(Path("unused")).start(time.monotonic() + 1)
        run.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows process-lifetime test")
    def test_killing_contained_parent_terminates_harmless_child(self):
        # A separate Python joins the job; the test runner, Codex and xtask never join it.
        script = ("import read_bridge, subprocess, sys, time; "
                  "read_bridge.establish_child_job(); "
                  "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
                  "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                  "print(child.pid, flush=True); time.sleep(60)")
        parent = subprocess.Popen([sys.executable, "-c", script], cwd=Path(bridge.__file__).parent,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        lines = queue.Queue(maxsize=1)
        threading.Thread(target=lambda: lines.put(parent.stdout.readline()), daemon=True).start()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        child = None
        try:
            line = lines.get(timeout=5)
            self.assertTrue(line.strip().isdigit(), "contained parent did not report its child PID")
            child = kernel.OpenProcess(0x00100001, False, int(line))  # SYNCHRONIZE | TERMINATE
            self.assertTrue(child, "cannot open handle to the test's own live child")
            self.assertEqual(kernel.WaitForSingleObject(child, 0), 258)  # WAIT_TIMEOUT
            parent.kill()
            parent.wait(timeout=5)
            self.assertEqual(kernel.WaitForSingleObject(child, 5000), 0)  # WAIT_OBJECT_0
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)
            parent.stdout.close()
            parent.stderr.close()
            if child:
                if kernel.WaitForSingleObject(child, 0) == 258:
                    # Cleanup only the harmless child handle created by this test if it failed.
                    kernel.TerminateProcess(child, 1)
                    kernel.WaitForSingleObject(child, 5000)
                kernel.CloseHandle(child)

    def test_request_shape_and_crc(self):
        frame = bridge.encode_request(7, 0x123456000, 32, 99)
        words = struct.unpack("<16I", frame)
        self.assertEqual(words[:8], (bridge.REQUEST_MAGIC, 1, 7, 1, 32, 0x23456000, 1, 99))
        self.assertEqual(words[8:15], (0,) * 7)
        self.assertEqual(bridge.parse_scan(bridge.scan_hex(frame)), frame)
        for address, count in [(0xfffff, 1), (0x100fff, 2), (0x100000, 0), (0x100000, 33)]:
            with self.assertRaises(ValueError):
                bridge.encode_request(1, address, count, 99)
        for sequence, address, count, boot in [(True, 0x100000, 1, 1), (1, 0x100000, 1.5, 1),
                                                (1, "0x100000", 1, 1), (1, 0x100000, 1, 0)]:
            with self.assertRaises(ValueError):
                bridge.encode_request(sequence, address, count, boot)

    def test_response_requires_matching_complete_nonleaking_frame(self):
        decoded = bridge.decode_response(response(), 1, 0x100000, 8)
        self.assertEqual(decoded["data"], "0102030405060708")
        for value, sequence, address, length in [
            (response(sequence=2), 1, 0x100000, 8),
            (response(address=0x200000), 1, 0x100000, 8),
            (response(), 1, 0x100000, 16),
            (response(status=1), 1, 0x100000, 8),
            (response(status=7, count=0), 1, 0x100000, 8),
            (response(tail=1), 1, 0x100000, 8),
            (response()[:-1] + "f", 1, 0x100000, 8),
        ]:
            with self.assertRaises(ValueError):
                bridge.decode_response(value, sequence, address, length)

    def test_stdio_preserves_ids_and_stops_on_timeout(self):
        requests = "\n".join(json.dumps({"id": identifier, "gpa": "0x100000", "length": 8,
                                      "timeout_ms": 1000}) for identifier in (4, 5, 6)) + "\n"
        output = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO(requests)), patch.object(sys, "stdout", output), \
             patch.object(bridge.OpenOcdSession, "start"), \
             patch.object(bridge, "execute", side_effect=[("0102030405060708", (1, 2, 3, 4, 5)),
                                                          ValueError("timeout")]) as execute:
            self.assertEqual(bridge.serve(Path("unused")), 1)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([item["id"] for item in replies], [4, 5])
        self.assertEqual([item["status"] for item in replies], ["complete", "error"])
        self.assertEqual(execute.call_count, 2)

    def test_live_command_builder_binds_boot_and_rejects_boot_change_without_hardware(self):
        probe = "BEFORE:" + snapshot(99)
        output = "\n".join([probe, "READ:" + response(), "AFTER:" + snapshot(99)])
        with patch.object(bridge, "run_commands", side_effect=[probe, output]) as run:
            data, identity = bridge.execute(Path("unused"), 1, 0x100000, 8, 1000)
        self.assertEqual(data, "0102030405060708")
        self.assertEqual(identity[-1], 99)
        commands = run.call_args_list[1].args[1]
        encoded = next(command.split(" ", 2)[2] for command in commands if command.startswith("set request "))
        self.assertEqual(bridge.parse_scan(encoded), bridge.encode_request(1, 0x100000, 8, 99))
        changed = output.replace("AFTER:" + snapshot(99), "AFTER:" + snapshot(100))
        with patch.object(bridge, "run_commands", side_effect=[probe, changed]):
            with self.assertRaisesRegex(ValueError, "boot identity changed"):
                bridge.execute(Path("unused"), 1, 0x100000, 8, 1000)

    def test_generated_scan_commands_execute_in_offline_tcl(self):
        # Exercise the actual generated Tcl with inert command replacements, no OpenOCD.
        scans = []

        def emulate(_executable, commands, _deadline):
            interpreter = tkinter.Tcl()
            selected = [None]
            output = []
            interpreter.createcommand("irscan", lambda _tap, instruction: selected.__setitem__(0, instruction))

            def scan(_tap, _bits, value):
                if selected[0] == "0x03":
                    return snapshot(99)[2:]
                scans.append(value)
                return response()[2:]

            interpreter.createcommand("drscan", scan)
            interpreter.createcommand("echo", lambda value: output.append(value))
            interpreter.createcommand("sleep", lambda _delay: None)
            interpreter.createcommand("shutdown", lambda: None)
            interpreter.eval("; ".join(commands))
            return "\n".join(output)

        with patch.object(bridge, "run_commands", side_effect=emulate):
            data, _identity = bridge.execute(Path("unused"), 1, 0x100000, 8, 1000)
        self.assertEqual(data, "0102030405060708")
        self.assertEqual(len(scans), 1)
        self.assertEqual(bridge.parse_scan(scans[0]), bridge.encode_request(1, 0x100000, 8, 99))


    def fake_session(self, replies, delay=0):
        # Real anonymous pipes and a real harmless child, without OpenOCD or USB.
        script = ("import sys,time; replies=" + repr(replies) + "; delay=" + repr(delay) + "\n"
                  "for reply in replies:\n"
                  " data=bytearray()\n"
                  " while not data.endswith(b'\\x1a'):\n"
                  "  chunk=sys.stdin.buffer.read(1)\n"
                  "  if not chunk: sys.exit(0)\n"
                  "  data.extend(chunk)\n"
                  " if reply is None: time.sleep(delay); continue\n"
                  " if reply == 'DISCONNECT': sys.exit(0)\n"
                  " if reply == 'OVERSIZED': reply = 'x' * 262145\n"
                  " for byte in reply.encode('ascii')+b'\\x1a':\n"
                  "  sys.stdout.buffer.write(bytes([byte])); sys.stdout.buffer.flush()\n"
                  "time.sleep(30)\n")
        launch = subprocess.Popen
        def spawn(*args, **kwargs):
            return launch([sys.executable, "-u", "-c", script], **kwargs)
        return patch.object(subprocess, "Popen", side_effect=spawn)

    def test_persistent_pipe_reuses_one_process_for_multiple_reads(self):
        probe = "BEFORE:" + snapshot(99)
        replies = ["bridge-ready"]
        for sequence in (1, 2):
            replies += [probe, probe + "\nREAD:" + response(sequence=sequence)
                        + "\nAFTER:" + snapshot(99)]
        requests = "".join(json.dumps(dict(id=i, gpa="0x100000", length=8,
                                         timeout_ms=2000)) + "\n" for i in (1, 2))
        output = io.StringIO()
        with self.fake_session(replies) as spawn, \
             patch.object(bridge, "_CHILD_JOB_HANDLE", 1), \
             patch.object(bridge.secrets, "randbelow", return_value=0), \
             patch.object(sys, "stdin", io.StringIO(requests)), \
             patch.object(sys, "stdout", output):
            self.assertEqual(bridge.serve(Path("unused")), 0)
        self.assertEqual(spawn.call_count, 1)
        results = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([r["status"] for r in results], ["complete", "complete"])
        self.assertEqual(results[0]["startup_ms"], results[1]["startup_ms"])
        self.assertGreater(results[0]["startup_ms"], 0)
        self.assertTrue(all(r["round_trip_ms"] > 0 for r in results))

    def test_rpc_timeout_kills_child_and_permanently_stops_session(self):
        with self.fake_session(["bridge-ready", None], delay=30), \
             patch.object(bridge, "_CHILD_JOB_HANDLE", 1):
            session = bridge.OpenOcdSession(Path("unused"))
            try:
                session.start(time.monotonic() + 2)
                with self.assertRaisesRegex(ValueError, "timeout"):
                    session.command("pending", time.monotonic() + .05)
                self.assertIsNotNone(session.process.poll())
                with self.assertRaisesRegex(ValueError, "not open"):
                    session.command("replacement", time.monotonic() + 1)
                with self.assertRaisesRegex(ValueError, "cannot be restarted"):
                    session.start(time.monotonic() + 1)
            finally:
                session.close()

    def test_rpc_disconnect_and_oversized_reply_fail_stop(self):
        for reply, expected in (("DISCONNECT", "disconnected"), ("OVERSIZED", "exceeds bound")):
            with self.subTest(expected=expected), \
                 self.fake_session(["bridge-ready", reply]), \
                 patch.object(bridge, "_CHILD_JOB_HANDLE", 1):
                session = bridge.OpenOcdSession(Path("unused"))
                try:
                    session.start(time.monotonic() + 2)
                    with self.assertRaisesRegex(ValueError, expected):
                        session.command("read", time.monotonic() + 10)
                    self.assertTrue(session.closed)
                    self.assertIsNotNone(session.process.poll())
                finally:
                    session.close()

    def test_rpc_startup_is_bounded_and_cleanup_is_idempotent(self):
        with self.fake_session([None], delay=30), \
             patch.object(bridge, "_CHILD_JOB_HANDLE", 1):
            session = bridge.OpenOcdSession(Path("unused"))
            with self.assertRaisesRegex(ValueError, "timeout"):
                session.start(time.monotonic() + .1)
            self.assertIsNotNone(session.process.poll())
            session.close()

    @unittest.skipUnless(os.environ.get("OPENOCD_OFFLINE_TEST"), "optional pinned OpenOCD RPC check")
    def test_real_openocd_rpc_without_adapter_initialization(self):
        launch = subprocess.Popen
        def spawn(*args, **kwargs):
            # noinit skips ALL adapter/target initialization. Scans are inert Tcl procedures.
            script = ('noinit; tcl_port pipe; gdb_port disabled; telnet_port disabled; '
                      'proc irscan {tap value} {global selected; set selected $value}; '
                      'proc drscan {tap bits value} {global selected; '
                      'if {$selected == "0x03"} {return ' + snapshot(99)[2:] + '}; '
                      'return ' + response()[2:] + '}')
            return launch([os.environ["OPENOCD_OFFLINE_TEST"], "-c", script], **kwargs)
        with patch.object(subprocess, "Popen", side_effect=spawn) as started, \
             patch.object(bridge, "_CHILD_JOB_HANDLE", 1):
            session = bridge.OpenOcdSession(Path("unused"))
            try:
                session.start(time.monotonic() + 2)
                for _ in range(2):
                    data, identity = bridge.execute(session, 1, 0x100000, 8, 2000)
                    self.assertEqual(data, "0102030405060708")
                    self.assertEqual(identity[-1], 99)
                self.assertEqual(started.call_count, 1)
            finally:
                session.close()

    def test_invalid_or_stale_completion_cannot_succeed(self):
        probe = "BEFORE:" + snapshot(99)
        for value in (response(sequence=2), response()[:-1] + "f",
                      response(address=0x200000), response(count=4)):
            output = probe + "\nREAD:" + value + "\nAFTER:" + snapshot(99)
            with self.subTest(value=value), \
                 patch.object(bridge, "run_commands", side_effect=[probe, output]):
                with self.assertRaisesRegex(ValueError, "timed out"):
                    bridge.execute(Path("unused"), 1, 0x100000, 8, 1000)

    def test_default_offline_mode_does_not_start_openocd(self):
        request = json.dumps({"sequence": 1, "gpa": "0x100000", "length": 8, "boot_id": 99})
        result = subprocess.run([sys.executable, str(Path(bridge.__file__)), "--encode", request],
                                capture_output=True, text=True, check=True)
        self.assertEqual(bridge.parse_scan(result.stdout), bridge.encode_request(1, 0x100000, 8, 99))
        refused = subprocess.run([sys.executable, str(Path(bridge.__file__)), "--openocd", "missing"],
                                 capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)


if __name__ == "__main__":
    unittest.main()
