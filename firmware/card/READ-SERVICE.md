# USER4 diagnostic read channel

**Retired runtime interface:** the current resident no longer polls or services this
physical-read mailbox. This document and its codecs/RTL tests describe the older
external transport. Same-PC reads now use [VMMCALL batches](../../LOCAL-READ.md).
JTAG flashing and crash snapshots remain supported independently.

This document describes the USER4 mailbox implemented in the separate firmware worktree.
The host tools in this checkout require an already compatible FPGA and runtime build;
adding these tools does not update the firmware sources, program the card, or establish
which build is currently running. Earlier USER2/USER3-only builds cannot accept these requests.

The external caller submits one request over JTAG. The monitor services it only when a suitable
VM exit already occurs, using its admitted physical reader. The card originates no PCIe request,
DMA transfer or interrupt. The existing completion-only TX guard remains the sole user TX source.
No Windows client, memory hook, guest output buffer or new exit trigger is part of this channel.
There is no completion deadline when the guest generates no suitable exits.

`crates/card-abi/src/read_service.rs` owns the semantic ABI. Each 512-bit frame is sixteen
little-endian DWORDs, scanned least-significant bit first. Word 15 is CRC32 of the first 60 bytes.
CRC detects corruption; it does not authenticate the caller or establish process identity.

| Word | Request | Response |
|---|---|---|
| 0 | `0x51525653` | `0x50525653` |
| 1 | version 1 | version 1 |
| 2 | nonzero request sequence | matching sequence |
| 3 | operation 1: physical observation | status, zero means complete |
| 4 | length 1–32 bytes | length in bits 15:0, CPU slot in bits 31:16 |
| 5–6 | GPA, low DWORD first | echoed GPA |
| 7 | nonzero current boot ID | first four output bytes |
| 8–14 | zero | remaining output bytes |
| 15 | CRC32 | CRC32 |

Successful responses contain exactly the requested fragment; unused bytes are zero. Refusals
contain no source bytes. A physical observation does not prove which process owns a page, hold
the page alive, or promise coherent process structures. The runtime independently checks boot
identity, request shape, owned NPT translation, RAM/cache admission and monitor exclusion.

BAR0 `0x500..0x53f` contains the immutable active request. `0x540..0x57f` accepts sixteen response
staging DWORDs and reads the most recently committed response. Writing the matching sequence to
`0x580` starts CRC validation over a latched candidate. `0x584` reads capability `0x31525653`,
`0x588` reads the active request sequence (zero when idle), and `0x58c` reads the published response
sequence. Response writes are ignored during candidate validation. Partial, mismatched and
bad-CRC responses cannot replace committed output. Runtime use requires the existing endpoint
lifetime guard and route/identity/cache validation; numerical BAR addresses alone are insufficient.

The compatible minimal runtime pauses endpoint access while any CPU has an open
configuration-write window. At that CPU's next exit it restores protection before allowing
service again. This adds PCI configuration exits and retains a fixed-BAR, first-boot platform
contract. That runtime implementation is maintained separately from this host-tool integration.

USER4 receives only complete CRC-checked frames through an acknowledged clock-domain crossing.
An occupied slot cannot be replaced. The completed sequence is remembered to suppress immediate
request replay. PCIe reset cancels response staging, preserving the active request and published
response. Capture-DR freezes one complete response for its entire scan. Repeated scans advance
the CDC handshakes; a single scan need not immediately deliver a response. No clock means no
progress. USER4 instruction `0x23` follows the 7-series USER4 encoding; the installed AMD Artix-7
BSDL opcode table also records `USER4 (100011)`.

`read_bridge.py` defaults to offline codecs. For example:

```powershell
python -B firmware/card/read_bridge.py --encode '{"sequence":1,"gpa":"0x100000","length":8,"boot_id":99}'
python -B firmware/card/read_bridge.py --decode <512-bit-response-hex>
```

An explicitly enabled external bridge uses `--live --openocd <executable>`. Its persistent stdio
protocol accepts one JSON line `{ "id": 1, "gpa": "0x100000", "length": 8, "timeout_ms": 1000 }`
and replies with `{ "id": 1, "status": "complete", "data": "...hex..." }` or an error. Stdout
contains only these JSON replies. The bridge starts OpenOCD once, on the first valid request,
and retains one private stdin/stdout Tcl RPC connection for subsequent fragments. No TCP listener
is enabled. The configuration defaults to disabling RPC when used outside the bridge. Commands
use the [OpenOCD Tcl RPC framing](https://openocd.org/doc/html/Tcl-Scripting-API.html) and capture
scan output into the reply. Each request retains the two existing scan stages and checks USER2 FPGA/ROM/boot IDs
before and after each request and across a bridge session. This is identity-change detection,
not authentication. The boot ID is also sent for runtime validation.

Successful replies additionally contain `startup_ms` (the one-time process/connection startup,
repeated unchanged in subsequent replies) and `round_trip_ms` (that request's identity probes,
mailbox scans and response validation, excluding startup). Both use the host monotonic clock.
The first request's `timeout_ms` includes startup; later deadlines cover only their own work.
RPC reads and writes are covered by that deadline, replies are bounded to 256 KiB, and cleanup
terminates the owned process with bounded waits. An error ends the session without reconnecting
or replaying an ambiguous request. EOF also closes the owned process.

This transport change needs no new hypercalls, FPGA protocol change or firmware flash on an
already compatible read-mailbox build. It neither adds process discovery nor establishes a 60 Hz
performance claim. The [Rust desktop client](../../client/README.md) uses the separate
local VMMCALL reader described in [LOCAL-READ.md](../../LOCAL-READ.md).
This external mailbox transport requires independently established current-boot
process-discovery context and compatible running firmware.

Live bridge execution currently requires Windows. Before starting OpenOCD, Python places itself
in a new unnamed kill-on-close Job Object and keeps its non-inheritable handle until process
termination. OpenOCD children inherit job membership. Killing or timing out the bridge therefore
also terminates its remaining OpenOCD children; xtask and its ancestors are outside this new job.
Failure to establish containment aborts before JTAG access. This uses host process-lifetime APIs,
not Windows guest memory APIs. The offline tests verify cleanup with harmless Python processes.

A timeout is not cancellation: the card may retain the request and the monitor may finish later.
The bridge stops after an error rather than replace an unknown pending request. Host-side process
walking must remain bounded and treat the bytes as changing observations, not a coherent capture.
No hardware access is performed by the offline tests:

```powershell
python -B -m unittest discover -s firmware/card -p test_read_bridge.py
./firmware/card/test-endpoint.ps1 -Suite read_mailbox,completer,payload_completer,tx_guard
```

The new mailbox test checks truncated and corrupt scans, occupied-slot retention, incomplete and
wrong-sequence output, corrupt CRC, reset during staging, duplicate replay and publication during
a scan. The existing endpoint build still requires routed timing, CDC, resource and TX ownership
audits. A simulated byte exchange or synthetic-ROM FPGA build is not a deployable firmware result.
