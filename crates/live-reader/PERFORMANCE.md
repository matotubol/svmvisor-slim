# Reader and client cost review

## 2026-09-28: on-demand inspection and batched watches

The HyperDbg reference review used local commit `ff3ba351` (v0.24). Useful
patterns were explicit page-table inspection, bounded memory reads and capture
output. Implementations here are original Rust and preserve the reader's passive
memory acquisition contract. The user's priority for this pass was lower overhead
and fewer guest-state changes.

The client now loads module names on first use. Starting the console and issuing
numeric-address commands performs no loader-list walk. Explicit `modules` still
refreshes the list; it is not refreshed periodically. `watchmany` samples up to
eight values with one `read_batch` per tick and displays request/reader-exit costs.
It reuses its scatter buffers and retains the existing missed-tick behavior, so
slow reads do not cause catch-up bursts. Completed stop requests are checked
before issuing another sample.

The real resident batch engine running over synthetic memory verifies:

| Eight values inside their respective pages | Logical requests | Modeled reader exits |
| --- | ---: | ---: |
| Eight separate scalar reads | 8 | 24 |
| One batch with eight scattered values | 1 | 4 |
| One batch with eight adjacent values | 1 | 3 |

These are transport counts, not measured hardware latency or a claim of
undetectability. Tests also mutate memory between ticks, verify that the next
batch sees fresh data and verify that reads leave the supplied target image
unchanged. No target-data or page-table cache was introduced.

`pte`/`explain_address` runs only on request. Its diagnostic walk uses the same
translator and physical-read count as a normal walk; before/after process
revalidation gives the complete operation a conservative bound of 124 physical
requests and the configured read timeout. Ordinary reads do not collect traces.
The bounded generic observer compiles into the shared translator; the resident
build and linked-code audits pass.

Capture splits at page boundaries and retains gaps without retrying or faulting
pages into Windows. It keeps strict process identity checks and does not write
target memory, freeze the process, install hooks, or add background timers.
Explicit profile selection performs local verification only, without scanning
directories or downloading symbols.

Verification: workspace tests, the 213-test resident-runtime library suite,
format checks, and `cargo xtask resident` passed. The final resident build is in
`target/native-resident/reader-forensics-final-20260928`. Windows sandbox/compiler
temporary-file restrictions required directing TEMP/TMP to a workspace directory
and running the native build outside the sandbox. No firmware was flashed or
executed, and no live VMMCALL or hardware latency benchmark was run.

Automatic discovery still has only the caller-root candidate; a KPTI shadow
root may not map the kernel evidence it needs. The failure now identifies that
candidate and explains the possible limitation. Kernel-root acquisition, WOW64
module support and general symbol/type inspection remain separate follow-up work.

## 2026-09-26 baseline

This review covers `crates/live-reader`, `client`, the local resident service and
the shared batch frame codec. Changes add no instruction intercepts, timers or
background polling. They preserve the current synchronous VMMCALL transport:
each submit, continuation, context, probe or abort instruction causes a VM exit.
Zero-exit acquisition would require a different transport and ownership design.

## Requests and exits

The client keeps its connection and process binding. Discovery is not repeated
for every sample. Each logical process sample retains identity checks before
and after copying. The resident groups at most four 256-byte data fragments in
one opportunity; those identity checks remain separate opportunities.

These counts describe successful reads with an already-bound process and no
recovery traffic. They exclude connection, discovery, binding and unrelated exits.

| Read pattern | Previous reader VMMCALLs | Revised reader VMMCALLs |
| --- | ---: | ---: |
| Empty read | 0 | 0 |
| One 8-byte value inside a page | 3 | 3 |
| Eight separate, scattered 8-byte values in one batch | 4 | 4 |
| Eight consecutive 8-byte values in one batch | 4 | 3 |
| Sixteen consecutive 8-byte values in one batch | 8 | 3 |
| Thirty-two consecutive 8-byte values in one batch | 16 | 3 |
| One aligned 4096-byte process sample | 6 | 6 |
| One aligned 4096-byte physical request | 4 | 4 |

Packing merges only exactly adjacent consecutive reads. It neither reads gaps
nor merges overlaps or duplicate addresses. Scatter destinations and their order
are preserved, including when a caller buffer spans several wire requests.
No caller output changes unless the whole public read succeeds. Reads remain
observations of mutable memory, not atomic snapshots.

`Svm::calls()` remains the logical request count. `Svm::hypercalls()` separately
returns the native transport's instruction count, including probe and abort calls.
An uninstrumented internal test backend can report `None`. Counter reads are local
and issue no VMMCALL. Use differences around the operation being measured;
neither counter measures all VM exits on the machine.

## Less work per call

- The physical-copy adapter no longer repeats a subset of the private NPT check
  already performed by `GuestReader::copy`. Actual copy admission still checks
  identity mapping, permissions, RAM, write-back memory and monitor exclusion.
  Output preflight retains its full writable check and the actual write still
  rewalks caller mappings. No guest PTE or target-data cache was added.
- Memory-free abort and metadata rejection paths avoid constructing the physical
  reader when NRIPS supplies the continuation. Privilege, pending event, debug
  and mode handling still precede dispatch. Without NRIPS, instruction evidence
  must still be read.
- Response decoding reuses the returned allocation instead of allocating a
  second payload vector. Malformed error responses end the session; only correctly
  framed empty-data read/binding refusals with the expected retained/cleared token
  remain recoverable. Inconsistent binding-state replies end the session.
- Checked module and loader-pointer additions reject overflow before it can wrap
  into a different memory read. Supplied invalid module offsets send no request.
- The unchanged IEEE frame CRC uses a compile-time 1024-byte lookup table instead
  of eight bit rounds per byte. It needs no special instruction or SIMD state.

Four adjacent 256-byte fragments within the same requested range and 4 KiB page
now share one numerical translation during that service opportunity. Four-level
translation/data callbacks fall from 20 to 8 (16 to 7 for 2 MiB mappings; 12 to 6
for 1 GiB mappings). Each physical callback still performs full copy admission.
The scratch alias is installed and removed for each callback, so its invalidations
fall from 40 to 16 in the four-level case. No alias is retained between copies.
The translation is discarded at a range boundary, 4 KiB boundary, or return to
the guest. A remapping before the next opportunity is observed afresh. There is
no change to the 256-byte fragment limit or the opportunity/exit count: an aligned
4096-byte process sample still needs six reader exits, with 32 instead of 80 data
phase callbacks. These counts exclude identity checks and transport buffer work.

Process discovery combines exactly adjacent PID and active links into one 24-byte
read, in either field ordering. On a four-level same-page mapping, acquiring each
node's PID and links takes five instead of ten physical reads. Profiles with gaps
retain separate reads; fields crossing a page translate both pages independently.
For 300 same-page nodes this removes 1500 physical requests from traversal, apart
from list-head, matched-process, identity and detail reads.

Full module enumeration batches the current name with the next 104-byte loader
entry. A list of N nonempty names uses N+3 requests for N>0 instead of 2N+2
(100 modules: 103 instead of 202). Empty lists use two setup reads. No bytes in
gaps are read. Name lookup and main-module lookup retain their early exit paths.

Optional address diagnostics use one Explain batch with separate before-check,
page walk and after-check opportunities. The first use adds one control-only
capability query; subsequent uses need three reader exits each. An older runtime's
exact INVALID/0 reply selects the previous bounded physical-request path (at most
124 per walk). Other refusals or malformed replies end the session. The resident
returns only sampled page-table entries; the host verifies and replays them locally.
Target data is never copied by this operation. Capability queries are lazy and do
not add work to ordinary reads. Neither batching nor grouping makes observations
atomic or removes the changes inherent in executing a host client and VMMCALLs.

The resident retains the immutable per-CPU 1 GiB-page capability after its first
query; ordinary SUBMIT/STEP traffic does not repeat CPUID. Guest EFER and memory
admission still use fresh observations. Diagnostics and ordinary samples share
the same compiled walker, with evidence recording enabled only for diagnostics.
The linker packs aligned data sections before small state, removing 4096 bytes
of padding while preserving map alignment and the original resident image limit.

## Client scheduling

The console watch skips missed ticks after a slow sample or slow output, then
waits a full interval. It no longer produces immediate catch-up reads. Scalar and
watch commands reuse stack buffers; the dump formatter writes one preallocated
string instead of allocating strings per byte. Process-picker rows retain their
original process index even if inserting another row fails.

The supplied client is a Windows library. It is now a workspace member, so its
offline tests and compilation run with the reader. No binary entry point was
invented, and none of the verification commands executes the live transport.
Because the existing client explicitly requires Windows x64, workspace-wide host
commands now have that platform requirement; explicit resident package builds
remain separate. A watch stop cannot interrupt a read already in flight. The
existing console input thread can remain blocked after a fatal read error.

## Evidence and limits

Offline API tests run the resident's actual bounded batch engine over an in-memory
image. They count service opportunities, check scatter results and exercise
failures after earlier chunks have succeeded. Separate tests cover framing,
identity changes, deadlines, native control-only dispatch and admission failures.
CRC fixtures were computed independently with Python `zlib.crc32`.

A development-machine microbenchmark compared the old CRC with the new one using
16 MiB per case and the median of three runs, alternating measurement order:

| CRC input bytes | Previous ns/frame | Revised ns/frame | Ratio |
| --- | ---: | ---: | ---: |
| 64 | 275 | 71 | 3.83 |
| 252 | 1180 | 364 | 3.23 |
| 4160 | 19083 | 6342 | 3.01 |

These are optimized host-only CRC measurements, not reader throughput or resident
interrupt latency. The source and output are retained under
`target/reader-review-crc-bench.rs` and `target/reader-review-crc-bench.log`.
The runtime still bounds each opportunity to 60 physical callbacks and four data
fragments. Callback counts do not bound elapsed time. Target-machine boot tests,
read correctness checks and latency measurements remain necessary; no live read,
flash or reboot was performed on this development machine.
