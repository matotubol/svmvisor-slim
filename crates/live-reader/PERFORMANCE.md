# Reader and client cost review — 2026-09-26

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

For an ordinary opportunity with four four-level target page walks and four data
fragments, removing the duplicate private-NPT walk eliminates 20 of its former
40 such walks. This does not remove the guest page-table reads, scratch alias
invalidation or any required VMMCALL.

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
