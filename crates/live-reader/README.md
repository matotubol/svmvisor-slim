# svmvisor-live-reader

Read another Windows process's memory through the resident svmvisor runtime,
with calls shaped like `OpenProcess` and `ReadProcessMemory`. Programs link this

```toml
[dependencies]
svmvisor-live-reader = { path = "../crates/live-reader" }
```

## What to know

- **`connect` is `unsafe`.** Its first request is a VMMCALL. Without a hypervisor
  it faults and ends your process, and an older svmvisor runtime can stop the
  machine. Call it only on a boot you know runs runtime v2.
- **One thread.** The connecting thread is pinned to `Config::cpu` (default 0)
  while the connection lives, and `Svm` is neither `Send` nor `Sync`. Give it a
  dedicated thread in a GUI program.
- **One open process per connection.** The runtime binds one process per
  session, so `open_process` closes the handle opened before it. Reads through an
  old handle return `InvalidHandle`.
- **Windows is never asked.** `list_processes` walks the kernel's own process
  list through the runtime, and no process is opened through Windows. Names come
  from the image path the kernel recorded at process start. A listing costs a few
  dozen runtime requests per process, so refresh it when you need to, not every
  frame. `attach` refuses a listed PID that has since been reused.
- **Batch whatever you can.** Each process sample checks the process identity
  before and after copying. `read_batch` merges exactly adjacent consecutive
  reads, then packs up to eight wire ranges and 4096 bytes per request;
  `read_process_memory` splits long reads the same way. It reads no gap bytes
  and does not merge overlapping ranges. Pointer chains need a separate read
  for each dependent hop.
- **Requests are not VM exits.** The synchronous VMMCALL transport deliberately
  exits once per submit or continuation. A small process sample takes three
  exits; an aligned 4096-byte sample takes six. `calls()` counts logical requests;
  `hypercalls()` counts actual reader VMMCALL instructions on the native transport.
  Reading either counter sends nothing. See [costs and validation](PERFORMANCE.md).
- **Observations, not snapshots.** Values may change while a request copies, and
  separate requests are separate observations.
- **Strict reads are all-or-nothing.** On any strict read error, no output buffer is changed.
  The separate capture API records readable spans and explicit gaps.

## Profiles and diagnostics

The embedded default describes kernel build `26100.9457`. To use another verified
build without recompiling, supply the JSON produced by
`crates/hypervisor/profiles/extract.py` from that build's exact kernel and PDB:

```powershell
python crates/hypervisor/profiles/extract.py --image ntoskrnl.exe --pdb ntkrnlmp.pdb --output kernel-profile.json
```

Extraction requires `llvm-pdbutil` on PATH (or its `--llvm-pdbutil` path option).

```rust,no_run
use svmvisor_live_reader::Config;

let config = Config::new("ntoskrnl.exe", "ntkrnlmp.pdb").profile("kernel-profile.json");
```

Explicit evidence is bounded to 1 MiB and fails without fallback if invalid. The
reader checks schema, offsets, hashes, file lengths, kernel PE/CodeView identity,
and syscall anchors before connecting; discovery still checks the mapped kernel.
Use evidence from your trusted extraction process: hashes bind the supplied files
to the record but do not prove that someone supplied the correct symbol offsets.
No symbol download or directory scan is performed.

`Svm::explain_address(handle, address)` returns the page-table root, raw entries
and the precise translation result, including a nonpresent entry that stopped
the walk. It checks process identity before and after and never accesses the
translated target data. Supporting runtimes perform it in one batch with three
service opportunities. The first diagnostic makes one additional capability query;
the result is retained for this connection. Older runtimes fall back to at most 124
physical requests per diagnostic. Both paths use fresh observations and the read
timeout. Ordinary reads do not issue capability queries.
Entries are observations, not proof of a stable mapping or CPU access permission.
Nonpresent Windows entries remain raw; this does not recover pagefile or
compressed memory.

## Captures with gaps

`capture::read(&mut svm, handle, regions, limits)` returns page-bounded spans.
Readable spans contain bytes and SHA-256; unreadable spans contain no bytes.
PID, creation time, capture/span timing, request counts and measured reader
VMMCALL counts accompany the data. Process or session failure discards the whole
capture. Strict `read_process_memory` and `read_batch` retain their existing
all-or-nothing behavior.

The defaults allow 16 MiB, 8192 spans and 30 seconds. Hard ceilings are 64 MiB,
16384 spans and 300 seconds. Limits and complete ranges are checked before reads;
each read receives the remaining deadline. Captures use no retry, page-in,
background polling or target memory cache. A capture is a sequence of observations,
not an atomic snapshot. The client can display gaps and export a binary file with
an authoritative manifest; see [client commands](../../client/README.md).

## Errors

`Error::kind()` says what is still usable:

| Kind | Meaning | Still usable |
|---|---|---|
| `Unreadable` | An address is not mapped in the process | handle and connection |
| `ProcessNotFound` | No such PID in the process list | connection |
| `ProcessGone` | The process exited or its identity changed | connection; open again |
| `InvalidHandle` | Closed, or replaced by a later `open_process` | connection |
| `Discovery` | Kernel context or process discovery failed | connection |
| `InvalidArgument` | Bad address range or setting; nothing was sent | everything |
| `LimitReached` | Capture reached its local time limit; no result published | handle and connection |
| `Profile` | Kernel/PDB files do not match the recorded profile | nothing was started |
| `Connect` | The runtime could not be reached or the thread pinned | nothing was started |
| `SessionEnded` | Malformed response, timeout or transport failure | nothing; connect again |

The connection never retries on its own.

## Tests

`cargo test -p svmvisor-live-reader` runs the public API against the resident's
own batch engine over an in-memory physical image. Test builds never issue a
VMMCALL.
