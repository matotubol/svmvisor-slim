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
- **Nothing partial.** On any error, no output buffer is changed.

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
| `Profile` | Kernel/PDB files do not match the recorded profile | nothing was started |
| `Connect` | The runtime could not be reached or the thread pinned | nothing was started |
| `SessionEnded` | Malformed response, timeout or transport failure | nothing; connect again |

The connection never retries on its own.

## Tests

`cargo test -p svmvisor-live-reader` runs the public API against the resident's
own batch engine over an in-memory physical image. Test builds never issue a
VMMCALL.
