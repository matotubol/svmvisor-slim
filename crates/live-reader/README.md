# svmvisor-live-reader

Live reading is temporarily disabled. The public API remains available, but
`Svm::connect` is now safe and always returns `ErrorKind::ReaderDisabled` before
opening kernel/PDB files, changing thread affinity, allocating native transport
buffers, or calling the runtime. The legacy guest transport and its probe were
removed; there is no compatibility fallback or configuration switch to restore it.

This is an interim closure, not an implemented authenticated reader. Re-enabling
the same-PC client under the administrator/kernel threat model requires a proven
isolation boundary for client authority and protected results. Ordinary Windows
process memory cannot supply that boundary. The replacement is not available yet.

The retained API and in-memory tests are built with:

```toml
[dependencies]
svmvisor-live-reader = { path = "../crates/live-reader" }
```

## Retained offline behavior

These properties remain covered against an in-memory engine. They do not imply
that a live connection is available. Existing binaries compiled with the old
transport are unsupported and can fault when calling the retired interface.

- **One open process per connection.** The runtime binds one process per
  session, so `open_process` closes the handle opened before it. Reads through an
  old handle return `InvalidHandle`.
- **Windows is never asked.** `list_processes` walks the kernel's own process
  list through the runtime, and no process is opened through Windows. Names come
  from the image path the kernel recorded at process start. Listing reads PID,
  links and metadata together, then resolves names after validating the list.
  The resident translates discovery reads itself. With no page crossings, the
  list head and each process's fields each take one VM exit. Resolving a short
  full path adds two exits; long paths or page crossings can need more.
  Refresh when needed, not every frame. `attach` compares the listed creation time.
- **Batch whatever you can.** Every sampling request checks the process identity
  before and after copying, so one request with eight ranges costs little more
  than one with a single range. `read_batch` packs up to eight ranges and 4096
  bytes per request; `read_process_memory` splits long reads the same way.
  Pointer chains still need one call per hop.
- **Small samples can finish in one exit.** Both identity checks and up to four
  256-byte data fragments run together only if their worst-case work fits the
  existing 60-physical-callback ceiling. Page crossings and separated identity
  fields can reduce that allowance. Larger reads retain continuations: an aligned
  4096-byte sample still takes six exits. There is no translation cache.
- **Observations, not snapshots.** Values may change while a request copies, and
  separate requests are separate observations. A resident token remembers process
  identity; it holds no Windows object reference and does not keep the process,
  its address space or its pages alive.
- **Nothing partial.** On any error, no output buffer is changed.

## Errors

`Error::kind()` says what is still usable:

| Kind | Meaning | Still usable |
|---|---|---|
| `ReaderDisabled` | Live access is retired; authenticated replacement unavailable | no connection was started |
| `Unreadable` | An address is not mapped in the process | handle and connection |
| `ProcessNotFound` | No such PID in the process list | connection |
| `ProcessGone` | The process exited or its identity changed | connection; open again |
| `InvalidHandle` | Closed, or replaced by a later `open_process` | connection |
| `Discovery` | Kernel context or process discovery failed | connection |
| `InvalidArgument` | Bad address range or setting; nothing was sent | everything |
| `Profile` | Kernel/PDB files do not match the recorded profile | nothing was started |
| `Connect` | Retained classification for failed offline session initialization | nothing was started |
| `SessionEnded` | Malformed response, timeout or transport failure | nothing; connect again |

The connection never retries on its own.

## Tests

`cargo test -p svmvisor-live-reader` runs the public API against the resident's
own batch engine and a test-only submit/step loop over an in-memory physical image. The
one-process, short-name fixture takes two exits to list and six to open, after
connection with an already supplied kernel context. Previously those operations
took ten and twenty-six exits respectively. A small bound sample goes from three
exits to one. These are deterministic protocol counts, not measured latency.
No build of this crate contains a native hypercall transport. The crate forbids
unsafe Rust, including inline assembly, and live connection denial is tested
before profile and configuration validation.
