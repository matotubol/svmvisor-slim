# svmvisor client

Windows x64 library with a process picker and an interactive read-only console.
It requires a boot running the matching svmvisor runtime; unit tests use a
synthetic backend and never execute VMMCALL.

Pass `Config::new(kernel, pdb).profile(evidence_json)` to `pick` or `connect` to
select an extracted Windows kernel profile. Omitting `profile` retains the
embedded build. See [reader setup and limits](../crates/live-reader/README.md).

## Console

```text
modules
read client.dll+0x40 u32
dump 0x7ff600001000 256
pte 0x7ff600001000
watch client.dll+0x40 u32 500
watchmany u32 500 client.dll+0x40 client.dll+0x44 client.dll+0x80
capture 0x7ff600001000 0x10000 C:\captures\first
```

Addresses and module offsets are hexadecimal. Lengths are decimal or `0x`-hex.
Numeric commands do not load the module list. The first command using a module
name loads it once; `modules` explicitly refreshes it. Module names remain an
observation of loader bookkeeping, not a complete inventory of executable memory.

`watchmany <type> <milliseconds> <addresses...>` reads up to eight values in one
batch per tick. It keeps the connection, binding and buffers, skips missed ticks
and stops on Enter. Output includes logical requests and measured reader exits.
All values in a failed batch are withheld. Batching reduces transport overhead;
it does not make separately copied values an atomic snapshot.

`pte` reports the root, each sampled raw paging entry and the exact reason a walk
stopped. It performs fresh bounded identity checks and page-table reads only when
requested. Supporting runtimes use three reader calls, plus one capability query
on first use. Older runtimes retain the bounded physical-read fallback. Nonpresent
entries are not automatically faulted into memory.

`dump` displays at most 64 KiB with `??` for missing bytes. `capture` saves up to
16 MiB using the default 30-second capture deadline. Paths may contain spaces;
the rest of the command is the directory name. The destination must be new and
its parent must exist. No existing capture is overwritten.

## Capture files

An export contains `memory.bin` and `manifest.json`. The manifest records process
identity, addresses, file offsets, readable/unreadable status, timing, hashes and
request costs. Region positions and missing spans retain their file offsets.
Zero placeholders inside unreadable spans are **not captured memory**; consult
the manifest when interpreting the binary. Only spans marked `read` contain
captured evidence.

The final manifest is published after data and metadata are flushed. If export
fails, an incomplete directory can remain; absence of `manifest.json` means the
export did not finish. A live capture does not freeze Windows or the process.

The library exposes `Process::capture`, `Process::explain_address`, and
`capture::export` for callers that do not use the console.

## Validation

```powershell
cargo test -p svmvisor-live-reader -p svmvisor-client
```

Tests cover the resident batch engine over synthetic memory, gaps and mutation,
profile identity, deadlines, page-walk errors, display and export. Native boot,
latency, and live read correctness still require validation on the target machine.
