# Windows GMET entry trial

Build and boot the runtime with `cargo xtask resident --output <fresh-dir>
--entry-trial` (or the corresponding `card-dev --entry-trial` deployment).
The default runtime omits this protocol. The client does not install a runtime,
create a memory window, or change mappings. Only run against the matching booted
experimental runtime: VMMCALL is not a safe absence/version probe. An absent
runtime can fault the process; an incompatible runtime can stop the machine.

On native x64 Windows:

```powershell
cargo build -p xtask
target/debug/xtask.exe entry-trial --live --entry-trial-v1 --cpu 0 --output trial.jsonl
```

Choose an allowed processor in group zero, 0..31, hosting the experimental
runtime. The client conservatively requires a process confined to group zero.
It pins its thread through QUERY, generates a random nonzero correlation nonce,
resolves `ntdll!NtYieldExecution`, and locks its result buffer and relevant code.
A warm-up invocation runs the syscall before ARM and touches the assembly frame;
that frame is then locked. Preparation failures issue no ARM. Locking and warming
reduce unrelated page faults but cannot guarantee the absence of intervening
events or account for arbitrary instrumentation of ntdll.

The assembly wrapper issues exactly one ARM. If accepted, it stores the raw ARM
registers, tests RAX, and directly calls the prepared function. There are no
allocations, logging, or other Windows calls in that interval. After the syscall
returns (or immediately upon ARM refusal), it issues one QUERY using the same
nonce. RBX retains the result pointer while QUERY overwrites R8 through R12; R12
and all other modified Windows nonvolatile registers are restored. The wrapper
provides aligned stack and shadow space plus Windows unwind metadata.

The new output file contains newline-delimited JSON: a flushed `prepared` record
before the trial and a final result after return. Existing files are not
overwritten. A machine stop can leave only the prepared line. The final result
includes raw ARM RAX/status, syscall NTSTATUS (null if skipped), QUERY RAX,
experiment status, exit code, RIP, INFO1/INFO2, sequence, CPU and nonce. Hexadecimal
strings preserve full-width values. NTSTATUS is recorded without assuming that
`NtYieldExecution` must return zero.

| Outcome | Interpretation |
| --- | --- |
| Activation refused | Preconditions unsuitable or this CPU's attempt already used; no gating result |
| Supervisor fetch gated | Monitor classified the expected GMET supervisor fetch |
| Physical interrupt first | Intended boundary was not observed; inconclusive |
| User page fault reflected | Supported unrelated fault ended the trial; inconclusive |
| Rejected QUERY or incomplete status | No usable correlated result |
| Unsupported exit/inconsistent state | Runtime stops; client may never return |

Exit status zero requires accepted ARM, a returned syscall, successful QUERY,
GATED status, the expected NPF code/flags and a nonzero entry sequence. All other
results exit nonzero. There is no automatic retry, polling loop, or CPU fallback.
The runtime consumes one attempt per CPU per boot, including late refusals.

A returned client and the expected exit establish only a hardware smoke test.
GMET gates the first supervisor instruction fetch, after any architectural
transition effects preceding that fetch. Independent tracing is still needed to
identify the actual kernel-entry boundary. This does not prove target-page
retention, shadow-page-table coherence, or memory-window isolation.

Offline verification (never issues live VMMCALL):

```powershell
cargo test -p xtask entry::
```

Test builds assemble synthetic ARM/QUERY responses in place of VMMCALL, exercising
the actual wrapper's refusal branch, syscall return capture and QUERY clobbers.
These tests do not establish hardware behavior.
