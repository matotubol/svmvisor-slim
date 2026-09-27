# MSR ordering review — 2026-09-28

Three parallel reviews covered MSR/exception ordering, other intercepted state
and I/O paths, and the existing DriverSuper comparison harness. Findings below
describe architectural correctness, not a claim of hardware equivalence.

## Fixed: ICR operand faults required successful completion evidence

`src/host/resident/runtime/msr.rs::handle_native_icr` previously required
capabilities, a usable continuation, and TF=0 before checking a reserved ICR
write. A documented faulting write with TF=1 therefore caused a terminal
diagnostic stop instead of preparing #GP(0).

The handler now validates the actual MSR exit, ICR index, CPL and event/profile
boundary, then reflects known operand faults before requiring successful
completion evidence. It performs no IPI or guest instruction fetch on this
path. Successful accesses retain their existing continuation/debug checks.

Regression coverage in `src/host/resident/runtime/msr/tests.rs` checks reserved
operands, TF, absent continuation capabilities, unusable nRIP, startup modes,
pending/masked NMIs, conflicting events, and complete guest-state preservation.
Only EVENTINJ changes on the fault path; the retained ICR value is unchanged.
The main regression failed before the fix and passes afterward.

Sources actually read: `24593_3.44_APM_Vol2 p305` (fault state), p470 (single
step), p580 (MSR intercept ordering), pp721,723 (x2APIC faults and layout);
`57896-3.00_PPR p179` (target ICR). Page 723's layout image was checked.

## Fixed: MSR evidence rejected a fault at the canonical-address boundary

`src/svm/exit.rs::MsrInstruction::hardware` previously required a canonical
successor before an MSR owner could evaluate operand faults. For a two-byte
WRMSR starting at 0000_7fff_ffff_fffe, the current instruction fits in canonical
space while its successor does not. An operand fault needs the original RIP,
not that successor.

Successor canonicality is now checked by `continuation`. Actual exit identity,
current RIP, NRIPS support and bounded instruction length remain validated.
Successful accesses still refuse unsupported noncanonical completion before
changing architectural state.

`tests/svm_dispatch_efer_nrip.rs` covers reserved EFER operands, LMA mismatch,
two-byte/prefixed instructions, TF and full state preservation. Its fault
regression failed with NonCanonicalNrip before the fix. A separate regression
ensures a nonfaulting write cannot commit before continuation validation.

Sources actually read: `24593_3.44_APM_Vol2 p202` (referenced byte addresses),
p305 (fault boundary), p571 (nRIP), p580 (MSR-specific fault ordering).

## Remaining findings

- Scalar intercepted PCI configuration I/O can lose guest I/O breakpoints:
  `src/svm/diagnostic_config.rs::prepare_io` does not account for active
  CR4.DE/DR7 I/O breakpoints, while `runtime/diagnostics.rs` executes the access
  in the host and advances guest RIP without the corresponding guest #DB/DR6
  completion. Guest debug-register writes execute directly, so initial
  admission cannot rule this out. Full support needs debug suppression,
  retirement and event-ordering work. No change was made to this path.
  Sources: `24593_3.44_APM_Vol2 pp468,569,579`.
- ICR message types 1 and 7 conflict between the general APM (reserved, p723)
  and target PPR (Lowest Priority/External Interrupt, p179). Their existing
  classification was preserved. New fault regressions avoid using those values
  as architectural oracles. The APM p723 table also says reserved 55:20, while
  its diagram shows 31:20 and DEST occupies 63:32; the existing mask follows
  the diagram and target PPR.

## Validation

- `cargo test --workspace --quiet`: 639 tests passed, including doctests.
- `cargo test -p svmvisor-hypervisor --lib --features resident-runtime --quiet`:
  213 tests passed.
- Changed Rust files pass rustfmt; `git diff --check` passes.
- `cargo xtask resident --output target/native-resident/msr-ordering-20260928-final`:
  build and mandatory binary audits passed. Outputs include `driver.efi`,
  `payload.bin`, `summary.json`, and the exact source snapshot/manifest.

Windows process/temp-directory restrictions initially blocked some checks.
The successful runs used workspace-local TEMP/TMP directories; no test code was
changed to resolve those environment failures. Workspace test output is saved
at `target/ordering-workspace-tests.log`.

No driver was loaded and no bare-metal or virtualized boot was performed.
Host tests and binary audits do not establish hardware equivalence.

## DriverSuper comparison

DriverSuper's existing fault collector runs target instructions at CPL3 with
read-only kernel context queries. It cannot exercise the CPL0 ICR+TF bug or
the canonical-edge case. Windows SEH status is not a raw exception vector or
error code. A live regression for these fixes still requires a dedicated
kernel exception/recovery harness; an ordinary CPL3 probe is insufficient.

The companion offline comparison in `C:/Users/mato/Documents/driver-super`
compares saved evidence from the same binaries and machine baseline, with
explicit Native/KnownHypervisor labels. See `docs/COMPARE-RUNS.md` there for
commands and limits. It verifies comparability and reports observed differences
in the existing probes; it does not supply live coverage for these new fixes.
Its 39 offline fixtures pass in both Windows PowerShell 5 and PowerShell 7.
Stable EFER/CPUID context differences between boots are reported as observations;
unstable context within one measurement remains invalid evidence.
