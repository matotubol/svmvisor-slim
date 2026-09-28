# Intercepted MSR retirement and debug delivery — 2026-09-29

The selected native-behavior gap is the instruction boundary between an emulated
RDMSR/WRMSR and a single-step debug exception. A legal access to EFER, VM_CR,
VM_HSAVE_PA, SVM_LOCK_KEY or TSC_RATIO previously stopped whenever RFLAGS.TF was
set. Native execution either completes the access and takes #DB, or, with
DebugCtl.BTF set, completes the non-branch instruction without taking #DB.

This review follows `docs/README.md`. References use physical PDF page numbers.
The architecture review, implementation review and test review independently
followed the indexed manuals and cross-checked relevant page PNGs. Implementation
evidence comes from `crates/`; old descriptive notes were not taken as proof of
current behavior. No target execution or native-versus-resident measurement was
performed during this review.

## Findings and architectural evidence

| Finding | Previous behavior | Required native behavior and evidence |
| --- | --- | --- |
| Legal MSR under ordinary TF stepping | `UnsupportedDebugState` stops before completing the instruction | Complete the access, save the following RIP, set DR6.BS, and deliver #DB. `24593_3.44_APM_Vol2 p115, p470, p581–582` |
| Legal MSR under branch stepping | The same blanket TF refusal | DebugCtl.BTF changes TF into control-transfer stepping; RDMSR/WRMSR are not control transfers. `24593_3.44_APM_Vol2 p460, p471–472`; target BTF field confirmed in `57896-3.00_PPR p124` |
| Fault versus retirement | Existing owners already check architectural operand faults before the TF refusal | Preserve this ordering: an invalid write queues #GP(0) at the original RIP, with no completed write or single-step trap. `24593_3.44_APM_Vol2 p305, p570, p580–581` |
| Debug status must precede delivery | No software owner for MSR single-step status | Pure single-step sets BS and clears stale B0–B3 while preserving sticky BD/BT and the unrelated BLD bit. AMD's SMM example explicitly synthesizes DR6 and then queues #DB. `24593_3.44_APM_Vol2 p455–456, p825–826` |
| Completed instruction must not be replayed | Existing event recovery handles injected faults, but had no MSR completion outcome carrying a trap | The new completed result owns a pending #DB. If delivery exits again, replay EXITINTINFO at the already advanced RIP; do not repeat the MSR. `24593_3.44_APM_Vol2 p570–573, p593–594` |

The distinction is observable without timing measurements: a debugger stepping a
valid RDMSR should see the returned EDX:EAX and following RIP in its #DB frame.
Previously the monitor stopped instead. For a valid WRMSR, the logical register
must already contain the new value when #DB runs. For an invalid WRMSR, neither
the write nor instruction retirement occurs.

## Implemented ownership

`svm/vmcb/continuation.rs` now prepares retirement before any MSR owner, result
register or RIP changes. The plan checks event conflicts and establishes whether
the instruction needs a post-instruction trap. It is consumed once after the
owner commits its result and the validated next RIP.

The three owners in `svm/dispatch.rs`, `svm/vmcr.rs` and `svm/control_msrs.rs`
use this same preparation and completion path. Both hardware-nRIP and fetched-byte
entry points converge on it. Invalid continuation or unsupported debug state
therefore leaves the VMCB, frame and logical MSR unchanged. Operand faults are
handled before preparing retirement and do not require a valid successor RIP.

For TF=1 the saved DBGCTL is trusted only with the existing native LBR hardware
switch enabled. The VMCB location is state-save offset 270h, hence page offset
670h, not the similarly numbered LBR stack field in another part of the table.
The ownership and layout were checked in `24593_3.44_APM_Vol2 p602, p806–808`.

With TF=1, BTF=0 and no interrupt shadow, completion clears RF, updates DR6,
invalidates the VMCB debug-register cache group through the normal typed writer,
and queues EVENTINJ=80000301h (#DB, exception, no error code). Saved TF remains
set so hardware can put it into the exception frame. Hardware owns exception
entry, including live TF, DR7.GD and branch-record control effects. Prematurely
applying entry effects in the emulator would move them ahead of delivery.
Evidence: `24593_3.44_APM_Vol2 p116, p458, p470–472, p593–594`.

With BTF=1 the MSR completes without #DB; debug status and branch controls are
retained. RF still clears after the successful instruction. Existing TF=0
completion retains its shadow/RF behavior.

There is no new restriction on enabled DR7 address breakpoints. Hardware checks
instruction breakpoints and prior data traps before the MSR intercept, RF can
suppress an instruction breakpoint, and these MSRs have no data or I/O operand
to produce another address match. Evidence: `24593_3.44_APM_Vol2 p467, p570`.

The runtime distinguishes `DebugTrapPrepared` (instruction completed) from
`GeneralProtectionPrepared` (instruction faulted). A common completion helper
records event ownership on every selected MSR dispatch path. The existing
EXITINTINFO recovery handles repeated delivery exits. A separately queued V_NMI
is retained: #DB has priority over NMI/INTR, and EVENTINJ is delivered before the
next guest instruction (`24593_3.44_APM_Vol2 p327, p470, p593`).

## Deliberate remaining gaps

- TF together with INTERRUPT_SHADOW remains a refusal before any commit, even
  with BTF set. The saved one-bit shadow does not identify its originating
  instruction or deferred debug history. Extending it needs an explicit design
  for STI/MOV-SS and delayed traps; merely clearing the shadow is insufficient.
  The existing TF=0 shadow path also lacks explicit ownership of a possible
  deferred MOV-SS data breakpoint. This review preserves that behavior and does
  not establish complete shadow conformance. See `24593_3.44_APM_Vol2 p306,
  p596–597`.
- Other emulation owners, including cache/routing and diagnostic accesses, retain
  their existing debug restrictions. This change covers the five named logical
  MSRs; it is not a general x86 instruction emulator.
- Interrupted TYPE4 INTn delivery still stops. Asynchronous exits reset nRIP,
  and simply allowing TYPE4 does not establish the return-IP information needed
  for software-interrupt injection (`24593_3.44_APM_Vol2 p571, p593`).
- ICEBP has a documented injection exception (`24593_3.44_APM_Vol2 p594`). The
  review did not establish that a pre-instruction ICEBP intercept and an exit
  during its already-started IDT delivery have interchangeable requirements.
  No speculative ICEBP fix or claim of complete replay coverage is included.
- Native CPUID exposure, unsupported nested execution, higher-priority host
  events and the existing hardware-boot limitations remain separate concerns.

## Validation and target comparison

Host tests cover the three owners, read/write results, both decoding paths,
ordinary TF versus BTF, RF, stale and sticky DR6 bits, breakpoint controls,
pending events, malformed nRIP, fault precedence, and refusal transactionality.
Runtime tests cover pending-trap ownership, a completed write followed by repeated
interrupted #DB delivery, and coexistence with a pending virtual NMI. These tests
use inert VMCBs; simulated hardware transitions are explicitly marked.

Required software checks are `cargo fmt --all -- --check`, `cargo test --workspace`,
`cargo test -p svmvisor-hypervisor --lib --features resident-runtime` and
`cargo xtask resident --output target/native-resident/<fresh-directory>`. The last
check compiles and audits the actual linked payload; it does not execute SVM.

Before claiming native equivalence on the admitted target, retain the build's
`summary.json` and run the same privileged probe with and without the resident:

1. Single-step legal reads and reversible legal writes of the five named MSRs.
   Record access results, handler count, saved CS:RIP/RFLAGS, DR6, DR7 and branch
   controls; restore the original MSR values after each write test.
2. With TF=1/BTF=0, require one #DB after retirement, the correct following RIP,
   TF=1/RF=0 in its frame, and BS=1. Check stale Bn clearing and preservation of
   unrelated status. Verify IRET returns successfully and the access is not run
   twice.
3. With TF=1/BTF=1, require the MSR to finish without an immediate #DB and require
   the next intended control transfer to retain branch-step behavior.
4. Use invalid operands to require #GP(0) at the original RIP, unchanged logical
   MSR/GPRs and successful fault recovery, with no spurious completion #DB.
5. Exercise RF with an instruction breakpoint, pending NMI/INTR, and a controlled
   interrupted debug delivery. Verify the debug frame, handler ordering, and
   branch-record controls on actual entry, including recovery from delivery
   faults. Host unit tests alone cannot establish these processor effects.

TF plus interrupt shadow and other unsupported cases must be recorded separately
from passing cases. A terminal refusal is not a native-conformance pass.
