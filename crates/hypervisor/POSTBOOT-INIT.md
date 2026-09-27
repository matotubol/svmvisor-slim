# Postboot INIT with native interrupt delivery

Status: design proposal and routing safeguard; physical rebootstrap is not implemented
or enabled. The selected direction keeps ordinary interrupts on the physical LAPIC.
This document describes architectural correctness, not a claim of bare-metal equivalence.

## Implemented prerequisite

The initial all-AP-started milestone no longer removes x2APIC ICR interception.
Later guest INIT/SIPI writes therefore still publish target commands before issuing
a private wake. The milestone only suppresses routine progress diagnostics.

The current boot reset helper cannot perform an arbitrary live LAPIC reset. An INIT
addressed to an AP that has already started, to the captured BSP, or after the global boot milestone, now
stops at `StartupStage::PostbootInitUnsupported` (11). The command remains at the
head of its mailbox; it is neither dropped nor applied through the partial reset
helper. Source-side IPI publication may already have completed, as with other
asynchronous IPIs. This is a terminal diagnostic, not successful INIT emulation or
a guest architectural exception. Ordinary fixed interrupt delivery remains native;
ICR accesses now continue to incur their interception cost after boot. Existing
ICR handler limits also remain active, including refusal of TF-enabled completion
and unowned startup encodings; this is not general postboot ICR conformance.
The retained BSP role prevents its stale local boot-progress flag from authorizing
the AP-only reset helper before that CPU observes the final AP's startup.

A successfully committed initial INIT also resets the guest ICR readback and the
superseded instruction's routing retry count. The initial boot helper otherwise
retains its existing limitations. It is not evidence of complete postboot support.

Implementation: [startup runtime](src/host/resident/runtime/startup.rs),
[terminal stage](src/host/resident/terminal/refusal.rs), and
[routing transport](src/svm/startup.rs).

## Why an actual processor restart is needed

APM2 physical p719 says INIT preserves APIC_BASE.AE/EXTD but initializes the other
APIC registers. On this Ryzen target ISR, IRR and TMR are read-only/error-on-write
(PPR physical p177). The current `reset_native_lapic` changes a subset of writable
registers after checking ISR/IRR. It does not atomically reset active interrupt state.

Software-disabling the APIC preserves ISR/IRR; it is not an INIT substitute (APM2
physical pp691,703; PPR physical p57). APIC_BASE mode transitions do not document
the required reset either. EOI/SEOI acknowledges sources and cannot be used as an
inert reset operation. Do not drain or fabricate pending interrupt state to make a
quiescence check pass.

Physical INIT can perform this hardware transition, but also destroys the host's
execution context. A retained entry path and a live coordinating CPU must rebuild
that context before returning to the guest.

## Architectural contract

| Resource | Required treatment |
| --- | --- |
| Guest CR0 | Reset all specified fields while retaining **guest** CD/NW, not the host CR0 present when physical INIT executes. |
| Guest GPRs, segments, CR2/3/4, CR8, flags, debug registers | Follow APM2 physical pp543–545, Tables 14-1/2. RDX gets the target signature. |
| Guest EFER | Logical value becomes zero. Both host EFER.SVME and backing guest VMCB EFER.SVME must separately be set for SVM entry. |
| x87/MMX/SSE, XCR0, PKRU, TSC, MTRRs and ordinary MSRs | Preserve INIT-retained state. The entire restart closure must remain integer-only. Do not apply RESET or FINIT defaults. |
| VM_CR | Apply its specific INIT rules: LOCK survives; SVMDIS clears if LOCK=0 and is retained if LOCK=1. Do not generalize the ordinary-MSR rule to every field. |
| VM_HSAVE_PA / TSC_RATIO | Keep logical guest owners separate from the host's physical save address and unity ratio. Reestablish and validate host execution requirements. |
| SMM configuration | Preserve firmware ownership and locks; no SMM unlock or reconfiguration is part of restart. |
| LAPIC | Let actual INIT perform its documented reset. Preserve x2APIC mode and identity; never restore pre-INIT guest LVT/TPR/timer settings afterward. |
| Guest ICR readback | Reset to zero in the retained owner. Writing zero to the physical ICR sends an IPI and is not a reset primitive. |
| Guest startup address | Use the **guest** SIPI vector for real-mode CS=`vector << 8`, base=`vector << 12`, RIP=0. Never capture the private trampoline as the guest. |
| TLB / VMCB cache state | Treat reentry as a cold hardware owner: invalidate reuse evidence/clean bits and request the required guest-ASID flush. Host MOV CR3 alone is insufficient. |
| Pending events | Separate pre-INIT internal delivery, external events and post-INIT arrivals. Do not clear a later NMI merely because another wake or SIPI arrives. |

Sources: APM2 physical pp543–545, 590–591, 645–649, 705, 719; PPR physical
pp177–185. The admitted target's extended LVT reset is `0x10000` (PPR p185),
which differs from the generic APM2 p693 table. Hardware readback tests must use
the target value.

## Retained resources to provision before boot

1. A permanently reserved, aligned SIPI landing page below 1 MiB, with transition
   code and its real/protected-mode descriptor data. Its reservation must survive
   ExitBootServices and remain excluded from every guest nested mapping.
2. Owned transition page tables with a root address usable by the 32-bit entry
   stage; all code, data, tables and cache types in the execution closure validated.
3. An immutable directory keyed by the full physical CPU identity, including an
   entry for any admitted CPU that can be a guest INIT destination. No firmware
   ordinal or eight-bit alias may select another CPU's stack.
4. Per-CPU restart stack, fault/NMI stacks, descriptors, control record and terminal
   evidence storage. No ordinary guest or DMA write may alter restart instructions
   or the directory under the platform's existing memory-ownership assumptions.
5. A resident rearm entry that accepts retained runtime state. It must not call the
   original DXE callback, allocate memory, invoke firmware services, repeat initial
   guest capture, or reset one-shot telemetry as if a new machine had booted.

The existing low page is allocated as `LOADER_CODE` and expressly has no permanent
postboot reservation. Its old contents cannot be used as a restart resource.
`physical.S` also jumps into PE code, uses one-shot claims and calls the firmware
capture path. Only its copied AP wait loop is relocation-independent, and that
loop assumes a captured continuation; it cannot reconstruct a host.

Reusable ideas: the identity-first entry discipline in
[physical.S](src/firmware/native/resident/physical.S), the mapping builder in
[bootstrap_paging.rs](src/firmware/native/resident/bootstrap_paging.rs), and the
stopped CPU ownership checks. Reuse requires new lifetime and reentry proofs, not
calling [physical_boot::start](src/firmware/native/resident/activation/physical_boot.rs)
a second time.

## Proposed transaction

Use a separate restart transaction, not the initial bootstrap ACK or monotonic
`started` bit. Each target record needs an epoch, full target/coordinator identities,
phase, accepted guest command/vector, outstanding-event classification, and failure
evidence. Publication uses release/acquire ordering; reentry claims are specific to
one epoch, not a permanently set one-shot bit. Exhausted epochs fail explicitly.

| Phase | Owner and transition evidence |
| --- | --- |
| Running | Existing guest execution and retained ICR routing. |
| Requested | Guest INIT accepted into the routing transaction. No target reset is implied by publication. |
| Prepared | Target has completed its actual VMEXIT state save, closed temporary mappings/windows and relinquished all shared leases. Coordinator and retained entry closure are admitted. |
| InitIssued | Coordinator issued the authorized physical INIT after the target's readiness handoff. Sender completion alone does not prove target reset acceptance. |
| AwaitGuestSipi | The coordinator retains responsibility while the physical target cannot service mailboxes. Guest SIPI supplies the eventual guest vector; the private SIPI starts only the retained host closure. |
| Rearming | Target claims the matching epoch and reconstructs host execution. This is not guest startup completion. |
| GuestReady | Guest INIT image and its SIPI address are committed, SVM entry requirements and event ownership validated, and the target can service private notifications again. |
| Running | A generation-matched, successful guest-entry return confirms the restarted execution path. A pre-VMRUN record or VMEXIT_INVALID return is not success. |
| Failed | Persistent terminal evidence. No silent fallback to the pre-INIT guest after physical reset may have occurred. |

The phase names are software protocol states. In particular `InitIssued` and
`AwaitGuestSipi` do not fabricate a hardware acknowledgment that x2APIC lacks.

Before `Prepared`, complete or reject incompatible cache/terminal rendezvous and
active entry trials. A restart cannot strand a routing/cache lease on a CPU about
to reset. Reserve the transaction under a separate coordinator protocol, release
short-lived routing locks, and never wait for a reset target while holding them.
Concurrent requests must not create A-waits-for-B/B-waits-for-A cycles. An
all-excluding-self guest request leaves its source as a possible coordinator, but
that source still needs admission against concurrent incoming requests.

The target must arrange real INIT recognition instead of #SX redirection. APM2
physical pp597–598 describe the R_INIT/GIF dependency. A drained private wake is
not evidence of a still-pending physical reset request. Cache/terminal notifications
must not be sent to a CPU while its physical R_INIT is temporarily disabled.

Do not park a target with a resident stack reference across actual INIT. After a
private SIPI, reconstruct a fresh host stack, GDT/TSS/IDT and auxiliary save state;
enable the host's physical SVM prerequisites before using SVM instructions.
VM_HSAVE memory is opaque hardware storage, not a serialized Rust call frame.

The rearm entry must bypass the one-shot LBR capture in the existing entry path.
Retained guest LBR and guest auxiliary MSR state cannot be overwritten with the
host's post-reset state. Reestablish the host save address, physical unity TSC ratio,
R_INIT redirection, native interrupt/VNMI controls and cold VMCB/ASID ownership.
Preserve logical guest MSR owners. Only then advertise notification readiness.

The current four-entry FIFO is not by itself the complete wait-for-SIPI state
machine. A pending INIT transaction must allow its following SIPI to be examined
without losing the INIT's completion/failure record. Repeated INIT while physically
waiting, duplicate SIPIs, and an INIT arriving during rearm need explicit event
rules. Do not blindly replay every queued INIT as another processor reset or let
an awaiting INIT at the queue head prevent discovery of the SIPI that can release it.

## Activation gates still unresolved

**Early ordinary-SIPI events are the principal blocker.** APM2 physical p705 says
SMI/NMI and other interrupts are held until SIPI is accepted. It does not promise
they remain blocked while private code builds its interrupt tables. APM2 p623
conditions SIPI's additional GIF clearing and VM_CR security changes on prior
SKINIT. The stronger pending-event statements on p624 belong to that secure
sequence and cannot establish the ordinary postboot contract here.

CLI does not mask NMI. CLGI requires protected mode and EFER.SVME (APM3 physical
p417), while INIT clears those prerequisites. Adding CLGI later in the old
trampoline leaves an earlier gap. A pre-reset sample of “no pending NMI” also
cannot exclude a later arrival. Activation needs a documented early event owner or
a demonstrated applicable platform guarantee covering the entire transition. No
such mechanism is implemented or established by the current manuals/code review.

Additional gates:

- Establish ordinary INIT/SIPI pending-event behavior without borrowing secure-startup
  assumptions. Resolve repeated INIT precedence and the ownership of physical and
  virtual NMIs at each epoch boundary.
- Prove the retained low-memory closure and all entry dependencies remain owned
  after firmware handoff and virtual-address changes.
- Prove cache and terminal services tolerate a physically absent target. It cannot
  acknowledge their existing private notifications while awaiting SIPI.
- Distinguish target entry witnesses from sender ICR completion. Target PPR p179
  makes x2APIC ICR bit 12 reserved; it is not an INIT-completion bit. Existing PAUSE
  counts are iteration limits, not calibrated physical deadlines.

Until these gates are met, retain the explicit postboot refusal. Do not enable a
partial restart behind a success return or treat this design as a validated backend.

## Implementation and acceptance sequence

1. Prove the early-event contract and provision the permanent restart closure.
2. Add an inert epoch/phase model and concurrency tests before privileged execution.
3. Add the resident rearm entry, with relocation, stack-boundary and no-FP/xstate
   binary audits; keep it unreachable from the production dispatcher until admitted.
4. Integrate targeted physical INIT/private SIPI and coordinator failure handling.
5. Replace the postboot refusal only after the complete path passes the checks below.

Required tests include two complete guest INIT/SIPI cycles using different vectors;
duplicate SIPI while running; repeated INIT while awaiting SIPI; INIT with an old
fault/replay; NMI before reset, between INIT/SIPI and during early entry; queued
fixed/level-triggered interrupts; active timer/LVT state; simultaneous requests;
stale epoch claims; lost private SIPI; and target failure at every phase.

Compare guest CPU, retained MSRs/xstate, LAPIC reset/readback and interrupt delivery
against a controlled native baseline on the actual Ryzen 9900X. Inert tests establish
software transitions and preservation only. Build audits and emulator tests cannot
establish the physical early-NMI or INIT timing contract. No physical reset or
firmware deployment is performed by the routing safeguard in this change.
