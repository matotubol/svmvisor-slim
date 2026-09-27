# EFER conformance review — 2026-09-26

Two independent reviewers checked the register semantics and runtime lifecycle against the
indexed AMD manuals. No confirmed defect was found in the reviewed EFER masks, capability
gates, mode checks, capture/restore ordering, or state commits. This is source review and
offline validation of a bounded implementation, not complete hardware verification.

EFER is intercepted and emulated. `NativeEfer` retains the logical guest value while the
VMCB retains the SVME bit required for guest entry. Native execution of other instructions
does not make EFER a pass-through register or establish complete native CPU behavior.

| Area | Review result | Manual evidence, physical pages |
| --- | --- | --- |
| Field definitions and capability gates | Implemented masks and optional-feature gates match the architecture and admitted target. Processor-absent features prepare a guest fault. | `24593_3.44_APM_Vol2 p117–120`; `57896-3.00_PPR p87, p88, p99, p117, p186` |
| LMA and LME | Writes must preserve hardware-derived LMA; LME cannot change with paging enabled. Production enables the owner that observes LMA after native CR0 changes. | `24593_3.44_APM_Vol2 p119, p552–553`; `57896-3.00_PPR p186` |
| Logical and backing EFER | Initial capture precedes permanent SVM enablement. VMCB initialization and later commits preserve mandatory SVME. | `24593_3.44_APM_Vol2 p564, p566–567, p569` |
| MSR interception | Both EFER reads and writes remain intercepted, with MSR protection enabled. Common instruction checks and register-specific faults have separate owners. | `24593_3.44_APM_Vol2 p580–581` |
| Guest INIT | The startup path stages the logical reset and commits it after applying the guest INIT state. Logical EFER becomes zero. | `24593_3.44_APM_Vol2 p543` |
| VMCB and translation state | Typed EFER writes invalidate the corresponding clean group and request translation invalidation. | `24593_3.44_APM_Vol2 p589, p591` |
| INTWB operation | Guest WBINVD/WBNOINVD are not intercepted in this profile, so the guest-loaded EFER setting applies in hardware. Host cache-maintenance WBINVD is a separate operation. No mismatch was confirmed. | `24593_3.44_APM_Vol2 p801`; `24594_3.37_APM_Vol3 p544` |

The review does not justify a claim of 1:1 behavior. Some reserved/control writes, execution
modes, single-step completion, and nested-SVM operations are explicitly outside the supported
contract. Their terminal refusal is not equivalent to completing a native operation. Reserved
read-as-zero descriptions do not, by themselves, prove that writes must be ignored: the target
PPR also specifies reserved-field software obligations (`57896-3.00_PPR p26–27`). The FFXSR
clear restriction is an implementation policy consistent with the target's OS programming
guidance; it is not evidence that hardware implements a write-once latch.

Exception recovery is a separate limitation. A pending software injection with valid
EXITINTINFO remains unsupported by `complete_event_delivery`. The implementation preserves
the unfinished obligation and stopped state. Passing the regression for that refusal does
not mean delivery recovered. Later guest re-INIT after startup routing is retired is another
runtime limitation, separate from the EFER reset operation itself.

This review added four offline regressions:

- An invalid EFER write preserves the complete VMCB except EVENTINJ, the register frame,
  and the logical owner; a modeled successful delivery permits a subsequent EFER read.
- Interrupted EFER fault delivery retains its obligation after a modeled VMEXIT clears
  EVENTINJ, without changing the stopped VMCB, register frame, or logical owner.
- A modeled paging-disable transition updates logical LMA before a legal LME clear.
- Successful reinjection changes only EVENTINJ across the entire 4096-byte VMCB, retaining
  the error code only when valid and clearing reserved injection bits.

The focused integration run passed **66 tests** across guest continuation, EFER boot policy,
independent EFER bit coverage, NRIP, visible-SVM EFER state, instruction faults, permission
maps, event delivery, and VM_CR. Formatting also passed. The retained log is
`target/efer-conformance-tests.log` at the repository root.

No production emulation behavior was changed by this review. The new fixtures do not execute
privileged instructions or guest handlers, and cannot establish physical feature effects,
exception recovery, malware-detection behavior, or the cause of the reported shutdown.
