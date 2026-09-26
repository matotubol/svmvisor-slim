# SVM exception behavior and #GP mediation

**Historical report:** this records the exception work before the
[private-interface retirement](PRIVATE-INTERFACE-PLAN.md). The local reader ABI,
guest entry trial and `native-entry-trial` feature described below have since been
removed. The supported producer now uses `resident-runtime`; the test counts and
artifact measurements below remain evidence for the earlier snapshot only.
The architectural #GP handling is retained.

Research and implementation review date: 2026-09-26. Code reviewed: working tree
based on `da37f2a`, including existing uncommitted changes. Independent agents
examined AMD architecture, the matching VMAware release, instruction decoding,
and exception delivery. The implementation described here has host tests;
target boot and hardware fault-delivery validation remain unperformed.

## Result and scope

The resident now intercepts #GP and repairs the specific difference between
logical `EFER.SVME=0` and the actual `SVME=1` required for SVM guest execution.
For a proven SVM instruction whose logical enable state requires #UD, it queues
#UD at the original RIP. It reflects unrelated #GP faults with their original
error code and combines faults that occur during exception delivery.

This is software-mediated exception behavior. The ordinary exception bitmap
contains #GP only; the optional entry trial temporarily adds #PF. There is no
opcode filter on the exception bitmap, so every guest-generated #GP reaches the
resident while that intercept is enabled. #UD interception is unnecessary for
this repair. Legal nested SVM, GIF operations and secure launch remain outside
the existing instruction owner's execution contract.

There is still no documented control on the admitted AMD platform that provides
all of active SVM guest execution, logical SVME clear, direct arbitrary guest
execution, and native SVME-disabled fault behavior without exception mediation.
The change implements the authorized #GP mediation; it does not establish
undetectability or universal equivalence to execution outside a hypervisor.

## Matching the reported executable

The supplied SHA-256,
`bc5954ecc5c87f0490915a7b7141bbc0ca9a317ccc9c89cf0bdc2f75445987c7`, matches the
published `vmaware.exe` asset for [VMAware v2.8.2](https://github.com/NotRequiem/VMAware/releases/tag/v2.8.2).
That release warns that `--version` still displays v2.8.1. Its source commit is
`a3cc54f7da798819d305fd1415daf1b8cd140c70`. The local executable and deployed
resident were not independently inspected.

This release's [SVM_EXCEPTIONS implementation](https://github.com/NotRequiem/VMAware/blob/a3cc54f7da798819d305fd1415daf1b8cd140c70/src/vmaware.hpp#L14583-L14626)
executes only **VMLOAD at CPL3**, not the larger instruction set described in
older release notes. The [stub](https://github.com/NotRequiem/VMAware/blob/a3cc54f7da798819d305fd1415daf1b8cd140c70/src/vmaware.hpp#L663)
does not initialize RAX. A Windows illegal-instruction status passes; other
results detect. With SVM visible in CPUID and an exception observed, the
[default score is 35](https://github.com/NotRequiem/VMAware/blob/a3cc54f7da798819d305fd1415daf1b8cd140c70/src/vmaware.hpp#L16937).
Hidden SVM capability or no exception selects the stronger branch. The probe
also skips a recognized Hyper-V host.

The reported 35%/one-hit result is consistent with visible SVM and a non-UD
exception. It does not contain the exact Windows exception status or prove the
CPU vector was GP. The aggregate bare-metal conclusion does not invalidate the
individual exception mismatch. A rerun using this implementation is outstanding.

## Architectural evidence

Manual references use physical page numbers, as required by
[docs/README.md](../../docs/README.md). Relevant tables and implementation
details were checked in both their text and PNG representations.

1. **Guest entry requires actual SVME=1.**
   `24593_3.44_APM_Vol2 p566` lists guest `EFER.SVME=0` as invalid VMRUN state.
   [NativeEfer::observe_backing](src/svm/dispatch.rs) requires hardware backing
   to equal logical EFER OR SVME. A logical MSR shadow does not change the CPU's
   instruction eligibility checks.
2. **Disabled-SVM #UD precedes privilege and operand #GP.**
   VMLOAD with SVME clear requires #UD; with SVM enabled, nonzero CPL, an
   out-of-range physical operand or misalignment requires #GP(0).
   See `24594_3.37_APM_Vol3 p534–535`. The corresponding instruction tables are
   at `p417` (CLGI), `p431` (INVLPGA), `p507` (SKINIT), `p514` (STGI),
   `p541` (VMRUN), and `p542–543` (VMSAVE).
3. **#GP precedes these SVM instruction intercepts.**
   `24593_3.44_APM_Vol2 p577`, Table 15-7, gives that ordering for VMLOAD,
   VMSAVE, VMRUN, INVLPGA, STGI, CLGI and SKINIT. Their instruction-exit handler
   alone cannot repair #GP caused by mandatory SVME backing.
4. **STGI and SKINIT have independent enable gates.**
   With logical SVME clear, either enumerated SKINIT or SVML support keeps these
   two instructions recognized. A nonzero CPL then requires #GP(0), not #UD.
   See `24594_3.37_APM_Vol3 p507, p514` and
   `24593_3.44_APM_Vol2 p648`. Same-CPU feature capture is required; SVM support
   alone does not establish these gates (`57896-3.00_PPR p87, p101`).
5. **VMMCALL has a different contract.**
   Its intercept precedes exceptions, it has no CPL check, and unintercepted
   execution raises #UD (`24593_3.44_APM_Vol2 p577, p593`). It stays under the
   existing local ABI and is excluded from the #GP opcode classifier.
6. **#GP does not provide instruction decode assists.**
   Its nRIP is reset to zero, and the instruction-byte count is zero. Bytes left
   in the decode-assist area cannot identify the faulting instruction
   (`24593_3.44_APM_Vol2 p571, p574`). The implementation fetches bounded bytes
   from saved CS:RIP instead.

For protected-mode CPL3 VMLOAD with logical SVME clear, the intended comparison is:

| Execution context | Actual SVME | Result |
| --- | --- | --- |
| Bare metal with SVM disabled | 0 | Hardware #UD |
| Earlier resident without #GP interception | 1 | Hardware #GP before the VMLOAD instruction exit |
| Implemented resident, with required fetch evidence | 1 | #GP exit (`0x4d`), then injected #UD at unchanged RIP |
| Bare metal with SVM enabled | 1 | Hardware #GP |

Capability and enablement are separate. Visible CPUID.SVM is not itself the
exception mismatch; the relevant contract is the guest's logical SVME state.

## Implemented path and boundaries

[Native boot controls](src/svm/vmcb/control.rs) install #GP interception.
[Runtime dispatch](src/host/resident/runtime/exit.rs) routes #GP before ordinary
interrupted-event reinjection. The
[#GP handler](src/host/resident/runtime/protection.rs) reconciles logical EFER
with the stopped backing state, obtains bounded instruction evidence when
needed, and then calls the transactional event resolver.

The [classifier](src/svm/protection.rs) converts only actual #GP(0) exits with
no valid EXITINTINFO, logical SVME clear, a protected execution mode, and a
recognized instruction that requires SVME. It recognizes VMRUN, VMLOAD,
VMSAVE, INVLPGA, STGI, CLGI and SKINIT, sharing the feature gates with the
[instruction-exit owner](src/svm/instructions.rs). There is no CPL3-only
shortcut: CPL0 operand #GP can also lose priority to logical #UD. Nonzero #GP
error codes, logically enabled instructions and unrelated opcodes are reflected.

The [reader](src/host/resident/fetch.rs) supports 64-bit code and 16/32-bit
compatibility code through four-level long-mode paging, plus unpaged 16/32-bit
protected startup code. It admits CPL0 through CPL3, checks execution permissions
and cache/physical-memory ownership, and applies CS base and limit outside
64-bit code. A 16-bit default code size does not impose a separate 64-KiB EIP
limit: a 32-bit branch can supply a larger offset when CS.limit permits it
(`24594_3.37_APM_Vol3 p244–245`).

Reads stop as soon as an opcode is classified and never exceed the 15-byte
instruction limit. A complete opcode at the end of a mapped page or code segment
does not require the next byte to be readable. Accepted prefixes follow the
documented legacy groups and immediate pre-opcode REX placement. Long64 null
segment prefixes can repeat when UAIE is clear. LOCK/REP forms, undefined
duplicate groups and misplaced REX are not classified as supported SVM forms;
their observed #GP remains unchanged (`24594_3.37_APM_Vol3 p44–53, p571`).

When classification needs bytes, legacy paged32/PAE, five-level paging, unavailable
or inadmissible backing, unsupported cache controls and unproved arithmetic
address wrap cause an explicit stopped-guest refusal. They are not reported as
successfully repaired faults. Temporary memory-control contention uses the
existing bounded retry path. Proven CS-limit or noncanonical instruction-address
failures retain the original #GP. Real mode and VM86 skip opcode classification:
these SVM instructions already require hardware #UD with backing SVME set, so
an observed #GP there is not evidence of this enable mismatch.

The reader requires stopped same-CPU ownership, coherent page tables and
**unchanged instruction backing**. Stopping one vCPU does not itself exclude
another CPU or device changing that memory. The current parser does not prove
arbitrary concurrent-writer exclusion or recover historical bytes fetched by
the CPU before VMEXIT. That contract limits the fidelity established here.

## Fault delivery and entry trial

[Exception reflection](src/svm/vmcb/reflection.rs) preserves the current error
evidence, RIP, registers and existing state. An already valid new EVENTINJ
request is a conflict and is never overwritten. A fault intercepted during
delivery is resolved from EXITINTINFO; saved RIP is not decoded as an SVM opcode.

AMD checks secondary exception intercepts before combining them with the prior
event (`24593_3.44_APM_Vol2 p571–573, p581`). For a secondary #GP, the resolver:

- Reflects #GP after a benign exception, external interrupt, NMI or software INT.
  Event type matters: a software INT with vector 13 is not a prior #GP.
- Queues #DF(0) after prior #DE, #TS, #NP, #SS, #GP, #CP, #VC, #SX or #PF.
  The modern contributory classification is in `24593_3.44_APM_Vol2 p309`;
  the combination rule is in `p314`.
- Reports a terminal shutdown outcome for #GP during #DF delivery.

Real/paged-real handlers receive FLAGS, CS and IP without an error-code push;
the reflected EVENTINJ encoding clears EV and its error field in that mode.
VM86 faults use protected-mode delivery. See `24593_3.44_APM_Vol2 p331, p594`.
Injected events bypass their own exception intercept, while secondary faults
during delivery remain subject to interception (`p593`).

The [entry trial](src/svm/vmcb/trial.rs) preserves the existing #GP intercept
when adding temporary #PF interception. A #GP trial exit restores canonical
controls and returns to ordinary #GP dispatch, retaining the restoration flush.
Interrupted injection on a nonexception exit is retried using EXITINTINFO
without discarding the pending-delivery obligation.

## Alternatives that do not remove mediation

The reviewed controls do not provide independent native SVME-disabled semantics:

- **Clear actual SVME on entry:** invalid guest state (`24593_3.44_APM_Vol2 p566`).
- **Enter with SVME set, then allow WRMSR to clear it:** explicitly undefined
  during guest execution (`24593_3.44_APM_Vol2 p119`).
- **Set physical VM_CR.SVMDIS:** setting it with SVME=1 faults; setting it first
  prevents enabling SVME (`24593_3.44_APM_Vol2 p646`, `57896-3.00_PPR p215`).
- **Remove SVM instruction intercepts:** does not move the privilege check;
  clearing the mandatory VMRUN intercept also makes entry invalid
  (`24593_3.44_APM_Vol2 p567`).
- **Use VMCB clean bits:** consistency checks still examine merged state
  (`24593_3.44_APM_Vol2 p567`).
- **Enable virtual VMLOAD/VMSAVE or VGIF:** assists state transfer or interrupt
  masking, without changing this exception priority (`24593_3.44_APM_Vol2 p650`).
- **Change CPUID, detector recognition or the guest exception handler:** changes
  presentation or policy rather than the CPU's fault eligibility rule.

Running outside SVM with actual SVME clear supplies a different hardware context,
but a safe resident exit/re-entry design is not implemented here. Translation or
instrumentation would require a separate execution mechanism.

## Verification and hardware validation

Host suites cover [opcode classification](tests/svm_protection.rs),
[bounded instruction fetch](tests/host_resident_fetch_gp.rs),
[#GP delivery and combination](tests/svm_vmcb_gp_delivery.rs), runtime dispatch,
and entry-trial restoration. These tests use inert VMCBs, constructed exit
evidence and supplied instruction bytes. They establish software decisions and
state preservation; they cannot establish that hardware produces the modeled
exit or successfully delivers an injected event. Existing instruction-owner
tests likewise supply the instruction exit themselves.

Validation commands for this working tree are:

```powershell
cargo test --workspace --quiet
cargo test -p svmvisor-hypervisor --lib --features native-entry-trial --quiet
cargo fmt --all -- --check
cargo xtask resident --output target/native-resident/<fresh-name>
```

The workspace suite passed 584 tests, the runtime/entry-trial suite passed 175
tests, and formatting verification passed. Resident packaging and the linked
instruction/relocation audits passed, with no undefined symbols or prohibited
FP/SIMD/xstate instructions.

The first link exceeded the image limit because of padding between BSS objects.
Sorting those input sections by alignment preserves each object's alignment and
all symbol-based references while recovering five pages. The linked image now
ends at `0x1ec000`, leaving 16 KiB before the unchanged cache-alias boundary at
`0x1f0000`. The linker assertion and external layout offsets remain unchanged;
an independent review checked stack guards, directory consumers and relocation
handling after this packing change.

The resident build compiles the real payload and runs its link/relocation and
instruction audits. Host tests and artifact audits remain separate from a target
boot test. No new resident deployment, hardware boot, raw fault-delivery test or
VMAware rerun has been performed for this report.

For hardware validation, retain the resident build identity and compare the same
CPU, firmware and Windows configuration with and without the resident. Record
raw vector/error code in a privileged harness, Windows exception status where
applicable, original and delivered RIP, RAX, CPUID.SVM/SVML/SKINIT, logical EFER,
VMCB EFER, and successful fault recovery. Restrict instruction cases to the
specified fault-producing states; legal CPL0 operations remain unsupported.

| Case | CPL0 validation | CPL3 validation |
| --- | --- | --- |
| Logical SVME=0; VMLOAD/VMSAVE/VMRUN | Test aligned, misaligned and out-of-range rAX: #UD at original RIP through the applicable instruction or #GP path | #GP exit becomes #UD regardless of rAX, including the pinned VMLOAD probe |
| Logical SVME=0; INVLPGA/CLGI | Instruction exit queues #UD | #GP exit becomes #UD |
| STGI/SKINIT independent support absent, logical SVME=0 | #UD | #GP exit becomes #UD |
| STGI/SKINIT independent support present | Confirm legal-operation refusal without executing the operation | Preserve #GP(0) |
| Logical SVME=1 | Invalid VMCB operands preserve #GP; legal operations remain refused | Preserve SVM privilege #GP(0) |
| Unrelated #GP | Preserve vector, error code and fault RIP | Preserve vector, error code and fault RIP |
| Delivery faults | Controlled benign-to-#GP, contributory/#PF-to-#DF, and #DF-to-shutdown cases | Repeat through user-origin faults and protected handlers |
| Decode boundaries and modes | Supported prefixes, page/CS boundaries, unpaged protected startup; explicit unsupported-fetch refusal | Long64 and compatibility16/32, prefixes and page/CS boundaries |

Also validate real/VM86 hardware #UD behavior, real-mode #GP frame shape, existing
VMMCALL behavior, pending-injection recovery and optional entry-trial #GP exits.
A passing VMAware result would validate its particular VMLOAD probe on that
configuration, not the full matrix or every virtualization observable.
