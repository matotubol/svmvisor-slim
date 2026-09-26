# Path to protected interactive client reads

The retained client API can be reused, but this Windows library is not yet a
protected client. Completing IOMMU table preparation does not authenticate a
Windows process or protect displayed results from the Windows kernel.
The full same-PC interactive workflow remains the target.

## Existing reusable code

| Component | Existing behavior | Integration boundary |
| --- | --- | --- |
| `Process` wrapper | Process/module lookup and bounded typed/batched reads through `Svm` | Retain useful application semantics in the protected client environment. |
| `Svm` and reader logic | Profile/context/process checks, handle lifetime and failure handling | Production `connect` stops with `ReaderDisabled`; the test constructor is not a production admission path. |
| Batch engine and codecs | Bounded requests, continuation, identity rechecks, sequence and output validation | Reuse behind an owner that has already admitted the caller and operation. HELLO, process tokens and CRC do not authenticate callers. |
| `Exchange` | Private in-memory test boundary using `std`, allocation and deadlines | A future adapter needs a real protected peer, host clock/lifecycle and result recipient. Making this trait public would not establish those properties. |
| Win32 picker/console | Selection and display through Windows-owned UI | Cannot approve privileged requests or consume confidential results under the hostile-kernel threat model. |

The client crate currently requires Windows x64 and contains no executable
frontend. The live-reader crate uses a hosted Rust environment, files, clocks and
allocation. Porting it into a freestanding component requires those dependencies
to be replaced or supplied explicitly; changing a build flag does not provide
an execution environment.

## The next useful milestones

1. **Windows with owned device protection.** Resolve and corroborate the actual
   requester/alias topology and all hardware control paths. Select a coherent
   guest IOMMU presentation consistently; implement ownership, invalidation/completion and
   reset/failure retention. Demonstrate monitor-memory denial while Windows
   storage, graphics, input and networking still work. The current uninstalled
   all-deny table and strict configuration refusal cannot satisfy this test.
2. **A protected interactive peer on this PC.** Select and prove its execution,
   input and result-display ownership. The resident has one Windows guest context
   per CPU and direct physical interrupt delivery; it has no protected client
   scheduler or device stack. A monitor component needs trusted interactive I/O;
   an isolated client domain also needs CPU/memory/interrupt lifecycle. Record
   device availability and ownership evidence before committing to either
   architecture. A fixed-job worker does not replace the interactive requirement.
3. **One working authorized read.** Connect the protected peer to the bounded
   engine through a single admitted service. Derive identity from the actual
   protected owner, validate scope before any memory callback, and retain results
   only for the protected recipient. Demonstrate authorized HELLO and a bounded
   process read, then reject unowned callers, stale/replayed requests, reset and
   cancellation races. Extend that working path to the retained client methods.

These milestones depend on authenticated boot/code updates and protected policy.
They can be developed in parallel where independent, but production reading
stays disabled until their combined boundary is demonstrated. No second physical
PC or second Windows installation is assumed.

## Current implementation round

Requester resolution relates a numeric peripheral to an IOMMU-visible source
without guessing alias precedence. Resource binding relates explicit candidate
bank assignments to complete observed unit identities and control apertures.
Both are offline planning checks. They do not own hardware, make observations
fresh or settle firmware reservations. The selected
[Windows coexistence direction](../crates/hypervisor/WINDOWS-IOMMU.md) is now a
virtual AMD IOMMU with monitor-owned composed mappings. Its candidate profile is
not yet exposed to the native Windows guest. Offline implementations now exercise
PCI configuration mediation, copied guest-table translation, composed mappings,
virtual registers/commands/events and a multi-unit takeover transaction through
an injected backend. A combined test checks bus mastering against a composed
mapping with protected holes. These do not supply native firmware publication,
table-write tracking or hardware effects. A bounded NPF MOV preparer supplies
exact operands and guest-state commit for later effect owners. The
[implementation and recovery checkpoint](../crates/hypervisor/OWNERSHIP-CANDIDATE.md)
records the remaining admission and integration requirements.

The saved Windows IVRS fixture contains overlapping ordinary and alias
declarations. The AMD specification forbids that overlap for the same peripherals
(`48882-3.11` physical pp293,304-305). Source-backed corroboration or a diagnosed
firmware correction is required before treating those requester IDs as resolved.
The fixture itself is guest-reported evidence, not proof of current boot state.

Further generic helper layers alone will not close the client gap. The next
implementation must complete the selected Windows presentation and settle the
protected interactive peer/device arrangement, with an explicit way to test
each. The [F7 BIOS investigation](../crates/hypervisor/FIRMWARE-F7-EVIDENCE.md)
identifies specific indirect/reset paths and the alias-construction code; it
does not replace a complete platform control map or live validation.

Source anchors: [client wrapper](src/core/process.rs),
[connection](src/core/runtime.rs), [picker](src/core/picker.rs),
[reader connection](../crates/live-reader/src/svm.rs),
[test transport boundary](../crates/live-reader/src/transport/mod.rs),
[batch engine](../crates/hypervisor/src/reader/batch.rs),
[resident state](../crates/hypervisor/src/host/resident/runtime/mod.rs), and the
[full private-interface plan](../crates/hypervisor/PRIVATE-INTERFACE-PLAN.md).
