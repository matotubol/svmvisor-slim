# Native execution and VM-exit review — 2026-09-26

This review follows `docs/README.md`: manual references below are physical PDF pages,
and register tables were checked against their indexed page images. Findings describe
the current source; the separate test machine's driver and booted artifact were not
available. They do not identify the driver's shutdown decision or measure exit rate.

## Default exit policy

| Operation | Current behavior | Source |
| --- | --- | --- |
| CPUID, RDTSC/RDTSCP, CR3, HLT, WBINVD, XSETBV | No instruction intercept in the native profile | `src/svm/vmcb/control.rs`, `configure_native_boot_intercepts` |
| Ordinary physical interrupts and NMIs during guest execution | Native delivery | `src/host/resident/runtime/interrupt.rs` |
| PAUSE | Count-filtered during startup and pending NMI/configuration work; disabled in ordinary steady state | `src/host/resident/runtime/maintenance.rs` |
| x2APIC ICR | Intercepted during guest AP startup; each CPU releases reads and writes on a successful dispatch after every admitted AP has started | `src/host/resident/runtime/startup.rs`, `finish_guest_startup` |
| EFER, SVM controls, cache/routing MSRs | Selected software owners; unsupported intercepted accesses still stop | `src/svm/permission_maps.rs`, `src/host/resident/runtime/exit.rs` |
| Local reader | Explicit VMMCALL requests; no autonomous reader polling | `src/host/resident/runtime/local/mod.rs` |

Relevant control definitions: `24593_3.44_APM_Vol2 p580, p587, p799–801`.
Routine diagnostic publication also stops after guest AP startup. Its call sites alone
are not evidence of continuous PCI traffic. The current TLB lifecycle consumes an old
flush request after entry, and reuses reviewed VMCB clean groups on the same CPU;
there is no unconditional full TLB flush on every successful exit.

The startup retirement condition requires every admitted AP to start. A guest that
deliberately leaves admitted CPUs offline can retain the startup intercepts. This is
an existing lifecycle limitation, not an exit-rate measurement.

## Changes from this review

### Direct startup wakeups to their selected CPU

`NativeIcr` already resolved a single physical destination and published its mailbox.
The runtime callback discarded that ID and sent an all-excluding-self private INIT.
It now carries the selected ID into the physical ICR. Multiple destinations, cache
rendezvous and terminal rendezvous retain their broadcast notification.

The mailbox remains authoritative. Publication precedes the wake with MFENCE, and
the routing lock is released before notification. The recipient still consumes the
private INIT through the existing VM_CR.R_INIT / #SX mechanism. This reduces wake
fan-out from all peers to one for directed startup operations; it does not establish
an exact count of saved VM exits, since pending notifications can coalesce.

Evidence: `24593_3.44_APM_Vol2 p598, p706, p721–723`; `57896-3.00_PPR p179`.

### Preserve native reads of firmware SMRAM configuration

The blanket C00101xx permission policy intercepted reads of SMM_BASE, SMMAddr and
SMMMask without an emulation owner, ending in an unsupported-MSR stop. The admitted
target documents these registers as readable, including when SmmLock is set. Only
their three read-intercept bits are now cleared. Writes and adjacent SMM/SVM controls
retain their interception. The monitor does not relocate these firmware regions.

Evidence: `57896-3.00_PPR p213–215`; `24593_3.44_APM_Vol2 p580, p601`.

### Keep guest branch records separate from host execution

The prior native profile left DebugCtl and the branch-stack controls accessible to
the guest while LBR virtualization was disabled. VMLOAD/VMSAVE do not transfer
these MSRs. Enabled guest recording could consequently include monitor control
transfers. AMD requires their state to be preserved across the world switch.

The revised entry admits LbrVirt, LbrExtV2 and exactly sixteen stack entries before
the nonreturning boundary. Assembly preserves the original controls, disables host
recording, and captures all four legacy records, the stack selector and thirty-two
stack MSRs into the guest VMCB in MSR order. Hardware then owns their guest
save/restore through LBR_VIRTUALIZATION_ENABLE. Other DebugCtl bits are retained;
guest INIT retains the captured MSRs. LBR's clean group remains conservatively dirty.

The initial capture boundary is native-to-resident entry, after the existing native
firmware callback work, with the VMCB already validated as writable under the current
root. It is not a reconstructed earlier firmware snapshot. This fixes state
ownership and adds no new instruction intercepts; it does not promise lower VMRUN
latency, since the processor now performs the required additional state transfers.

Evidence: `24593_3.44_APM_Vol2 p544, p568, p589, p601–602, p807–808`;
`57896-3.00_PPR p118, p125, p190, p234–235`.

## Local reader cost

The existing bounded engine groups four 256-byte data fragments per call. An aligned
4-KiB physical request takes four calls; an already-bound process sample takes six,
including separate identity checks before and after its data. Connection, discovery
and binding add their own calls. These counts are covered by
`reader::batch::tests::bounded_calls_preserve_bytes_and_reads_with_fewer_continuations`.

Increasing this batch size alone would hold the CPU in the monitor longer. GIF=0
defers INTR and NMI delivery (`24593_3.44_APM_Vol2 p592`); callback counts are not
elapsed-time bounds. Batch size and identity checks were retained pending target
latency measurements. The CPL3 version probe remains an intentional observable ABI.

## Remaining architectural limits

- A host-window NMI is deferred through EVENTINJ while virtual NMI support is disabled.
  AMD explicitly says an injected NMI does not block further NMIs
  (`24593_3.44_APM_Vol2 p593`). This is not a complete native NMI-blocking model.
- Native CPUID exposes SVM, but valid nested SVM operations remain unsupported.
  Some intercepted MSRs, debug completion and event-delivery cases also deliberately
  stop. Removing their intercepts without owning the underlying state is not a fix.
- Private physical ICR writes can become visible after the guest ICR intercepts are
  retired. Maintaining an independent guest ICR view needs a coherent ownership
  design, including ordinary native IPI writes.
- Later guest INIT to a running CPU is not implemented after startup routing is
  retired: the current runtime consumes it as a private wake. This differs from
  architectural INIT (`24593_3.44_APM_Vol2 p597–598`) and remains separate from
  the corrected destination selection during initial startup.

Hardware validation must use the built artifact's `summary.json`, boot with the same
CPU/firmware/OS configuration, and record AP startup completion and per-operation
behavior. Offline tests and linked-image audits cannot establish that the malware
driver's particular check changed or that its shutdown is resolved.
