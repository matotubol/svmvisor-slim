# Minimal native hypervisor core

The single resident payload continues Windows on AMD SVM with identity nested
paging. Physical x2APIC interrupts, ordinary IPIs, NMIs, CR3 and CPUID run natively.
Guest MTRR accesses use shared core register banks and nested-page memory types;
the physical MTRRs retain their admitted host values. AVIC backing pages, the
physical IRQ bridge, synthetic CPUID, and per-exit TSC telemetry have been removed.

The remaining runtime owns its VMCB, EFER/VM_CR virtualization, required SVM
instruction interception, and software INIT/SIPI mailboxes so application
processors can restart without destroying their resident host. It intercepts the
x2APIC ICR for startup routing; other IPI writes are forwarded to hardware. An NMI
caught in a host INIT-acknowledgment window is deferred into guest EVENTINJ.

Directed startup commands now send their private INIT wake only to the selected
physical CPU. Multiple destinations and cache/terminal rendezvous retain broadcast
wakes. Readable firmware SMM_BASE, SMMAddr and SMMMask registers run natively;
their writes remain intercepted. See the [manual-backed VM-exit review](VMEXIT-REVIEW.md)
for the reviewed policy, changes and remaining architectural limits.

The PCI card terminal remains, including its configuration lifetime checks.
Legacy physical-mailbox polling has been removed. Guest SYS_CFG bit19 visibility
is per-thread; it does not change the physical host's routing or memory types.
Physical visibility changes used by low-memory reads remain serialized. The code
retains stop evidence and fails closed on unsupported exit state.

Cache-type changes park every admitted CPU, stage each private NPT, retire the
previous guest ASID before cache flushing, then install the maps and release the
CPUs. A full flush on the next VMRUN precedes ASID reuse. The initial guest ACK
gate prevents notifications before every CPU has installed INIT redirection.
The instruction boundary is still validated: invalid nRIP is never replaced by
an assumed instruction length.

This cache owner is bounded to the admitted Family1Ah Model44h CPU. It preserves
physical DRAM/I/O routing and fixed-range enablement. Logical SYS_CFG18 and
visible fixed-range routing writes synchronize even with guest MTRRs disabled.
Ranges whose logical routing differs from physical routing become inaccessible
in NPT; restoring routing restores only these marked leaves, retaining holes
and permissions. An access during that window stops with reason `0xf401` and
the guest physical address, rather than accessing the wrong bus destination.
Software instruction/page-table readers check the same NPT admission before
creating host aliases. This supports programming windows without accesses to
the affected ranges, not arbitrary DRAM/MMIO routing emulation. It refuses guest cache
types that cannot be represented using the retained host PAT and physical MTRRs.
Runtime NPTs have 64 pages each; a staged update that exceeds that capacity is
refused without installing a partial map. Ordinary memory-reader admission remains
restricted to its existing WB-memory contract.

The [local batch reader](../live-reader/README.md) adds a user-mode VMMCALL interface
after startup acknowledgement. It reads through the caller's buffers and performs
target translation and process revalidation in the resident runtime. CPUID remains
unintercepted. The new local calls bypass routine PCI diagnostic/mailbox traffic.
The required probe returns the local protocol version without a session; this is an
intentional, observable interface. Native CPUID and native execution do not make the
runtime indistinguishable from bare metal.

Local batches service up to four existing 256-byte data fragments per VMMCALL.
Before/after process validation remains in separate calls, with the original
callback and total-phase bounds. An aligned 4 KiB Physical request takes four
calls; an already-bound Sample takes six, excluding discovery and binding.
The limit bounds work, not elapsed time or interrupt latency.

PAUSE filtering remains active through startup and while a deferred host NMI or
local ECAM write window needs another exit. Ordinary steady-state PAUSE executes
directly. Startup, cache and terminal rendezvous retain their explicit private
INIT notifications. PAUSE remains an opportunistic service point, not a timer.

The resident reuses reviewed VMCB cached groups only after a successful entry on
the same CPU and VMCB page. Typed writes invalidate their own group, permission
map edits invalidate the map group, and unknown changes, initial entry or lost
ownership invalidate everything. VMLOAD/VMSAVE still switch auxiliary state.
LBR virtualization separately preserves guest branch controls and records. Native
entry captures the existing records and disables host recording before hardware
takes over their guest save/restore; admission requires the target's sixteen-entry
branch stack. The LBR clean group remains dirty.
Physical CPU/cache diagnostic sampling runs only for SYS_CFG MSR exits; the
linked-image audit checks that selection precedes CPUID and physical RDMSR.

When the same CPU enumerates ERAPS, guest execution uses its native return-address
predictor size. Software INIT and committed MTRR/IORR writes request a predictor
clear; software EFER paging-mode changes conservatively request one as well.
A successful entry consumes that request;
invalid entry retains it. Native CR3/INVPCID keep their hardware behavior, and
monitor-only NPT maintenance does not request a guest predictor clear. These
changes preserve native CPUID; they provide no measured performance guarantee.

The local reader accepts CPL3 callers only. A recognized local VMMCALL from
CPL0-2 queues #UD at its original CS:RIP, before instruction-length lookup or
reader access, preserving registers, flags and pending delivery. The supported
user-mode probe still returns its version and remains an observable interface.

The [control-register review](CONTROL-REGISTER-REVIEW.md) traces native CR0–CR8,
PCID/TLB and INIT state ownership. Host entry clears inherited CR4.PGE before
installing its private root; runtime validation rejects every CR interception
path. Legal mode changes can still reach unsupported monitored MSR accesses in
compatibility or paged legacy code, so native CR execution is not complete
bare-metal equivalence.

After startup acknowledgement, a VMMCALL unclaimed by the installed interfaces
queues guest #UD at the original CS:RIP. It preserves registers and pending event
delivery. The local reader and optional entry-trial ABI retain priority over that
fallback.

The guest keeps native CPUID and the existing SVME-capable EFER policy. VM_HSAVE_PA
now has per-CPU guest state captured before host save-area installation; guest
writes never change the physical host save area. SVM_LOCK_KEY reads return zero,
with guest writes following the admitted firmware zero-key/LOCK profile. These
controls survive guest INIT. Admission requires the exact target CPU, firmware
SMRAM locking and valid captured register formats; guest HSAVE writes additionally
check the target's address restrictions and protected SMRAM ranges.

TSC_RATIO reads and writes use per-CPU guest state captured before first entry.
Writes with reserved bits set prepare #GP(0); valid 40-bit values, including zero,
are retained across guest INIT. Entry installs physical unity scaling (1.0), which
the linked build audit verifies. Guest writes therefore do not change the running
OS's TSC/MPERF rate, matching native host-mode register semantics. This does not
provide nested TSC scaling; other unowned intercepted MSRs still require handlers.

Intercepted SVM instructions prepare the covered architectural #UD/#GP faults at
the original RIP. Legal nested execution, GIF changes and secure launch remain
unsupported and still stop. Hardware can raise an operand or privilege #GP before
the instruction intercept, so the new handler does not establish bare-metal fault
priority for those cases. Other unsupported MSR policies also retain their stops.
This is bounded conformance work, not nested virtualization or interface hiding.

Logical EFER, VM_CR, VM_HSAVE_PA, SVM_LOCK_KEY and TSC_RATIO accesses now retire
under ordinary single stepping and queue #DB at the validated following RIP.
Branch-only stepping completes these non-branch instructions without a trap.
Operand faults still retain the original RIP; TF with an interrupt shadow or
without owned debug controls remains unsupported. The [MSR retirement review](MSR-RETIREMENT-REVIEW.md)
records the manual evidence, event-replay checks, remaining gaps and target probes.

This native hardware rewrite is experimental. The first cache-owner boot stopped
on the SYS_CFG `0x780000` policy refusal (`0xf400`, detail 17); this routing-window
correction still requires a target boot. Host checks establish software
consistency only. Windows boot, native AP startup, device interrupts,
NMI delivery and cache reprogramming must be retested on the target machine.

`svmvisor-hypervisor` is the only hypervisor crate. It builds the freestanding
resident library and the UEFI boot binary from one codebase. The `firmware` module
is excluded from the freestanding target. `payload.ld` links its resident image;
the UEFI binary embeds that audited image. There are no alternate launcher profiles.
The normal producer selects only `resident-runtime` with default features disabled;
its linked-symbol audit rejects all `svmvisor_entry_trial_` exports. The optional
entry-trial interface requires the explicit `cargo xtask resident --entry-trial`
build. The local reader remains in both profiles.

```powershell
cargo test --workspace
cargo test -p svmvisor-hypervisor --lib --features resident-runtime
cargo xtask resident --output target/native-resident/<fresh-name>
```

Host tests exercise inert VMCBs and logical register state. The resident build
audits the linked artifact; neither step executes privileged guest probes. For a
target comparison, use the same CPU, firmware configuration and guest kernel with
and without the resident, and retain the artifact's `summary.json`:

1. Record per-CPU CPUID leaves and admitted firmware VM_CR before takeover.
2. Check supported EFER and VM_HSAVE_PA read/write sequences, including per-CPU
   isolation and guest INIT behavior; guest writes must preserve host backing state.
3. For invalid operands or execution modes, record the exception vector, error
   code, original CS:RIP, unchanged register state and successful fault recovery.
   A fault without recovery is not a passing result.
4. Verify the required local probe still replies and an unclaimed VMMCALL delivers
   #UD. Record the recognized interface as an expected difference from bare metal.

Valid nested-SVM execution remains outside the implemented contract. Negative
instruction tests and successful MSR round trips do not establish that VMRUN,
VMLOAD/VMSAVE or nested interrupt virtualization work. Keep these unsupported
cases separate from the conformance results for implemented operations.

| Namespace | Responsibility |
| --- | --- |
| `arch::x86_64` | CPU admission, physical register definitions and native access |
| `boot`, `guest` | Firmware observations, captured state and native continuation |
| `host::resident` | Resident ABI, private host mappings, dispatcher, card service and stops |
| `firmware` | UEFI allocation, CPU capture, boot handoff and transition assembly |
| `reader` | Bounded translation, memory reads and process discovery |
| `memory` | Address validation, identity NPT and MTRR decoding for memory admission |
| `svm` | VMCB, permission maps, exit decoding, EFER/VM_CR and INIT/SIPI ownership |
| `sync` | Nonblocking shared-state lock |
