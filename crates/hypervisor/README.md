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

The [local batch reader](../../LOCAL-READ.md) adds a user-mode VMMCALL interface
after startup acknowledgement. It reads through the caller's buffers and performs
target translation and process revalidation in the resident runtime. CPUID remains
unintercepted. The new local calls bypass routine PCI diagnostic/mailbox traffic.

After startup acknowledgement, a VMMCALL unclaimed by the installed interfaces
queues guest #UD at the original CS:RIP. It preserves registers and pending event
delivery. The local reader and optional entry-trial ABI retain priority over that
fallback. Unsupported nested SVM instructions and MSR policies still stop; this
fallback does not provide nested virtualization or hide the local interface.

This native hardware rewrite is experimental. The first cache-owner boot stopped
on the SYS_CFG `0x780000` policy refusal (`0xf400`, detail 17); this routing-window
correction still requires a target boot. Host checks establish software
consistency only. Windows boot, native AP startup, device interrupts,
NMI delivery and cache reprogramming must be retested on the target machine.

`svmvisor-hypervisor` is the only hypervisor crate. It builds the freestanding
resident library and the UEFI boot binary from one codebase. The `firmware` module
is excluded from the freestanding target. `payload.ld` links its resident image;
the UEFI binary embeds that audited image. There are no alternate launcher profiles.

```powershell
cargo test --workspace
cargo test -p svmvisor-hypervisor --lib --features resident-runtime
cargo xtask resident --output target/native-resident/<fresh-name>
```

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
