# Minimal native hypervisor core

The single resident payload targets Windows on AMD SVM with identity nested
paging. This development checkpoint holds every guest after the post-EBS CPU
rendezvous. It attempts a narrow native IOMMU publication only when translation
is already enabled, every old DTE passes the no-bypass audit and the unit has no
ATS support. Even successful physical completion holds guests because Windows
IOMMU, interrupt and firmware continuation is incomplete. It is not a Windows
boot candidate. The retained runtime stops on unowned PCI data I/O, ECAM writes,
reset and route-change effects. Its physical x2APIC interrupts, ordinary IPIs,
NMIs, CR3 and CPUID otherwise use native execution.
Guest MTRR accesses use shared core register banks and nested-page memory types;
the physical MTRRs retain their admitted host values. AVIC backing pages, the
physical IRQ bridge, synthetic CPUID, and per-exit TSC telemetry have been removed.

The remaining runtime owns its VMCB, EFER/VM_CR virtualization, required SVM
instruction interception, and software INIT/SIPI mailboxes so application
processors can restart without destroying their resident host. It intercepts the
x2APIC ICR for startup routing; other IPI writes are forwarded to hardware. An NMI
caught in a host INIT-acknowledgment window is deferred into guest EVENTINJ.

Internal terminal coordination now runs independently of any diagnostic endpoint.
Every CPU binds one retained firmware route expectation and permanently intercepts
CF8-CFF and both directions of MMIO_CFG_BASE_ADDR. Only admitted DWORD CF8 selector
operations, route reads and exact unchanged route writes can complete; unsupported
effects stop before native I/O. There are no temporary ECAM write windows.
CF8 forwarding also refuses an enabled same-CPU SMI I/O trap, which could
suppress the native selector cycle; no guest success is assumed in that state.
Detailed runtime faults stay in monitor-owned memory. The collective stop winner
may publish one coarse reason category after endpoint revalidation; it exports
no addresses, registers, timestamps or reader data. A missing report is inconclusive,
and CPU parking is not DMA drain. Firmware boot records remain separate.
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

The unauthenticated PROBE/SUBMIT/STEP/ABORT/CONTEXT interface and independent
ARM/QUERY experiment are removed. This is a reader-disabled interim build:
the rebuilt [client](../live-reader/README.md) refuses before any native call.
The bounded reader engine and codecs remain for offline use and a future protected
service. Native CPUID and native execution do not establish undetectability.

The [private-interface plan](PRIVATE-INTERFACE-PLAN.md) keeps analysis on this PC
while requiring authorization and sensitive result consumption outside the Windows
kernel being examined. The current one-guest runtime does not yet supply that
isolated component, protected provisioning or DMA ownership.

[Firmware IOMMU discovery](IOMMU-DISCOVERY.md) now supplies bounded preboot
inventory and documented register observations. It programs no new DMA policy.
The existing final boot record retains its compact discovery status; successful
observation does not establish isolation or enable the reader.
The full historical report is captured directly into a shared 64KiB region of the
retained pool, excluded from every guest NPT and mapped read-only/NX by each host
root. Callback checks read only its scalar header; the typed firmware payload
remains opaque to the runtime. This is CPU lifetime protection, not DMA integrity
or a current-state observation for takeover.
The [ownership components](IOMMU-OWNERSHIP.md) supply offline entry/command codecs,
bounded page-table images, independent translation walks and up to 32 permanent
4KiB-aligned NPT denial ranges. Construction sizes all backing before mutation;
cache rebuilds and permission helpers retain zero holes. The native installer,
callbacks and runtime cache rebuilds consume the same retained control manifest;
the entire observed IOMMU MMIO aperture and configuration page are denied.
Native publication freshly corroborates that manifest before effects. Initial
disabled-IOMMU drain, ATS source control, lifecycle and Windows coexistence
ownership remain prerequisites beyond the implemented narrow boot profile.
The retained shared tail has four unit slots, each containing a full 2MiB deny
device table, an empty root, command/event/completion pages and two zeroed 3MiB
composition destinations. Each destination has 256 translation/interrupt pages;
image capacity must be checked before use. Directory version 17 also reserves
a shared 0x12000-byte PCI/IVRS presentation and one 18MiB mapping workspace.
The installer prepares the candidate from its retained report; unresolved
identities remain a recorded refusal. Publication into guest firmware and a
complete native runtime owner are still required before exposure.
The complete pool, including unused capacity, remains CPU-excluded. Observation
aliases are RO/NX and hardware/composition aliases are RW/NX. A disconnected queue
producer validates wraparound and confined one-use completion cells. Storage
initialization grants no DMA integrity or ownership. DTE controls alone cannot
block SMI.

Offline requester resolution now preserves unit/source provenance and refuses
conflicting declarations. A separate binder checks a complete set of explicit,
verified banks against observed unit identities, features and exact control
apertures. Cross-module tests verify corresponding NPT holes and their cache
rebuild behavior. Neither resolver nor binder activates the native resource bank.
The [client integration milestones](../../client/INTEGRATION.md) keep Windows
device compatibility and protected interactive execution as explicit next gates.
The [Windows coexistence contract](WINDOWS-IOMMU.md) selects a virtual AMD IOMMU
with composed physical mappings; it is not yet exposed or implemented. A bounded
[NPF MOV preparer](src/svm/mmio/README.md) validates exact operands and commits
guest state only after an effect owner acts. No emulated MMIO effect is wired
into runtime dispatch.
[Static F7 firmware evidence](FIRMWARE-F7-EVIDENCE.md) records concrete indirect,
reset and IVRS-construction paths obtained with Binary Ninja 6.0.10601.

PAUSE filtering remains active through startup and while a deferred host NMI
needs another exit. Ordinary steady-state PAUSE executes
directly. Startup, cache and terminal rendezvous retain their explicit private
INIT notifications. PAUSE remains an opportunistic service point, not a timer.

The resident reuses reviewed VMCB cached groups only after a successful entry on
the same CPU and VMCB page. Typed writes invalidate their own group, permission
map edits invalidate the map group, and unknown changes, initial entry or lost
ownership invalidate everything. VMLOAD/VMSAVE still switch auxiliary state.
Physical CPU/cache diagnostic sampling runs only for SYS_CFG MSR exits; the
linked-image audit checks that selection precedes CPUID and physical RDMSR.

When the same CPU enumerates ERAPS, guest execution uses its native return-address
predictor size. Software INIT and committed MTRR/IORR writes request a predictor
clear; software EFER paging-mode changes conservatively request one as well.
A successful entry consumes that request;
invalid entry retains it. Native CR3/INVPCID keep their hardware behavior, and
monitor-only NPT maintenance does not request a guest predictor clear. These
changes preserve native CPUID; they provide no measured performance guarantee.

After the one-shot startup acknowledgement, VMMCALL queues guest #UD at the
original CS:RIP, preserving registers, flags and pending event delivery. The old
reader and experiment selectors cannot access a service at any CPL. The bootstrap
acknowledgement is not a presence probe and cannot reopen an acknowledged runtime.

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

AVIC_DOORBELL reads prepare #GP(0). SMM_CTL reads and writes do the same because
the admitted CPU fixes NoSmmCtlMSR to one; VIRTUAL_TOM accesses fault in the
admitted non-SNP profile. These cases use the existing MSR exits and preserve the
faulting RIP, registers and debug state. AVIC doorbell writes remain unsupported.
These MSR handlers perform no physical MSR accesses.

Intercepted SVM instructions prepare the covered architectural #UD/#GP faults at
the original RIP. Legal nested execution, GIF changes and secure launch remain
unsupported and still stop. The ordinary profile also intercepts #GP to resolve
privilege/operand faults that occur before the SVM instruction intercept. A proven
SVM instruction with logical SVME clear receives #UD at the original RIP, at both
CPL0 and CPL3; STGI/SKINIT retain their independent feature gates. Other #GP faults
preserve their error code. Delivery faults combine with the preceding exception
into #DF where required; faults during #DF delivery stop under the shutdown policy.
Real-mode delivery omits error-code pushes, while protected/VM86 delivery retains them.

Opcode reads are incremental and bounded to 15 bytes. They cover long64,
compatibility16/32 with four-level paging, and protected unpaged startup. Legacy
paged32/PAE decoding and inaccessible or incoherent instruction evidence are not
covered: missing evidence stops explicitly instead of fabricating #UD. Undefined
prefix combinations preserve the actual hardware #GP. Other exceptions remain
unintercepted; the retired guest entry trial cannot install a temporary #PF intercept.
This does not implement nested virtualization or establish undetectability.

This native hardware rewrite is experimental. The first cache-owner boot stopped
on the SYS_CFG `0x780000` policy refusal (`0xf400`, detail 17); this routing-window
correction still requires a target boot. Host checks establish software
consistency only. Windows boot, native AP startup, device interrupts,
NMI delivery and cache reprogramming must be retested on the target machine.

`svmvisor-hypervisor` is the only hypervisor crate. It builds the freestanding
resident library and the UEFI boot binary from one codebase. The `firmware` module
is excluded from the freestanding target. `payload.ld` links its resident image;
the UEFI binary embeds that audited image. There are no alternate launcher profiles.
The producer selects `resident-runtime` with default features disabled. Its
linked-symbol audit rejects legacy reader and entry-trial exports and retains
the architectural entry/world-switch checks. `cargo xtask resident` and
`cargo xtask card-dev` build this single payload. The old `--entry-trial` flag
is rejected. Metadata records `reader_enabled: false`, `entry_trial: false` and
`authenticated_reader: false`.

```powershell
cargo test --workspace
cargo test -p svmvisor-hypervisor --lib --no-default-features --features resident-runtime --locked
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
4. Verify retired reader/experiment calls and other post-bootstrap VMMCALLs deliver
   #UD without changing operands or exposing data. Old client binaries are unsupported
   and may fault; use a controlled exception harness, not an old client as a probe.

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
