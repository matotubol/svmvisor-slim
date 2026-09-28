# Native control-register review — 2026-09-29

CR0, CR2, CR3, CR4 and CR8 accesses execute on the CPU in the admitted native
profile. This review found no confirmed ordinary guest CR clobber in the current
world-switch path. It did find a host paging-boundary defect and an incomplete
profile guard, both corrected here. Legal mode transitions can still reach
unsupported intercepted instructions; this is not full bare-metal equivalence.

Three fresh reviewers independently covered instruction semantics, state
ownership, and translation/interrupt behavior. They followed `docs/README.md`,
read the relevant manual indexes and prose, inspected the register/table PNGs,
and challenged each other's findings. References below are physical PDF pages.
Implementation evidence comes from `crates/`. No target hardware was executed.

## Register ownership

| Register or operation | Actual owner and preservation | Manual evidence |
| --- | --- | --- |
| CR0 | MOV CR0, CLTS, LMSW and SMSW execute natively. VMRUN loads the guest copy; VMEXIT saves it and restores the host copy. Host WP enablement does not rewrite guest CR0. | `24593_3.44_APM_Vol2 p564, p569, p575–576, p611–612`; `24594_3.37_APM_Vol3 p420, p454, p461–462, p510` |
| CR2 | VMRUN loads guest CR2; VMEXIT saves it. CR2 is not independently restored as host state. The current host page-fault path terminates rather than returning with a changed CR2; ordinary host work does not write it. A future recoverable host page fault would need explicit ownership review. | `24593_3.44_APM_Vol2 p564, p569, p611, p807` |
| CR3 | Native MOV preserves hardware PCID, no-flush and fault semantics. Initial import preserves captured PCID/PWT/PCD bits. Operand bit63 is a no-flush hint, not stored CR3 state. Host CR3 and N_CR3 are separate roots. | `24593_3.44_APM_Vol2 p108, p220–223, p564, p611–612` |
| CR4 | Guest instructions modify the guest copy; VMRUN/VMEXIT switch it independently of host controls. Initial admission permits PGE/PCIDE but excludes features whose bootstrap support is absent. This is admission policy, not a runtime mask on guest MOV CR4. | `24593_3.44_APM_Vol2 p109, p564, p569, p611–612` |
| CR8 | With V_INTR_MASKING=0, reads use physical LAPIC TPR; writes update physical TPR and V_TPR. No ordinary world-switch CR8 write replaces it. The interrupt validator accepts hardware V_TPR writeback. | `24593_3.44_APM_Vol2 p569, p595, p802` |
| INVLPG / INVPCID | Execute natively. Guest EFER.TCE remains effective. Host ASID/NPT maintenance separately requests the required flushes. | `24593_3.44_APM_Vol2 p223, p590–591`; `24594_3.37_APM_Vol3 p430, p436–437` |
| INIT / SIPI | Software INIT resets CR2/CR3/CR4 and preserves only CR0.CD/NW plus ET. The startup LAPIC owner separately writes physical TPR=0; clearing V_TPR alone would be insufficient. SIPI changes CS/RIP. | `24593_3.44_APM_Vol2 p543, p595` |

The state-save and clean-bit layouts were visually checked at
`24593_3.44_APM_Vol2 p589, p806–807`: CR0/CR3/CR4/EFER use clean group 5,
CR2 uses group 9, and V_TPR uses group 3. Software setters dirty the corresponding
groups; native guest changes remain hardware-owned. VMLOAD/VMSAVE do not transfer
CR state (`p568`). They must not be mistaken for a second CR save/restore path.

## Corrected: inherited global translations before the first VMRUN

`firmware/native/resident/runtime.S` previously loaded the private host CR3 while
retaining admitted firmware CR4.PGE. A MOV CR3 does not invalidate global
translations. The private root in `host/resident/runtime/arm.rs` removes guard
pages, narrows RW/X permissions and installs shared aliases. Cached firmware
global entries could therefore retain old permissions or backing while early
host code already relied on the private root. The first full VMRUN flush was
later than the boundary that needed it.

The entry sequence now clears host CR4.PGE immediately before loading host CR3
and leaves PGE clear. The host tables have no global leaves. Guest CR4 was
already captured in its VMCB and is not changed by this sequence. Other host
CR4 bits, including PCIDE, are preserved; the aligned host CR3 selects PCID0
with the no-flush operand bit clear. Host PGE does not control guest global-page
selection under NPT.

The ordering matters: clearing and re-enabling PGE before switching roots would
allow a speculative global refill from the old root. Evidence:
`24593_3.44_APM_Vol2 p109, p220–222, p564, p615`. This is a conditional host
paging-isolation defect established from admitted state and architectural rules,
not a reproduced guest register-corruption incident.

## Corrected: incomplete CR profile validation

Cold configuration already cleared every CR intercept. The continuing runtime
guard checked only CR3 read/write interception. It could accept drift in other
CR reads/writes, selective CR0 interception, or post-write CR traps, despite
having no owner for those exits.

`Vmcb::control_registers_intercepted` now checks the entire dword at 000h,
00Ch bit5 and 010h bits31:16. Cold admission and continuing entry validation
use this check. The masks were checked against both text and PNGs of
`24593_3.44_APM_Vol2 p799, p801`. Regression coverage independently sets all
49 relevant bits and verifies refusal without rewriting the VMCB. This enforces
the intended policy; it does not establish that these bits previously drifted
in normal operation.

The assembly IF comment was also corrected: V_INTR_MASKING is clear. Guest
RFLAGS.IF controls guest interrupt delivery; the pre-VMRUN STI does not replace
guest IF. GIF prevents a host IRQ window around the register handoff.

## Confirmed remaining continuation limitation

A legal CPL0 far transfer into compatibility code followed by RDMSR(EFER) can
stop the monitor. Native CR instructions and native far transfers permit the
mode, but `host/resident/runtime/exit.rs` selects hardware-nRIP MSR completion
only in 64-bit code. Its fallback, `host/resident/fetch.rs::startup_instruction`,
rejects PG=1 or LMA=1 outside that mode. `svm/dispatch.rs` independently excludes
compatibility and paged legacy instruction completion.

This also bounds a legal sequence that leaves long mode and subsequently uses
legacy paging. The stop is an explicit unsupported-mode refusal, not a fabricated
architectural #GP and not silent CR corruption. Native mode and RDMSR support:
`24593_3.44_APM_Vol2 p552–554`; `24594_3.37_APM_Vol3 p473`.

Extending this needs mode-aware instruction completion, segment/IP bounds and
wrap behavior, plus event/debug-retirement tests. Simply removing the 64-bit
checks would apply the wrong continuation rules. This review leaves that separate
emulation extension unimplemented.

EFER is itself intercepted and has private SVME backing. Native CR0.PG changes
derive LMA in hardware; the logical EFER owner reconciles that bit on the next
owned access. This boundary and unsupported nested SVM execution remain relevant
differences from unrestricted bare metal.

Host CR4.MCE is deliberately enabled after installing the resident machine-check
gate. On the target, HOST_MCE_OVERRIDE is fixed at 1: a contained machine check
with guest CR4.MCE=0 can produce VMEXIT(MC) rather than hardware shutdown. The
runtime has no dedicated resume path for that exit and reaches its terminal stop.
The guest CR4 bit is preserved, but the failure behavior differs from native
shutdown. This host safety policy remains unchanged. Evidence:
`57896-3.00_PPR p101` (table image checked),
`24593_3.44_APM_Vol2 p583–584`; `runtime.S`, `runtime/exit.rs`, `runtime/stop.rs`.

## Findings rejected after cross-review

- The legacy PAE PDPE behavior described for NPT at APM2 p617 does not prove a
  target-native mismatch: p223 also describes on-demand PDPE loading on modern
  native AMD processors.
- NPT does not ignore guest CR0.CD. Either guest or host CD disables caching
  (`24593_3.44_APM_Vol2 p615`).
- A missing MOV CR8 in the switch is not a missing save/restore: physical TPR
  is deliberately live with V_INTR_MASKING=0. Startup owns its INIT reset.

## Validation and its limits

The resident unit suite checks CR drift rejection and existing CR3/PCID, TPR,
INIT, VMCB-cache and TLB-request behavior. A linked-image audit checks the actual
host PGE-clear/root-switch instruction sequence and its position before host
calls and VMRUN; mutation tests reject broken variants. The resident build
assembles and links the real switch and runs the existing symbol, relocation
and no-FP/SIMD audits.

These checks cannot establish physical CR fault ordering, TLB invalidation or
successful Windows boot. Target validation still needs initial PGE=0/1 and
PCIDE=0/1 coverage, nonzero guest PCIDs, guest CR readback around repeated exits,
and controlled native-versus-resident paging/exception cases. The host paging
change requires a hardware boot test before being considered deployed.

Native CR execution does not imply an undetectable monitor: the local reader
has an intentional observable VMMCALL interface, several execution paths remain
bounded, and no timing-equivalence claim has been measured.
