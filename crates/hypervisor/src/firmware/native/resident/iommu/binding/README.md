# Historical unit and candidate-resource binding

`bind` is a pure, bounded check over an immutable `Report`, an explicit protected
pool extent and one `UnitAssignment` per reported unit. It returns a copied
`UninstalledBindingPlan` or a refusal with the relevant unit, assignment, region
or profile field. There is no adapter, callback, allocation, hardware access,
register write, command submission, NPT mutation or reader activation.

The plan describes only the supplied historical inputs. It grants no ownership,
current-state, quiescence, installation, reclamation or reader authority. Every
hardware transition still requires fresh corroboration, DMA integrity, complete
control/lifecycle ownership, requester and reservation resolution and an explicit
Windows/device policy. Neither all-clear enable bits nor a successful old report
establishes a reset state or makes the reset-only initialization sequence safe.

## Binding and ranges

`UnitIdentity` names the PCI segment, DeviceID, capability offset and MMIO base.
Multiple capabilities in one PCI function are architecturally possible; a
function address alone is not an identity. Each assignment must match exactly one
reported unit and every unit must have an assignment. A repeated identity,
reused Rust storage object or overlapping numeric banks is refused. The native
ABI retains four independent complete banks; more units are refused. This binder
does not allocate resources or establish their physical ownership.

Both ACPI tables must have parsed completely. Each unit needs complete PCI,
effective-aperture and MMIO observations without a hardware/acquisition error;
unused observation slots must be empty. Binding independently checks the
capability identity/revision, optional-register presence, MCFG configuration page,
enabled PCI MMIO decode/base and exact extended firmware feature images. The
snapshot's capability-chain/header-type checks remain acquisition evidence, not
something this smaller copied PCI structure can recreate or refresh.

PCSup selects the full 512 KiB, 512 KiB-aligned aperture. Otherwise the aperture
is exactly 16 KiB and 16 KiB-aligned, including when EFRSup is absent and its
features are unsupported. The observed aperture must equal that derived size.
All aperture bytes must fit the supplied physical/encryption address policy and
be disjoint from every ECAM allocation, the protected pool, known F7 FCH control
page and other effective apertures. ECAM and the pool must also avoid that
chipset page. The plan exposes the exact PCI configuration page and MMIO aperture;
it does not automatically turn them into a CPU denial policy. A separate NPT
consumer must check its representable address range, table capacity, retained
policy, every reconstruction and coordinated invalidation before any activation.

The protected pool must cover complete pages. Every bank must have the exact
`IOMMU_RESOURCE_BYTES` extent, fit wholly inside that pool and fit the observed
IOMMU PAsize. The whole pool is checked against that width too. All assigned
padding counts. The pool cannot intersect ECAM, a control aperture, any firmware
memory reservation or a configured basic hardware buffer. Reservation
disjointness is only a numeric check: it neither interprets reservation policy
nor resolves requester scopes, bypasses or firmware obligations.

Nonzero observed device-table, command-buffer and event-log bases are checked
even with their enable bits clear. An enable/run indication requires a nonzero
valid buffer. Entire basic buffer extents and pointer-field bounds are checked
without dereferencing them. They cannot overlap the pool, ECAM, the FCH control
page or any IOMMU aperture. Existing buffers belonging to an old owner may share backing with each
other; binding does not claim to validate that owner's complete memory graph or
any completion-store destination hidden in fetched commands.

Finally `ResourceStorage::verify` rechecks the full immutable candidate bank,
including every DTE, empty region and padding word. The header alone is
insufficient. This is an offline local byte check, not authenticity, live DMA
integrity or an enduring guarantee after the function returns.

## Exact candidate profile

`DenyEmptyUnsegmentedBasic` is the existing retained bank: all 65,536 DTEs have
V=TV=IV=1, four host levels, domain zero, no read/write permission, controlled
interrupt aborts and no passthrough fields. All DTEs name one empty root. Commands,
events and completion each have one empty page. There are no PPR/GA/alternate
logs, segmented tables, interrupt-remap tables, SMI filters or MARC resources.
This inert deny image is not selected as a Windows DMA policy.

The binder requires VAsize 48 or 64, PAsize 40/48/52, a nonreserved HATS encoding
(all defined values support at least four levels) and a nonreserved basic
NumIntRemapSup encoding. Any 11h/40h form with HATDis=1 is refused before HATS
is interpreted: host translation is unsupported and the nonzero root is illegal.
The legacy 10h feature-info bit zero has a different meaning and is not tested
as HATDis. It requires no meaningful optional mode that would need
the missing resources or change the selected basic profile. Those restrictions
include guest/PPR/GA processing, SMI filtering, dual logs, segmentation, guest
privilege/automatic-PPR policy, MARC, enlarged interrupt format, enhanced PPR,
host access/dirty controls, x2APIC, vIOMMU, tiered memory and alternate
root/buffer/SNP interpretation. The per-unit `profile_zero_control_mask` records
the exact meaningful fields tested; it is never a register programming value.

Support bits alone do not enable a feature. Controls explicitly reserved or
ignored when a support bit is absent are not inferred from their read values.
Architecturally reserved read fields, including CRW, are ignored. Defined
nonbasic root/buffer/cache interpretation fields and HT tunnel translation are
conservatively refused. Meaningful optional-log status residue, an enabled
exclusion range and reserved InvTimeOut encoding are refused as well. These are
local profile limits and can reject legitimate firmware configurations; refusal
is not a hardware-defect diagnosis. GAPPIEn is conservatively excluded whenever
GASup is present; GAPPISup=0 is not assumed to make that control read reserved.

Basic IommuEn, command/event enable, run, interrupt and queue-pointer values are
preserved, and need not be zero. Their acceptance supplies no drain or safe
replacement evidence. SlfWBdis and BlkStopMrkEn do not require extra tables and
remain observable. SMI filtering disabled means no SMI containment follows.
ATS support may be advertised; device ATS state, cached translations, peer paths
and IOTLB drain remain separate unresolved obligations.

## Ambiguity and validation

The report can be `Observed` or `Ambiguous` while satisfying these local checks.
The plan preserves its state and unresolved-diagnostic count; the original
report retains all declarations and diagnostics. It does not select an IVHD form,
resolve aliases or establish requester-topology closure. A separate requester
result cannot clear unrelated ambiguity, and this binding result cannot grant a
requester any authority.

`tests/iommu_binding.rs` uses independently assembled ACPI byte fixtures, exact
range boundaries, both PCSup aperture geometries, reordered and duplicate
multi-unit assignments, feature/presence mismatches, unsupported mode/status
bits, active and disabled old buffers and a corrupted final padding word. The
captured Windows ACPI fixture is table data only; its binding test adds explicitly
synthetic hardware observations and verifies that requester ambiguity survives.
The parent integration test composes numeric ranges with an independently walked
offline NPT; no native installation is triggered.

## Sources

Read from the local indexed manual, physical PDF pages; all implemented field
layouts were checked against their PNGs as well as text:

- `48882-3.11` pp205-210: multiple capabilities per function, capability identity,
  lock scope, exact PCSup aperture, physical and virtual address widths.
- pp214-216: device-table and command/event base/size fields.
- pp217-228,250-251: meaningful control fields, EFR presence, HATS, optional
  support, exclusion bypass and interrupt-format constraints.
- pp252-256: basic pointer fields, status, run indications and the distinction
  between fetch progress and the completion of previously fetched commands.
- pp298-302: exact EFR/EFR2 images and HATDis in extended IVHD forms. The
  acquisition/parser performs the complete form decoding; binding compares the
  retained images. Table 102's generic reserved 12:0 row overlaps its explicit
  HATDis bit-zero row; the explicit HATDis definition and Table 98 agree, so
  HATDis=1 is refused rather than selecting a permissive interpretation.

The module intentionally supplies no live adapter and leaves the native bank
unbound until a separately reviewed ownership transaction exists.
