# Firmware IOMMU discovery

This is the read-only discovery part of the [private-interface plan](PRIVATE-INTERFACE-PLAN.md).
The live reader remains disabled. An inventory can identify prerequisites and
inconsistencies; it does not establish authenticated boot, DMA ownership or a
protected client.

The next [ownership components and control-path review](IOMMU-OWNERSHIP.md)
provide offline entry/command formats, a bounded page-table image builder and a
host-walk checker without installing an IOMMU policy.

No BIOS ROM binary is needed for this component. Indexed AMD/ACPI/UEFI manuals
and the captured table fixtures supply its structure and offline test inputs.
A later firmware execution must corroborate what this machine actually exposes.
A ROM file cannot establish the active mappings, register state or control owner.

## Components

- `memory/iommu` parses bounded immutable IVRS and MCFG snapshots without hardware
  access. Reports own their records. Checked lengths, checksums and resource limits
  precede parsing; partial parse results cannot be used as a completed inventory.
- Its [requester resolver](src/memory/iommu/requester/README.md) answers numeric
  requester and range queries with unit/source/provenance evidence. Contradictions
  carry original offsets; no form precedence or global diagnostic clearing is
  introduced. Numeric queries cannot establish ACPI, IOAPIC or HPET identity.
- `firmware/native/resident/iommu` acquires an ACPI 2+ root through the UEFI system
  table, follows XSDT, copies IVRS/MCFG, then corroborates documented IOMMU PCI and
  MMIO state through an injectable read-only adapter. It does not follow captured
  device-table or queue pointers.
- The native activation adapter supplies current memory-map, physical-width,
  paging and cache-type checks. Its pre-ExitBootServices observation is separate
  from resident CPU/NPT admission. Unsupported discovery does not enable any
  fallback reader or falsely assert a protection boundary.

Root cache admission interprets CR3[11:0] as a PCID when CR4.PCIDE is set;
otherwise PWT/PCD remain refused. This does not weaken PAT, MTRR or parent-entry
cache checks.

The PCI adapter uses validated uncached ECAM reads on the admitted CPU profile.
It does not write the legacy configuration-address port, enable MMIO decoding,
clear status bits, change IOMMU mappings or take over firmware queues. Firmware
table, RAM page-table and device-register accesses use separate admission rules.
ACPI reclaim/NVS handling does not widen the existing runtime memory reader.

Both extended-feature register images are corroborated when EFRSup permits their
reads. The effective register aperture is retained: 16 KiB normally, or 512 KiB
with PCSup. Units are visited by ascending physical base while retaining their
original report indices. An overlapping or unknown aperture stops further unit
acquisition; no neighboring unit is probed through a known overlapping window.

Large temporary table buffers use fixed boot-only firmware backing. The complete
report is captured in place into a dedicated 64KiB region of the retained monitor
pool after current descriptor, native mapping and cache admission. No firmware
table or scratch borrow survives capture. Partial/failed observations and all
retained ambiguity, aliases, reservations and feature declarations remain intact.

Every private host root maps the full assigned tail supervisor read-only/NX;
both initial and callback NPT construction exclude it with the rest of the pool.
Cache rebuilds retain that absence. A fixed 64-byte integer-only header records
capture context and completed publication. Callback checks copy only that header
after native mapping admission and compare the common route/profile/CPU count.
Route checks bind actual acquisition before, during and after its reads.

The payload is a live typed firmware value, not a serialized cross-image ABI.
The runtime leaves it opaque. The initial observation can become stale before
takeover; header consistency does not revalidate register state or authenticate
DMA-writable memory. Scratch stays outside the pool and is not retained authority.
This is CPU lifetime support, not protected analysis memory or DMA ownership.
The shared tail also contains a separate uninstalled resource bank described in
[IOMMU-OWNERSHIP.md](IOMMU-OWNERSHIP.md). Its preparation never follows the
historical report's device-table or queue pointers and never changes hardware.

## Inventory semantics

The parser normalizes IVHD types 10h, 11h and 40h by IOMMU identity while retaining
each form and its declarations. Different versions' raw feature encodings are
not assumed interchangeable. Requester ranges, alias source IDs, special devices,
ACPI identities and firmware memory ranges remain explicit. IVMD records retain
their preceding IVHD association and their own device scope.

An IOMMU exclusion range is a translation/access-check bypass. It is not denied
DMA memory. Future ownership must prevent any applicable bypass from covering
monitor or analysis memory, including IOMMU control structures.

Numeric overlaps and differing declarations produce diagnostics instead of
first-entry or last-entry precedence. In the captured machine fixture, numeric
requester and alias ranges overlap at `ff00..fffe`, which the AMD IVHD rules
forbid for the same peripherals. The resolver refuses those IDs. The unaffected
`1000..feff` range resolves locally, while `ffff` reaches a separate conflicting
shared-source setting. The saved guest-reported table still needs corroboration;
these findings do not establish an unusable board or authentic current firmware.
Compatible ACPI or special-device instances may share a source. Conflicting DTE
settings on that same source require explicit resolution and cannot yield
`observed`, including special-to-special, numeric, alias and ACPI declarations
within one normalized unit or across its IVHD forms.

MCFG addresses are relative to bus zero even when an allocation starts at another
bus. Disjoint allocations in one segment are permitted. Overlapping bus ownership
or physical ECAM windows are rejected.

## Bounds and unsupported cases

Each ACPI table is limited to 64 KiB. The parser permits at most 16 normalized
units, 48 IVHD forms, 256 requester scopes, 64 special devices, 64 ACPI devices,
64 bytes per UID, 64 memory regions, 32 MCFG allocations and 128 diagnostics.
These are local implementation limits, not architectural maxima.

Acquisition bounds include 1,024 UEFI configuration entries, 512 XSDT entries,
256 bytes for RSDP and 4 KiB for the system-table header. Legacy-only ACPI roots
are unsupported. Duplicate roots/tables, unknown formats, address overflow and
unverified mappings remain explicit failures. The native descriptor policy is
conservative: firmware structures must be allocated firmware RAM, ACPI data must
be reclaim/NVS memory, and register pages must be described as MMIO. A platform
using a different valid reservation convention may therefore be unavailable to
this version.

## Existing boot record

The final stage-5 record preserves a compact observation so earlier discovery
messages cannot be lost when the journal's latest record changes. Its version-2
detail word contains the normalized unit count, number of completed MMIO
observations, status and existing terminal endpoint indicator. The offline
[snapshot decoder](../../firmware/card/read_snapshot.py) also accepts legacy
records. The exact format is in [card documentation](../../firmware/card/README.md).

Statuses distinguish observed, unavailable, unsupported, malformed, ambiguous and
partial. Even `observed` describes only the implemented acquisition. It does not
approve static DMA ownership, require a shadow vIOMMU, attest Windows compatibility
or authorize reading. Register values, physical addresses, queue contents and
runtime analysis results are not added to this record. There is no guest query.

## Remaining evidence

The next ownership implementation still needs a complete fabric/requester policy,
protected real IOMMU tables and control paths, invalidation, reset/power lifecycle,
ATS/peer-to-peer coverage and an explicit Windows coexistence design. The current
inventory is not a full device enumeration or an audit of all reset mechanisms.
Trusted interactive input and results remain a separate required boundary.

Hardware acceptance must demonstrate actual denied DMA and resistance to guest
reprogramming, alongside working Windows storage, graphics, input and networking.
Offline parser/acquisition tests cannot substitute for those observations.

## References and fixture provenance

Local physical pages: ACPI_Spec_6.6 pp175–176/181; 48882-3.11 pp205–228,
250–256 and 290–309; 57896-3.00_PPR pp40–41/210. Table/register layouts are
cross-checked against their indexed PNGs as required by docs/README.md.

The local ACPI manual delegates MCFG's payload layout to PCI Firmware. Its
structure is cross-checked against the official
[TianoCore definition](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h).
Bus-zero addressing is documented in the
[kernel PCI documentation](https://docs.kernel.org/PCI/acpi-info.html); multiple
disjoint ranges per segment are confirmed by the
[PCI-SIG amendment](https://pcisig.com/PCIFirmware/ECN/Firmware/EnablingMultipleBaseAddressesperPCISegmentGroup).

The 484-byte IVRS and 60-byte MCFG fixtures were obtained through Windows firmware
table APIs on 2026-09-26. They are untrusted guest-reported samples, not authenticated
firmware or evidence of active enforcement. The
[retained fixtures and capture metadata](tests/fixtures/iommu/windows-2026-09-26/README.md)
include byte counts, SHA-256 hashes and the original acquisition provenance.
