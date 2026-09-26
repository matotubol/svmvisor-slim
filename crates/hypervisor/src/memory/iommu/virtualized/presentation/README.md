# Retained Windows IOMMU presentation

The PCI bank, IVRS renderer and retained scalar state share the selected bounded
guest profile: revision-2 IVRS with one type-40 form per unit, CapID 0fh/type3/
revision1, EFRSup and NpCache set, 48-bit VA/PA and GVA encoding2, HATDis=0,
EFR/EFR2=0 and a 16KiB guest aperture. IVInfo fields are encoded independently
from PCI Miscellaneous0; its low bits are EFR/DMA-remap flags, not MsiNum.

Firmware's `iommu::presentation::prepare` validates the complete acquired report,
the actual route/MCFG relationship, each observed unit identity and the complete
physical aperture. It refuses failed/partial/ambiguous acquisition, multiple
units in one PCI function and missing hardware facts. It never builds an
ordinary PCI inventory from these IOMMU observations. The renderer preserves
peripheral aliases, IOAPIC/HPET handles, ACPI HID/CID/UID values and every IVMD
reservation. ATS/CXL claims and non-string ACPI identities under the DMA-remap
flag are explicit refusals. Physical EFR capabilities are not copied.

`Storage` has a fixed integer-only layout, valid zero initialization, four banks,
64KiB IVRS capacity, and a size at most the ABI's 0x12000-byte extent. Successful
preparation remains private and inactive. `PublicationOwner` must establish the
complete topology, reservation semantics, actual initial DMA/interrupt state,
backing integrity, all-CPU traps and runtime behavior; replace the guest-visible
IVRS; and verify the exact result. Only then can `Storage::bank` or
`Storage::mmio_route` dispatch. Every publication or PCI effect failure poisons
the shared state. Checksums do not establish physical ownership or integrity.

The native `presentation::roots::Image` builder checks immutable RSDP, XSDT,
optional RSDT and original IVRS bytes, examines every referenced header, refuses
duplicate IVRS tables and resource aliases, and builds both root paths with
recomputed checksums. Other table pointers remain unchanged. It makes no native
write. A publisher still has to allocate and retain guest-readable ACPI backing,
update every firmware root before the loader caches it, and perform readback.
Private monitor pool bytes cannot be exposed as guest ACPI backing.

The currently installed native path retains candidate preparation and its exact
refusal. It does not supply a publication/effect owner, replace firmware roots or
release the post-EBS guest hold. Actual saved conflicting requester evidence is
refused by the offline test. Full ordinary PCI mediation, native table tracking,
physical publication and MSI delivery remain integration requirements; these
modules establish no Windows boot or hardware compatibility result.

Layout sources checked as text and PNG: `48882-3.11` physical pp206-210,240-242,
290-292,300-309; root layouts `ACPI_Spec_6.6` physical pp175-176,180-181.
Focused offline coverage is in `tests/iommu_presentation.rs`, `tests/svm_pci.rs`
and `tests/iommu_pci_composition.rs`. Each verification invocation uses a new
`target/windows-presentation-*` TEMP/TMP and CARGO_TARGET_DIR.
