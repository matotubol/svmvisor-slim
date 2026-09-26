# Ownership implementation and recovery checkpoint

This checkout contains native integration that has only been exercised offline.
It is **not an ownership-enabled Windows cold-boot candidate**. The post-EBS
bootstrap now holds every guest. Its narrow physical publication requires an
already enabled IOMMU, no ATS capability and a complete audit of old translated
DTEs. Actual matching completion is required; even success does not release
Windows. The reader, authenticated reader, entry trial and diagnostic read
remain disabled. No flag or historical inventory can authorize their activation.

The selected contract remains [WINDOWS-IOMMU.md](WINDOWS-IOMMU.md). New executable
software components live in `svm/pci`, `memory/iommu/virtualized`,
`memory/iommu/physical` and `firmware/native/resident/iommu/ownership`. Their
offline adapters do not establish native ownership. The current resident still
refuses unowned physical PCI data cycles and ECAM writes.

## Native admission blockers

- The saved IVRS has overlapping ordinary/alias declarations and incompatible
  source settings for 00a0/00a5. Obtain a fresh trusted preboot inventory and
  correlate actual bridge routing, requester aliases and the ACPI identities.
  F7's alias-construction disassembly explains the bytes but does not authorize
  a precedence rule. See [FIRMWARE-F7-EVIDENCE.md](FIRMWARE-F7-EVIDENCE.md).
- The B8/BC indirect fabric path and the FCH reset/power paths need a complete
  admitted control policy. Native construction now denies the known FCH control
  page and captures its exact three 16-bit PM routing words. Every vCPU intercepts
  those observed PM ports and verifies its IOPM; takeover rechecks routing before
  and after publication. F7 identifies CF9, platform base 0xfed80000 +0x310,
  0xfed803d2 and dynamic ports obtained at +0x360/+0x362/+0x368. Their observation
  is not a complete control map, and SMM remains trusted. Admission rejects
  PM/CF8-CFF overlap and ECAM/IOMMU windows overlapping the FCH page before
  discovery issues those configuration or register probes.
- Guest firmware publication, activated native PCI/vIOMMU state, arbitrary CPU
  table-write interception, DMA table-write exclusion, physical interrupt/event
  translation remain required. A native physical-effect backend now performs
  the narrow boot publication, but it does not provide these Windows runtime
  mechanisms. ABI17 allocates shared candidate PCI/IVRS state and an 18MiB
  workspace. Real NPT source guards and checked guest-memory adapters are wired
  at their boundaries, but a coordinated arbitrary-write step and physical DMA
  source barrier remain required. Immutable snapshots cannot substitute for them.
- The installed pool now retains four separate writable hardware banks and two
  3MiB composition destinations per unit, with the entire allocation CPU-excluded.
  Native admission must reject more than four units and each composed image must
  fit its 256 translation/interrupt pages. Allocation and private CPU aliases
  establish neither DMA integrity nor ownership of consumed storage.
- Initial disabled-IOMMU or ATS-capable hardware needs a real source/fabric
  drain and device-IOTLB policy. CPU parking, a disabled DTE I bit and an empty
  command ring cannot establish those facts. The implemented enabled/no-ATS
  path retains IommuEn, invalidates old translated state and waits for matching
  hardware completion. S3, S4, reset, rebind and hotplug are
  unsupported ownership transitions until an explicit policy implements them.
  Parking CPUs and command-head progress do not drain DMA.

## Diagnostics

Only the collective terminal winner can attempt a public coarse stop record.
The output has six closed categories: other, configuration access, configuration
route, SMI configuration trap, memory policy and architectural control. It has
no private context, addresses, timestamps or payload. It requires the all-CPU
barrier, both nonblocking guards, UC memory types, unchanged configuration, card
identity/build IDs and boot ID. Endpoint loss, host faults and barrier timeouts
may leave no public record. Historical snapshots contain boot records; they are
not evidence that this new runtime publication has executed.

## Offline-verified recovery material

On 2026-09-26 the existing `Assert-CardPayloadRestoreSource` validator checked
all 22 saved payload sessions: matching 1 MiB double backups, SHA-256 and the
required geometry/backup transcript markers. The 14 host-only payload flashing
test groups also passed. No hardware was accessed by these checks.

The latest saved session is `4990eb79efd0431c849804d8f41086cc`. Its pre-write slot
has SHA-256 `b505ca3359b4412cfc8f3a041de337fba6a87294f34eac8e5ef6e9210d9769cc`.
This verifies restore-source integrity, **not** that this slot is a working
Windows boot or that it is still the card's current contents.

After separately authorized physical testing, payload-only rollback uses:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File firmware/card/flash-card.ps1 `
  -Action RestorePayload -RestoreSession 4990eb79efd0431c849804d8f41086cc `
  -AdapterKhz 1000 -ConfirmFlash
```

That procedure makes a fresh double backup, writes only necessary sectors 64..79,
verifies the complete slot, and does not activate it. Prefer the fresh pre-test
session ID when it has been validated as the intended working rollback image.
A failed or hanging target must be powered down before removing the PCIe card;
booting without its option ROM is the physical bypass of this delivery path.
Hardware handling, power cycling and the restore command were not performed.

The separate recovery-bitstream pin points to
`target/firmware/card/recovery/a94c8fd7dc2441008d89bc52cf034b1b`, which is absent
in this checkout, and declares `PhysicalFixtureTest = 'NOT_RUN'`. Do not depend
on that bitstream for recovery. Recover or rebuild the pinned artifact and
demonstrate the chosen physical recovery path before an ownership experiment.

The earlier offline component checkpoint remains in
`target/windows-iommu-candidate-validation/REPORT.md`. Current native integration
results belong in `target/native-ownership-integration-validation/REPORT.md`;
that report must name the exact packaged artifact and distinguish offline
results from physical evidence.
