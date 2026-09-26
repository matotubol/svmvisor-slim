# Offline host-command formats

These codecs construct and decode two numeric `u64` words. They do not own a
queue, submit commands, access physical memory, inspect an IOMMU, or report that
invalidation or completion occurred. `HostCommand` has no `Default` or arbitrary
opcode constructor. Its Rust memory layout is not a hardware ABI; `words()` is
the only serializer and returns command bits 63:0 followed by bits 127:64.

| Command | Supported profile | Rejected or omitted |
|---|---|---|
| `INVALIDATE_DEVTAB_ENTRY` (02h) | Explicit `u16` DeviceID | Every other operand bit |
| `INVALIDATE_IOMMU_PAGES` (03h), one page | Explicit `u16` DomainID, aligned 4 KiB unsigned 48-bit DVA, explicit PDE, S=GN=PASID=0 | Larger pages, arbitrary ranges, guest/PASID translations and reserved bits |
| `INVALIDATE_IOMMU_PAGES` (03h), domain | Explicit DomainID, PDE=S=1, GN=PASID=0, Address[63:12]=7_FFFF_FFFF_FFFFh | Alternate whole-domain representations or partially normalized sentinels |
| `INVALIDATE_IOTLB_PAGES` (04h) | Explicit DeviceID, shared QueueID and Maxpend; standard Type=GN=PASID=0; one 4KiB page or exact whole-IOTLB sentinel | Enhanced types, guest/PASID forms, reserved bits and undefined all-ones address |
| `COMPLETION_WAIT` (01h) | s=1, i=0, explicit f, checked 8-byte SPA and explicit 64-bit store data | No-store and interrupt completion, reserved address bits |

Every other opcode is rejected, including interrupt-table, PPR,
prefetch, optional invalidate-all, and guest/vIOMMU commands. Decoding always
returns a value or an error for one fixed 16-byte command and never partially
writes caller state. It rejects unsupported and ignored nonzero bits rather
than normalizing another owner's command stream.

A page operand is a device-visible address, not a system physical address.
Its entire 4 KiB page must fit the existing four-level unsigned 48-bit profile;
sign-extended x86 addresses are rejected. Physical address width and an SME
encryption bit do not constrain this DVA. The whole-domain sentinel is a special
command encoding, so neither the DVA bound nor physical address policy applies.
The page-table examples in Table 14 have a narrower physical-address field;
the command uses the explicit whole-domain value specified on p126.

Completion addresses receive `AddressPolicy` checks over all eight bytes,
including alignment, end-of-range arithmetic, width, and excluded encryption
bits. Address zero and all `u64` store-data values remain legal numeric values.
Success does not show that a destination is system RAM, allocated, coherent,
retained, private, protected against DMA, or safe to overwrite. A future owner
must constrain completion destinations to its own suitable protected backing,
independently establish platform evidence, and maintain that backing throughout
the command lifecycle. No capability, token, installed-state object or ownership
claim is created here.

## Ordering and remaining owner obligations

The following are hardware/lifecycle requirements, not behaviors of this codec:

- Device-table invalidation alone does not invalidate translation cache entries.
  Removing a device from a domain also requires page/domain invalidation (p125).
- One-page invalidation is sufficient only when the largest affected mapping is
  4 KiB. PDE=1 ensures invalidation of a cached directory entry when the range
  covers all its pages; hardware may invalidate more than requested. The
  whole-domain constructor always sets PDE=1 (pp126-127).
- After updating tables and submitting appropriate invalidations, actual
  completion must be observed before relying on the fabric-drain guarantee or
  reclaiming pages. Encoding a store, choosing data, reading a queue head, or
  merely comparing memory with the expected value is not a freshness protocol.
  A future owner must design synchronization, coherent visibility, store-data
  reuse rules, bounded waiting and hardware-error handling (pp123-124, pp138-139).
- f=0 permits subsequent independent commands to begin before this completion;
  f=1 withholds subsequent commands until it finishes (p124).
- Devices with their own IOTLB require physical IotlbSup admission, current
  complete requester coverage and device-specific QueueID/Maxpend values.
  Issue IOMMU table/domain invalidations before remote invalidations and require
  matching completion afterward. The codec provides no capability discovery,
  device quiescence, ATS disable, timeout recovery or source/fabric drain for an
  initially disabled IOMMU. Native cold admission still rejects ATS-capable units.

## References

All references are physical page numbers in `docs/48882-3.11`. The text and PNGs
were checked for pp123-128 and pp138-139, plus p80 and p82. The manual's complete
INDEX.json and relevant command and ordering TOC entries were read first.

- p123 Figure 43: 128-bit command and opcode position.
- pp124-125 Figure 44 / Table 34: completion address, data, s/i/f fields.
- pp125-126 Figure 45 / Table 35: device-entry invalidation. Table 35 lists only
  +04[27:20] as reserved, while Figure 45 shades +04[27:0] as reserved. The strict
  profile follows the figure and rejects every non-opcode bit of that dword.
- pp126-128 Figure 46 / Table 36: page invalidation and whole-domain sentinel.
- pp128-130 Figure 47 / Table 37: remote invalidation fields, shared queue
  identity, exact whole-IOTLB sentinel and required IOMMU-before-IOTLB ordering.
- pp81-82 / Table 15: four-level unsigned DVA constraint; p80 Table 14 explains
  size encoding but is not substituted for the p126 command sentinel.
- pp138-139: inter-command ordering and outstanding DMA-drain requirements.
