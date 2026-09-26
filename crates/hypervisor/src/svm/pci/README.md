# Bounded virtual PCI fabric

This module implements a supplied synthetic PCI inventory. Both CF8/CFC and
ECAM reach the same configuration bank and the same effect owner. It performs
no physical configuration read/write, maps no guest pointer and opens no NPT
page. It is not an admitted representation of the saved physical machine and
is not a Windows compatibility result.

`Bus::new` validates a complete segment-zero inventory of at most 64 functions,
its parent bridges, multifunction declarations, resource ranges and up to 64
denied memory ranges. Missing functions inside that explicitly owned inventory
read as all ones; unimplemented virtual registers read zero and ignore writes.
A partial physical scan must never be used to claim this complete inventory.
Host-bridge classes and the target's processor configuration BDF range cannot
be registered. B8/BC accesses are always refused, even to an absent function,
so the observed indirect controls are not disguised as harmless register holes.

The bank implements these connected effects:

- Byte, word and DWORD lanes that do not cross a DWORD; immutable vendor,
  device, class, revision, subsystem and header identity; a coherent optional
  one-element MSI capability chain.
- Command IO/MEM enable gates BAR decoding. BME gates DMA and MSI, including
  every upstream bridge, before calling the effect owner. BME never supplies a
  DMA mapping. All assigned BARs must be valid before enabling BME.
- Memory32/Memory64 and 16-bit-policy IO BARs, immutable type/size attributes,
  all-ones sizing, two-DWORD Memory64 programming, address alignment, complete
  range and overlap checks. Sizing and relocation require decode/BME off. An
  intermediate disabled BAR value can lie outside its allowed window; enabling
  it cannot. Probe state cannot be enabled as a live resource.
- Type1 fixed primary/secondary bus identity, writable subordinate visibility,
  32-bit non-prefetchable memory and 16-bit IO windows within admitted ranges.
  Configuration visibility and downstream CPU decode obey every parent bridge.
  Window and bus changes require that bridge's decode/BME off. Its owner must
  account for descendants collectively before completing a bridge transition.
- Single-vector 64-bit MSI address/data/enable and INTx assertion/deassertion
  through the interrupt owner. INTx disable does not mask MSI. MSI addresses are
  guest values and are never executed as host stores. The interrupt line byte
  is software metadata, not a physical IRQ authority. Defined status bits have
  byte-correct RW1C behavior and device-owned error reporting.

`ConfigOwner::admit` must bind the entire inventory to its backing. Each access
revalidates that owner. `apply` receives complete before/after function states
and must finish the actual decode, DMA and interrupt transition before success.
This includes drain/revocation obligations when disabling BME and withdrawing
or reasserting INTx on command/MSI changes. `dma` must validate and compose the
whole DVA span; `interrupt` must route the guest request. Any owner failure
poisons the bus permanently because a partial external effect cannot be undone
by restoring a register shadow. Guest architectural state is committed only
after the bus operation succeeds. Offline fake owners establish none of these
physical prerequisites.

`RefuseOwner` is the native default. The runtime's tested optional-owner branch
checks the retained route, HWCR fault priority and enabled SMI I/O-trap refusal,
then uses the same stopped-IOIO adapter. The actual native caller supplies
`None`: neither retained historical inventory nor numeric ownership plans
produce a runtime PCI owner. Native CF8 selector behavior remains unchanged;
data and ECAM effects still stop. The ECAM adapter works with the existing
stopped-NPF MOV preparer, adds the target's AL/AX/EAX restriction, and requires
the preparer's caller to check UC and the complete operand translation.

## Exact unsupported scope

The separate `iommu` bank now presents explicitly identified AMD IOMMU
functions, without treating that subset as a complete ordinary PCI inventory.
`ConfigAccess` lets the stopped CF8/ECAM adapters use either bank. The IOMMU bank
rejects every unowned BDF, retains a shared selector and permanent poison state,
and routes command/MSI changes through an effect owner before committing. Its
capability chain, 48-bit widths, zero optional features, base-enable lock and
read-only IVRS range policy match the generated virtual IVRS. The native
preparation adapter retains candidate bytes in the common resident pool; it does
not activate the bank. Actual firmware publication, source closure and runtime
effects remain separately required. See
[`presentation`](../../memory/iommu/virtualized/presentation/README.md).

There is no physical-device forwarding backend, shared retained mutable bus
instance for ordinary PCI devices, native guest operand walker, all-CPU ECAM
read interception or complete native admission. The IOMMU capability model and
ACPI root-image builder are executable preparation; native ACPI publication is
not installed. All are required before exposure. Current NPT ECAM write
protection remains. No arbitrary physical IOMMU function is replaced or hidden
by the synthetic fabric.

Secondary-bus renumbering, prefetchable bridge windows, 32-bit bridge IO
windows, VGA/ISA forwarding, error-message controls, secondary bus reset,
expansion ROM, BIST, PM/D-state transitions, hotplug, PCIe control/capabilities,
ATS/PASID/SR-IOV, MSI-X, multi-message MSI and interrupt masking/pending arrays
are unsupported. The corresponding advertised optional capabilities are
absent; known command/reset effects return explicit errors. The model is not
an emulator for arbitrary existing PCI devices. It does not establish bridge
or platform reset/power coverage, SMM containment, DMA integrity or freshness.

The MOV preparer only accepts natural alignment although the direct model can
represent the PPR's wider no-DWORD-crossing lane rule. String, REP, locked,
non-accumulator and non-MOV ECAM instruction forms cannot complete through the
adapter. Disabled CF8 data routes and CF9 reset never become benign config IO.

## Evidence and tests

Read whole indexes, targeted outlines, page text and the relevant layout PNGs:

- `57896-3.00_PPR` physical pp40-42: ECAM UC/accumulator/scalar constraints,
  absent-function semantics and CF8/CFC selector layout.
- `pg054-7series-pcie-2022-12-23` physical pp42,45: common, Type0/Type1 and
  MSI register placement; pp109-111,392: command/status and DMA/MSI/INTx gates;
  pp140-141: MSI payload and INTx behavior; pp214-215: BAR resource shapes.
- `48882-3.11` physical pp240-242: single MSI header, address and data fields.
- `FIRMWARE-F7-EVIDENCE.md`: observed B8/BC indirect path and the incomplete
  reset/power evidence. It is not a chipset effects allowlist.

The generic PCI bridge window bit encodings are a bounded conventional model;
the local PG054 supplies register placement but is not a complete generic PCI
bridge or motherboard reference. Platform-specific forwarding, renumbering and
reset behavior remain evidence gaps; this model grants no physical authority.

`tests/svm_pci.rs` uses inert independent register vectors and actual stopped
VMCBs to check enumeration, status lanes, BAR sizing/address gating, bridge
visibility/windows, BME and interrupt effects, no-owner/error atomicity and
poisoned owner lifetime. These are software behavior tests, not hardware DMA,
interrupt delivery, Windows boot or installed-driver validation.
