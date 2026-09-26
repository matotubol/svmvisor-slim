# Windows IOMMU coexistence contract

The implementation direction is a virtual AMD IOMMU with monitor-owned physical
tables. Windows owns its virtual device, domains and mappings. The monitor
composes each device address -> guest physical address mapping with its admitted
guest -> host mapping and excludes all protected host memory. This is a selected
design, not an exposed native device or a Windows compatibility result.

The current native profile constructs IOMMU control denials and holds every
guest after its narrow physical takeover. The reader remains disabled. See
[implemented ownership components](IOMMU-OWNERSHIP.md).

The [disconnected software core](src/memory/iommu/virtualized/README.md) now
implements guest-format decoding, immutable-snapshot composition and virtual
register/command behavior correlated with physical-publication receipts. The
[PCI model](src/svm/pci/README.md) and
[takeover transaction](src/firmware/native/resident/iommu/ownership/README.md)
provide testable companion effects. Candidate PCI/IVRS state, bounded native
source guards and a narrow cold-publication backend exist. No native guest
IVRS/capability publication, complete live table tracking or mapping owner is
connected; this candidate
profile remains unexposed. See [activation and recovery gaps](OWNERSHIP-CANDIDATE.md).

## Why retain the Windows remapping contract

Windows graphics can use nonidentity DMA addresses and requires the driver to
keep its hardware silent during a domain switch. A fixed identity table cannot
implement those operations. This describes documented Windows behavior, not a
claim that a particular GPU currently uses it.
[Microsoft WDDM DMA remapping](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/iommu-dma-remapping)

The saved IVRS advertises DMA-remap support. Microsoft's OEM contract associates
that declaration with preboot protection, an enabled IOMMU at ExitBootServices
and PCIe native control. Guest firmware, PCI capabilities and actual behavior
must agree; silently accepting Windows programming would break that contract.
[Microsoft OEM requirements](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection)

Hiding the IOMMU before OS enumeration is a different platform contract. There
is no evidence here that this Windows installation and its device drivers accept
that contract, so it is not the selected implementation direction.

## Candidate guest baseline

The following bounded profile is proposed for development. It must stay
unexposed until its complete behavior exists. It is not a certified Windows
minimum, and actual driver evidence may require expansion.

| Surface | Proposed behavior |
| --- | --- |
| ACPI | Internally consistent revision-2 IVRS, one type-40h form per virtual unit; resolved peripheral, IOAPIC, HPET and ACPI identities; applicable IVMD semantics. HATDis=0. Never copy physical features into this virtual contract without implementing them. |
| Address widths | VA/PA=48 and GVA encoding 2, only after checking every exposed resource. These differ from the saved physical IVRS's VA=64. |
| PCI capability | CapID=0fh, CapType=3, CapRev=1, EFRSup=1, NpCache=1; CapExt/HtTunnel/IotlbSup=0. Virtual base-enable/lock and range semantics, coherent capability chain and basic MSI. |
| Optional features | EFR/EFR2=0, including no PASID, ATS/PPR, GA/AVIC, x2APIC remapping, MARC, segmentation or hardware-vIOMMU advertisement. HATS=00 is a maximum of four levels. |
| Register aperture | 16 KiB virtual aperture, naturally aligned 1/2/4/8-byte accesses. Trap the complete physical aperture even when larger. Defined lane, reset, read-only and RW1C semantics are required. |
| Core operation | Device-table, command/event base and size, control, exclusion, feature, head/tail and status registers, including actual enable/stop/restart behavior. |
| Commands | All baseline COMPLETION_WAIT, INVALIDATE_DEVTAB_ENTRY, INVALIDATE_IOMMU_PAGES and INVALIDATE_INTERRUPT_TABLE behavior. Legal queue sizes span 256..32768 entries. Unsupported optional commands receive the specified error/event behavior. |
| Interrupts | Basic IRTE GuestMode=0, fixed and arbitrated delivery, physical and logical destinations, RqEoi, suppression, remap-disable and virtual event/completion MSI. |

Sources: `48882-3.11` physical pp73-85,91-92,120-126,131,205-228,252-256,
290-309. The feature profile is a proposal derived from these definitions.

The current `HostDeviceEntry`, `HostPageEntry`, interrupt codecs and host walker
encode a restricted monitor output format. They are not general guest decoders:
Windows input also needs legal Mode=0, depths 1..4, skipped levels, large leaves,
ignored bits, V/TV/IV behavior and cumulative permissions.

## Required runtime boundaries

1. Publish the virtual firmware contract before Windows enumerates devices.
   Trap reads and writes to real IOMMU configuration and MMIO on every vCPU.
   Ordinary PCI enumeration, BAR, command/BME, interrupt, bridge and power
   effects need explicit compatible mediation as well.
2. Decode and validate each stopped CPU access, then apply exactly its admitted
   virtual effect, then commit guest architectural state. The
   [NPF MOV preparer](src/svm/mmio/README.md) supplies only the first and last
   mechanisms for its documented subset. It does not implement the device or
   justify forwarding an arbitrary physical access.
3. Track active guest translation structures coherently across CPUs, aliases,
   creation, replacement and lifetime. Compose accepted mappings into private
   physical images. Guest disable, bypass and exclusion states must still pass
   through the monitor's host exclusions. Guest addresses never become native
   queue, event or completion pointers.
4. Publish physical updates with the required invalidations and ordering.
   Complete a guest command only after its matching physical work completes.
   A command-head sample means fetched, not drained; numeric tokens and CPU
   parking cannot establish completion (`48882-3.11` pp124-126,138-139).
5. Compose interrupt behavior and translate hardware events to guest identities
   and addresses. Preserve Windows interrupt delivery without exposing internal
   host pointers or permitting a guest to select an unrelated physical domain.
6. Retain controls, mutable private backing and synchronization across reset,
   NPT reconstruction and power transitions. Lost hardware state requires the
   specified admission/restoration policy before protected work resumes.

NpCache=1 requires guest invalidation after every PDE/PTE change. It does not
eliminate table-write tracking: old DTE V=IV=0 transitions and some old IRTE
RemapEn=0 transitions may omit invalidation. These can precede immediate device
use. DMA mutation of tracked table memory also needs a policy; NPT alone only
observes CPU access. A MOV-only MMIO decoder cannot mediate arbitrary table
initialization, copying or atomic updates. The IOMMU does not queue or throttle
failed device accesses, so faulting initial DMA is not a transparent way to
discover new mappings (`48882-3.11` pp77,121,206).

## Platform evidence and validation

The captured IVRS has an ordinary/alias overlap inside each individual form,
different settings for sources 00a0/00a5, and three IVMD exclusion reservations.
The resolver correctly retains those conflicts. The
[F7 firmware investigation](FIRMWARE-F7-EVIDENCE.md) identifies code that can
generate the unusual alias range; it does not resolve current requester routing.

The saved EFR has hardware-vIOMMU bit55 clear. Even where that optional feature
exists, its GAEn and presentation requirements do not fit the current direct
physical-interrupt profile (`48882-3.11` p193). It is not a substitute for this
software owner.

Before activation, obtain fresh trusted topology/control evidence, complete the
indirect fabric and reset/power policy, and validate the guest profile against
the installed Windows build and drivers. Static firmware analysis identifies
specific paths to investigate; it cannot prove every possible path is covered.

The first end-to-end ownership test needs a real admitted unit and requester:
Windows creates a nonidentity mapping, the monitor publishes it, physical
invalidation completes, and the device performs DMA and delivers interrupts.
Protected-memory and alternate-reprogramming attempts must fail. Broader Windows
storage, graphics, input, network and lifecycle validation then establishes the
deployment claim. Synthetic queues and register models are useful preparation
but cannot provide that hardware evidence.

Protected interactive client execution and authorized reading remain separate
milestones in the [full interface plan](PRIVATE-INTERFACE-PLAN.md).
