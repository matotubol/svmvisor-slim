# Software AMD IOMMU core and bounded native primitives

This is executable preparation for the selected software virtual IOMMU design.
It is **not a complete guest device or an exposed Windows contract**. Nothing in
this directory publishes IVRS or PCI capabilities, installs MMIO/NPT handlers,
captures live guest memory, admits a physical owner, or performs native I/O.
Optional feature reads are zero; physical hardware features are never copied
into this model. The native activation gate remains closed.

## Implemented behavior

- `guest` decodes the ordinary 48-bit, no-optional-feature guest DTE/PDE/PTE
  profile separately from the restricted host output codecs. It handles V/TV/IV
  independently, ignored inactive fields, Mode=0 and depths 1..4, skipped levels,
  cumulative permissions, absent entries with ignored payload, default large
  leaves and NextLevel=7 size encodings. DTE SysMgt and IoCtl values are retained;
  ordinary-memory walking does not implement their special transaction spaces.
  Public decoded values are revalidated before arithmetic.
- Basic IRTE decoding supports 1..2048-entry tables, fixed/arbitrated delivery,
  physical/logical destinations, RqEoi and suppression. The pure evaluator returns
  guest APIC delivery or abort actions for basic interrupts, including IV/IntCtl
  bypass and RemapEn=0. Those guest identities are not physical interrupt targets.
- `snapshot` owns copied pages, rejects inconsistent aliases, and records DTE,
  page-table and interrupt-table read dependencies. `TrackedSnapshot` becomes
  permanently stale after an observed CPU, DMA or monitor write intersects any
  source host page; aliases share that invalidation. A new compose operation
  refuses stale input. There is no automatic live write observer.
- `snapshot::Capture` discovers the complete device/translation/interrupt page
  closure in retained scratch, including every old V=IV=0 DTE and the full
  potentially unaligned 2048-entry interrupt extent. Missing protection is never
  supplied by this object: each requested source must be CPU- and DMA-protected
  before the native caller supplies its bytes. Capacity, entry-work exhaustion,
  malformed links and contradictory aliases poison the entire capture.
- `compose` traverses the whole captured guest tree, converts every accepted
  DVA->GPA leaf through the explicit GPA->HPA map, intersects permissions and
  creates host-protected holes. It also handles virtual disable, V=0, Mode=0 and
  exclusion identity mappings through the same host policy. All captured table
  pages lose DMA write permission through every physical alias. The result feeds
  the existing `image::build`, which additionally excludes the entire assigned
  output-table backing and emits its restricted four-level host format.
- `compose::mixed` builds and verifies nonidentity output using ordinary AMD
  1GiB/2MiB/4KiB leaves in at most 256 caller-owned pages. Exact capacity and
  complete backing/protected-output checks precede mutation. Reused output is
  completely cleared; the independent walker checks its restricted format.
- `registers` implements the 16KiB aperture with naturally aligned 1/2/4/8-byte
  lanes, reset values, ignored unsupported-feature writes, baseline control,
  device/command/event bases, exclusion, pointers and RW1C status. All legal
  256..32768-entry queue lengths are accepted. Base writes reset ring pointers;
  running-engine register edits and invalid bounded ring motion refuse. Event
  overflow stops logging, and restart requires EventLogEn 0->1. CmdBufEn restart
  is separately level-sensitive and only occurs if its actual lane was written.
- `device` captures and decodes one command per step. It supports completion
  store/interrupt/flush operands and device, page/range and interrupt-table
  invalidations. Optional commands cause ILLEGAL_COMMAND_ERROR and stop command
  processing without advancing the offending head. Missing copied command
  memory causes COMMAND_HARDWARE_ERROR using the guest command address. Event
  insertion, reserved ring slot, wraparound, overflow and interrupt coalescing are
  modeled. Basic I/O page-fault records accept guest identities and DVA explicitly.
- Policy-changing writes and every accepted command produce `PhysicalWork` with
  exact physical unit, epoch and generation. Guest completion requires the shared
  physical owner's `DrainReceipt` with matching key and mapping-publication
  purpose. A takeover receipt, wrong generation or queue-head sample cannot
  complete it. Guest command head advancement means captured only. In-flight
  event state survives subsequent physical completion. Completion and event
  writes target checked copied guest RAM, never native pointers.
- `GuestRam::from_tracked` derives table-write guards from all source host pages
  and the entire guest map. This rejects monitor event/completion writes through
  aliases that were not themselves present in the capture, before changing RAM.
  `GuestRam::new` is for independent copied RAM with no associated table sources.
- `GuestMemory` lets the same event/completion state machine use the native
  retained-scratch writer. `tables_changed` creates an exact keyed publication
  independently of guest commands. An explicit interrupt acknowledgement lets
  adapters preserve the latch across a failed delivery; the adapter must call it
  only after its real delivery operation succeeds.

`host/resident/iommu_runtime.rs` initializes one shared 18MiB workspace in place,
including copied pages, closure and composition scratch plus separately bound
per-unit `Device` state. It never borrows zeroed enum payloads. The global lock
serializes software access; it cannot establish CPU or DMA source exclusion.

`host/resident/runtime/viommu.rs` provides native source installation/copy and
guest output primitives. Installation uses `memory/npt/table_guard` to split
actual per-CPU NPT leaves to 4KiB, remove table write permission while preserving
reads, and request a complete nested-TLB flush. Cache rebuilding reapplies the
retained policy, including write denial across quarantine/restore. The scratch
reader rechecks actual source leaf protection and RAM/cache admission. These
primitives are not a live table-tracking service: root dispatch refuses a tracked
CPU write until the global barrier, arbitrary-instruction step, DMA exclusion
and exact physical publication path exists. No native MSI or external interrupt
delivery/EOI pipeline is completed by these helpers, and the boot hold remains.

## Bounds and physical publication contract

Captures and host maps contain at most 4096 pages/ranges. Composition visits at
most 1,048,576 table entries and charges at most 4,194,304 table/range/split steps;
it emits at most 4096 mapping ranges. Tree depth is at most four. Missing input,
bad entries, capacity exhaustion and work exhaustion return errors. Composition
scratch may change on failure, but no usable image is returned. The host image
builder retains its separate transactional storage guarantees. This bounded
profile can refuse large otherwise-legal guest configurations.

Publication is an external trusted-owner operation, not a method on `Composed`.
Its backend must revalidate capture epoch/liveness, all host exclusions,
requester/domain identity, every physical interrupt target and retained table
storage under its current control lease; publish every affected mapping; perform
the required physical invalidations/drain; and retain all still-reachable old
and new backing. A copied image is not authority to publish it later. The
takeover backend currently keeps requesters quiesced, including during mapping
publication. Its completion receipt is a protocol result, not permission to
resume Windows DMA or release memory.

The integration test supplies a concrete backend that composes guest tables into
the owner's assigned alternating storage slots, validates them with the
independent host walker, and obtains receipts through the real owner transaction.
The modeled physical engine can fetch commands without executing their
completion stores: no guest store/MSI is produced in that state. This is offline
protocol evidence, not a physical DMA/interrupt test.

## Incomplete baseline and native boundaries

The selected Windows baseline must remain unexposed. Missing pieces include:

- coherent native snapshot creation and arbitrary CPU table-write mediation on
  every CPU/alias, including old V=IV=0 DTE and RemapEn=0 IRTE transitions that can
  omit guest invalidation; NpCache alone is insufficient;
- physical enforcement and lifecycle updates of the table DMA-write exclusions,
  and a device policy for table mutation; NPT observes CPU accesses, not DMA;
- complete requester/domain-cache lifetime management and same-domain root
  consistency across devices, complete command semantic fault translation for
  invalid requester/domain operands, and native reset/suspend restoration;
- full per-request SA/SE/IG/SupIOPF fault policy, physical event identity/address
  projection, all basic/special interrupt paths and physical interrupt policy
  composition, EOI reverse routing, and actual virtual MSI delivery;
- complete coherent PCI/IVRS presentation, guest aperture dispatch and native
  pinned guest-memory accesses. An output-memory failure currently refuses and
  retains pending work; it is not a complete guest hardware-error recovery path.

No software observer or callback boolean here establishes those platform facts.
Faulting initial device DMA is not used to discover mappings: the IOMMU does not
queue or throttle those transactions for later retry.

Sources are `48882-3.11` physical pp63-75,77,79-85,91-92,121-128,131,138-145,
152-154,158-160,177,214-224,252-256. Field layout PNGs checked include
pp63,74,80,82,85,91-92,124-125,127,131,141,144-145,152-154,158-159,
214-217,223-224,252-254,256. P141's full restart procedure and p222's no-effect
rule clarify p256's abbreviated event restart note.

Focused offline checks (each invocation uses its own `target/viommu-*` target
and TEMP/TMP directory):

```text
cargo test --offline -p svmvisor-hypervisor --test iommu_virtualized --test iommu_virtualized_publication --test iommu_pci_composition
cargo test --offline -p svmvisor-hypervisor --test iommu_mapping_runtime
```
