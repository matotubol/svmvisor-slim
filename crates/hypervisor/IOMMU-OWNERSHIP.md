# DMA ownership implementation boundary

This follows [firmware discovery](IOMMU-DISCOVERY.md) within the
[private-interface plan](PRIVATE-INTERFACE-PLAN.md). The reader remains disabled.
The native integration now builds and publishes a restricted host domain after
the post-EBS CPU rendezvous. It has only been tested through offline adapters.
The supported path requires an already enabled, coherent IOMMU with no ATS
capability and no old-DTE bypass; every other initial profile refuses. Both
successful publication and failure hold every guest. It is not a compatible
Windows deployment or evidence of protection on this machine.

The current [implementation/recovery checkpoint](OWNERSHIP-CANDIDATE.md)
adds executable synthetic PCI effects, a disconnected software virtual-IOMMU
core and a per-unit takeover transaction with an injected backend. Their
cross-component tests are offline. The separate `ownership/cold` protocol and
`activation/iommu_takeover.rs` connect the narrow pre-guest native path. Component
contracts live in [PCI](src/svm/pci/README.md),
[virtual IOMMU](src/memory/iommu/virtualized/README.md) and
[takeover](src/firmware/native/resident/iommu/ownership/README.md).

## Implemented offline components

- The [requester resolver](src/memory/iommu/requester/README.md) relates a numeric
  peripheral to one declared unit and source ID. It preserves declaration
  provenance, refuses conflicting overlaps and form/source settings, and checks
  whole ranges by bounded endpoint intervals. Local success leaves every parser
  diagnostic intact and does not establish current hardware routing.
- [Entry codecs](src/memory/iommu/tables/README.md) validate a restricted four-level
  host translation format with contiguous directory links and 4 KiB leaves.
  Raw ignored/reserved/unsupported bits are rejected. Whole-page physical width,
  alignment and encryption-bit checks precede encoding or decoding.
- `HostDeviceEntry` retains its lower-half DTE API for translation walks.
  `CompleteHostDeviceEntry` adds all 256 bits with mandatory explicit interrupt
  behavior: IV=1, controlled aborts or basic remapping, no passthrough bits and
  strict unsupported-field rejection. Basic IRTEs encode target abort or fixed
  physical delivery. Table operands validate their entire numeric extent, not
  just the root. SMI is outside these DTE controls; basic remapping requires
  separate GAEn=0 evidence. No active requester or interrupt policy is
  installed. Padding a lower half with zero remains rejected.
- The [device-table builder](src/memory/iommu/device_table/README.md) emits all
  65,536 complete entries with an explicit deny default and sorted range
  overrides. Same-domain entries must share a root. All entry, capacity and
  whole-backing checks precede writes, including unused supplied pages.
- The [host walk checker](src/memory/iommu/host_walk.rs) requests at most four
  words from an immutable offline snapshot. It checks unsigned 48-bit DVA
  indices, revalidates the DTE against the supplied physical-address policy,
  intersects permissions at the DTE and every page-table level, and distinguishes
  absent entries from malformed encodings and failed reads.
- The [image builder](src/memory/iommu/image/README.md) emits bounded four-level
  page tables into caller-owned storage with an explicit numeric physical base.
  It rejects physical outputs intersecting protected ranges or the entire
  assigned table backing, including unused capacity. Sorted ranges are sized
  arithmetically before any page iteration or storage mutation; every returned
  error leaves storage unchanged. Independent tests walk generated images across
  directory boundaries, through physical aliases and at the last 48-bit DVA page.
- The [command codecs](src/memory/iommu/commands/README.md) encode and strictly
  decode device-entry invalidation, 4 KiB or whole-domain invalidation, and
  completion stores. DVA operands and system-physical completion addresses have
  separate checks. Unsupported opcodes, guest/PASID operands, interrupt completion
  and noncanonical fields are rejected. No command is submitted or observed.
- The [disconnected queue producer](src/memory/iommu/queue/README.md) uses
  caller-owned pages, byte-offset head/tail validation and one reserved slot.
  Enqueue is transactional, including wraparound; completion stores must name
  an assigned completion cell with a nonzero increasing value. Cells are never
  reused in the producer lifetime. Numeric head progress means fetched commands,
  and numeric completion comparisons grant no drain or reclamation authority.

The checker returns numeric translation evidence for one address. It does not
read the translated payload, model caches or bypasses, establish device identity,
or prove that a protected region is inaccessible. Its callback addresses are
snapshot lookup keys, never authorization for arbitrary physical reads. It is
not a decoder for another software owner's unrestricted AMD-compatible tables.

The image builder does not allocate, pin or establish the physical protection of
its storage. Its caller must supply every protected range and a valid address
policy. A numeric completion destination likewise does not establish safe
backing. A retained candidate bank is prepared below, but no active interrupt
policy, hardware command owner or takeover sequence is provided.
These components do not mint an isolation-ready or reader-authorized object.

## Implemented CPU control preparation

- The [NPF MOV preparer](src/svm/mmio/README.md) derives an exact scalar operand
  from hardware decode-assist bytes at a stopped long64 CPL0 data fault. It
  validates full-span translation before returning an inert effect token;
  committing consumes only an explicitly supplied effect result. It supplies no
  register bank, physical forwarding or native dispatch permission.
- The serialized installer places a 16-byte immutable `RouteExpectation` after
  the terminal-control block in the already shared, pool-excluded startup page.
  Every vCPU revalidates its actual route, CPU profile and participant count
  against that common observation before arm. Directory version 17 also binds
  the pool's shared observation and four per-unit resource slots.
- Both firmware NPT construction paths use that expectation to split and protect
  ECAM before entry. Arm installs CF8-CFF and route-MSR read/write interception
  regardless of terminal availability, rechecks the guard, and retains its own
  route. Exit and reentry checks detect sampled route/intercept drift. Guest INIT
  does not clear the owner. Trusted firmware/SMM remains a prerequisite.
- The runtime supports only admitted DWORD CF8 selector operations, route reads
  and exact unchanged route writes. Bounded scalar target classification does
  not authorize a device effect. PCI data, reset, ECAM writes and route changes
  stop without native data I/O or falsely reporting success. Both broad ECAM
  reopening paths and diagnostic native forwarding are removed.
- Immediately before a native CF8 selector cycle, the runtime samples the
  same-CPU SMI I/O-trap control and refuses IoTrapEn=1. HWCR's architectural
  configuration #GP retains priority. An enabled trap can suppress the native
  cycle, so it cannot be followed by an assumed successful guest commit. This
  conservative check closes that forwarding gap without claiming general SMI
  containment or changing which MSRs the guest can access.
- Collective terminal refusal depends on admitted CPU participation, not a card
  endpoint. The existing all-CPU bootstrap-ACK gate still precedes notifications;
  before it opens, the trusted boot continuation owns failure handling. CPU
  parking does not drain DMA or guarantee a hardware time bound.
- `ControlPageDenials` validates up to 32 sorted, disjoint full-page ranges.
  `IdentityNpt::new_with_denied_ranges` sizes the entire hierarchy before any
  mutation, excludes all assigned table backing, and emits permanent zero holes.
  It retains the existing 64-page runtime capacity. Every returned constructor
  error preserves storage.
- Cache retyping preserves absent holes; its explicit denial variant can split
  old identity/quarantine mappings while refusing nonidentity aliases. A late
  failure clears the partial destination and never changes the source. Legacy
  write-permission helpers preserve denied PTEs and reject stale aliases.
  Independent walks, boundary/capacity tests and the runtime's software-alias
  admission test cover denial through quarantine and restoration.

The native installer derives a bounded integer control manifest from complete
aperture observations. Every native NPT construction and runtime cache rebuild
consumes the same ranges, using all 64 allocated NPT pages. It excludes entire
IOMMU MMIO apertures, their configuration pages and the known F7 FCH control
page, and separately excludes the whole retained pool. Native admission rejects
ECAM/IOMMU windows that overlap that chipset page before probing them. Captured
PM port ranges cannot overlap CF8-CFF. Native takeover refreshes physical observations and requires
an identical complete manifest before effects. These policies do not authorize
Windows release; the remaining indirect-control and guest-device contracts are
still required. Offline tests do not establish execution on physical hardware.

## Retained observation lifetime

The complete bounded report occupies the first 64KiB after the private per-CPU
images, followed by four 0x810000-byte unit slots. Every slot contains the
0x210000-byte deny/control bank and two 0x300000-byte composition destinations.
The slots are followed by a 0x12000-byte shared scalar PCI/IVRS presentation and
one 18MiB serialized mapping/capture workspace. The shared tail is 0x3262000
bytes (12898 pages), inside the same allocation and rollback owner.
No persistent pointer escapes before publication. Pools stay 2MiB aligned;
processor-count decoding excludes the whole tail. Six host page-table pages
support the local PT plus two boundary PTs, reusing the local PT when needed;
complete interior writable spans use 2MiB leaves.
Firmware admits the entire native extent in chunks of at most 2MiB before any
initialization and verifies every private leaf is supervisor/NX. The observation
is read-only, while hardware banks and composition generations are writable.
Guest NPT and software pool exclusions cover all assigned bytes, including
padding and unused unit slots, across cache reconstruction. The maximum pool is
32MiB+0x3262000 (82.3828125MiB).

The 24,944-byte typed observation contains a fixed 64-byte scalar header and the
full report with failures, aliases, ambiguity, reservations and hardware values.
Native acquisition binds the common route before/during/after reads. Callback
checks copy only the header, never reconstructing firmware enums in the resident
image. The report remains historical: later allocations, firmware activity or
device state changes can invalidate it. Header validation proves neither fresh
MMIO state nor DMA integrity, and produces no ownership/reader authority.

## Uninstalled retained resource bank

[ResourceStorage](src/firmware/native/resident/iommu/resources.rs) is initialized
in place, without a multi-MiB firmware stack temporary. Its page-aligned regions
are disjoint: a header page, 512 device-table pages, one empty translation root,
one command page, one event page, one completion page and eleven padding pages.
Every requester entry has V=TV=IV=1, Mode=4, no read/write permission, domain0,
the empty root, controlled interrupt aborts and no passthrough bits. A zero DTE
is never used as the deny policy. Command/event capacity is 256 entries, with
255 usable command slots. No command is prepared by the native installer.

Preparation independently verifies every DTE word and every empty/padding word
before publishing an integer-only 128-byte header. Callback checks only that
header against independently derived addresses for every slot; it does not treat
the header as proof of the payload's current integrity. Hardware pages remain
RW/NX under all private roots so a separately admitted owner can service queues.
All four slots are initialized even when discovery reports fewer units. Each
composition destination is 512 device-table pages plus 256 translation/interrupt
pages. A zeroed destination is not a valid hardware policy. A mapper must check
its exact capacity: the existing 4KiB-only builder cannot map ordinary machine
RAM within 256 pages, while a reviewed mixed-page image can represent larger
aligned spans. Arbitrary Windows mappings have no unconditional capacity promise.

There is native backing for at most four separately bound units; a fresh larger
inventory must be refused without truncation. Optional PPR/GA logs, SMI filtering, exclusions/MARC, ATS drain,
interrupt routing, reset and Windows presentation remain unresolved. The deny
image must not be installed as an ordinary Windows device policy. Later code
must obtain genuine DMA integrity, current topology/control ownership and a
reviewed live transition before publishing any hardware pointer.

## Offline per-unit binding

[Binding](src/firmware/native/resident/iommu/binding/README.md) now checks explicit
assignments against the complete observation report. Every unit requires its own
bank and full identity: segment, PCI function, capability offset and MMIO base.
The fixed deny/empty profile validates complete bank contents, physical widths,
the exact PCI configuration page and the 16KiB or 512KiB MMIO aperture. Pool,
bank, ECAM, control and configured basic buffer extents are checked before a
plan is returned. Extended forms with host translation disabled and enabled
optional modes outside the profile are refused.

The result is an uninstalled numeric plan. It retains the observation status and
unresolved diagnostic count; `Ambiguous` inputs can produce a local resource plan
without resolving requester topology. Historical enable/run bits do not imply
quiescence. Assignments assert physical backing rather than deriving it from a
Rust reference. The post-EBS native takeover calls this binder with freshly read
hardware observations and the four-slot allocation, but binding success does not
admit a native transition or establish the integrity of their physical contents.

The cross-module integration test combines parsed declarations, requester
resolution and verified binding with explicitly constructed offline NPT denials.
Independent byte walks check every page of the full retained pool and both
control-aperture sizes through cache quarantine/restoration, while neighboring
pages remain identity mapped. This verifies composition without activating any
real control denial from a historical report.

## Remaining paths before ownership

The following source paths were independently reviewed on 2026-09-26.

| Surface | Current behavior | Requirement for an owner |
| --- | --- | --- |
| Legacy PCI configuration | [arm](src/host/resident/runtime/arm.rs) always intercepts CF8-CFF; [configuration](src/host/resident/runtime/configuration.rs) completes only admitted DWORD selector operations. | Implement allowed target/effect policy, including bridge, indirect fabric and reset controls, before forwarding data cycles. |
| ECAM | A permanent write guard is installed through both firmware constructions and arm; every write stops. | Implement exact instruction/operand/effect mediation without reopening adjacent controls, paired with a coherent Windows view. |
| IOMMU MMIO | Native construction and cache rebuilds consume a retained whole-aperture denial manifest; physical takeover freshly corroborates it. | Connect virtual register effects before guest release and close alternate control routes. |
| ECAM route MSR | Both directions are permanently intercepted; every CPU matches the common retained expectation and checks sampled drift. | Complete all alternate routing controls and reset/power policy. This is not a hardware lock against trusted SMM or an audit of the chipset. |
| Other I/O and SMI controls | CF8 forwarding refuses an enabled same-CPU I/O trap before native I/O. Every vCPU also intercepts the three captured F7 PM port ranges; other ordinary ports, HWCR and SMI-on-I/O trap MSRs C0010050..C0010054 remain native. | Complete platform PM/reset and SMI-trigger policy; the captured F7 paths and narrow CF8 check are not a complete control map. PPR physical p208 describes these trap controls. |
| Hardware-consumed RAM | Discovery records existing addresses without following them. Four retained banks have verified deny/empty contents and separate writable command/event/completion pages; each unit has two retained composition destinations. | Reject excess units and image capacity, cover optional and interrupt buffers, establish DMA integrity and take ownership before any hardware publication. |
| Reset and power | CF9 and other unadmitted scalar effects stop before native I/O; no complete platform sleep/reset owner exists. | Define preserved transitions and transitions requiring fresh admission, including device/bridge reset and suspend/resume. CPU INIT ownership does not establish platform reset ownership. |
| Observation lifetime | [activation](src/firmware/native/resident/activation/iommu.rs) captures the full report directly into the CPU-excluded retained pool; runtime treats the typed payload as opaque. | Establish DMA integrity and freshly corroborate current state within the actual takeover transaction. The historical report/header and `Observed` are not authority. |

Existing cache/routing MSR owners are useful but do not establish ownership of
every chipset or indirect fabric control. Platform documentation and actual
preboot evidence must identify those remaining routes; absence of a source
handler is not evidence that a hardware route does not exist.

The IOMMU PCI capability's enabled-base lock has narrower scope than this
boundary. It does not lock MMIO IommuEn, device-table/queue addresses or exclusion
registers. IOMMU-generated memory accesses are themselves untranslated; a
guest-controlled physical command queue could issue a COMPLETION_WAIT store to
a protected system address despite restrictive device page tables. Log and
completion destinations therefore belong to the security boundary too.

## Integration order and unresolved choices

1. Freshly revalidate retained requester/alias, reservation, feature and routing
   evidence during takeover after establishing its integrity. Resolve contradictory declarations
   explicitly; preserve unsupported topology as a refusal.
2. Bind the retained candidate bank to an admitted per-unit policy and supply
   any additional complete device/interrupt tables and buffers. Cover the complete admitted
   requester space, all protected/control pages and firmware exclusions. Verify
   the emitted image, including every reachable link. A valid entry or one
   successful walk does not prove complete exclusion.
3. Establish CPU interception of all real control paths and an explicit device
   quiescence/lifecycle policy before any takeover. Stopping guest CPUs does not
   stop DMA. Protect all participating vCPUs and fail on partial participation.
4. Use a reviewed transaction for hardware programming, cache invalidation,
   observed completion, failure handling and teardown. Device-table invalidation
   alone does not flush domain translations; ATS-capable devices need additional
   device-IOTLB handling. Standard invalidation codecs now exist; actual device
   QueueID/Maxpend admission, source/fabric draining and native ATS ownership
   remain absent. A timeout or lost reset state
   cannot permit reuse of memory still reachable by the IOMMU or devices.
5. Demonstrate denied DMA and functioning Windows storage, graphics, input and
   networking before treating the boundary as established.

The [selected Windows coexistence direction](WINDOWS-IOMMU.md) is a genuine
virtual AMD IOMMU with composed mappings and monitor-owned physical structures.
Disconnected register/command, snapshot composition, tracking and completion
behavior now has executable components. Native boot publication is implemented
for its narrow profile. ABI17 now retains candidate PCI/IVRS state and shared
capture scratch. Source-page NPT guards split real identity mappings, survive
cache reconstruction and are verified before entry; any tracked write still
terminates because arbitrary instruction stepping and the all-unit DMA source
barrier are unfinished. Checked native output adapters and a mixed-page image
builder are available, but runtime physical composition effects and complete
interrupt/event delivery remain unfinished.
The candidate guest profile is unexposed
and has not been validated against this Windows installation. A fixed identity
domain cannot silently substitute for Windows nonidentity mappings.

The next software tasks are allowed PCI/ECAM effects, a Windows per-unit device
policy, initial disabled-IOMMU/ATS transitions and explicit reset and Windows
coexistence policy. The strict
refusal behavior deliberately exposes these missing effects instead of opening
a write window or falsely completing Windows programming. The local CPU PPR
does not supply a complete B850 board/chipset indirect/reset control map; obtain
that evidence before inventing an allowlist or asserting complete control ownership.
The user-supplied [F7 firmware analysis](FIRMWARE-F7-EVIDENCE.md), performed with
Binary Ninja 6.0.10601, now identifies the B8/BC indirect path, concrete reset/PM
paths and an IVRS alias-construction explanation. These static observations
narrow that gap; they do not establish complete control coverage.

Trusted firmware/SMM and protected boot remain prerequisites. Suspend may lose
IOMMU state. SMI interception is not an unconditional way to contain locked SMM;
firmware trust and restoration policy must be explicit. DMA isolation also does
not protect an ordinary Windows application's input, credentials or displayed
results from that same Windows kernel. Protected execution and interactive I/O
remain separate stages of the full reader rewrite.

## Source references

All page numbers are physical PDF pages in the indexed local manuals.

- `48882-3.11` pp63,68-74,79-85: lower DTE and host translation entry formats,
  unsigned DVA indexing and cumulative IR/IW permissions; corresponding PNGs
  were checked for bit layouts.
- `48882-3.11` pp61-77,90-93: complete DTE/interrupt fields, controlled aborts,
  basic IRTEs and format prerequisites. Corresponding layout PNGs checked;
  pp47,55,75 describe the separate optional SMI filter and DTE limitation.
- `48882-3.11` p49, pp123-128 and pp138-139: untranslated IOMMU-originated
  transactions, command encodings, COMPLETION_WAIT writes and ordering/drain
  obligations. Bit-layout PNGs were checked for the command codecs.
- `48882-3.11` pp206-207,222-223: capability lock scope, IommuEn and exclusions.
- `48882-3.11` pp205-210,217-228,250-256: explicit capability identity, profile
  feature/control checks and observed buffer extents; layout PNGs checked.
- `48882-3.11` pp293,304-307: alias source declaration, forbidden ordinary/alias
  overlap, extended settings and auxiliary identities; layout PNGs checked.
- `48882-3.11` pp61,70,214-216,252-253: complete table coverage, same-domain root
  consistency, resource base/size registers and command head/tail semantics;
  layout PNGs checked. The reset-only sequence on pp120-121 is not a live takeover.
- `48882-3.11` p50,p287: lost suspend state and firmware restoration obligations.
- `48882-3.11` p193: hardware vIOMMU prerequisites and guest presentation.
- `57896-3.00_PPR` p210: processor ECAM routing register.
- `57896-3.00_PPR` pp40-42,203: configuration scalar/selector semantics and the
  target HWCR I/O-configuration fault control; PNGs were checked.
- `24593_3.44_APM_Vol2` pp206-216,578-580,612-616: page-entry layouts, I/O/MSR
  interception, nested permissions and host-PAT selection; layout PNGs checked.
- `24593_3.44_APM_Vol2` p585,p600: SMI interception and uncontained SMM.
