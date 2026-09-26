# Physical ownership transaction boundary

This directory contains two distinct protocols. `Plan`/`Transaction` is a live
owner transfer with an injected retained `Backend`; it requires existing DMA
protection and cannot bootstrap that protection. Its `require_native_admission`
still returns unresolved Windows/runtime facts. `cold` is a separate pre-guest
protocol connected to `activation/iommu_takeover.rs`; neither protocol nor a
simulated `DrainReceipt` enables the reader.

Native ABI 17 allocates four 0x210000-byte banks and two 3 MiB composition destinations
per unit, followed by shared presentation and 18MiB mapping scratch. Private
roots map resources RW/NX and observations RO/NX; the whole
pool is CPU-excluded. Initialization occurs in place without a multi-MiB stack
object. `binding::bind` verifies each complete disconnected deny bank.

The cold protocol retains IommuEn, requires coherent host translation and no
physical ATS capability, audits every old DTE against a no-bypass profile, and
requires real old-command completion before replacing queues.
All old device-table/command/event extents are checked for overlap across and
within units before the first command write, so another engine cannot supply
the same completion through shared old command memory. It installs a
mixed 1 GiB/2 MiB/4 KiB identity image over admitted RAM, excluding the pool and control
pages, with explicit controlled interrupt aborts. New invalidations use IASup or
the full baseline DTE/domain/interrupt set, followed by exact distinct completion
tokens. Initially disabled translation and remote ATS need separate drain/source
control implementations. Firmware/SMM/devices remain trusted during construction;
CPU parking is never a DMA drain assertion. All allocations remain retained on
error. Successful publication reports a separate held-guest stage; no Windows
guest runs because the virtual IOMMU/interrupt/firmware contract is incomplete.

The remaining sections describe the live-owner transfer protocol.

`Plan::prepare` accepts only the binding's complete unit-to-bank assignment and
rejects unresolved inventory diagnostics. It rechecks the narrow running profile,
requires IASup, checks whole control apertures and configuration pages, excludes
cross-unit and within-unit aliases among old rings/tables/logs, and checks all
new-bank bytes plus both composition slots against numeric CPU denial, DMA
denial, retention and writable-WB coverage. Each protected range must itself
have complete CPU/DMA denial and retention. Coverage sets are sorted bounded
intervals, not evidence that mappings or protection have actually been installed.
The backend must establish those facts, including indirect controls, firmware
reservations and the reachable structures below each old device table.

The takeover sequence is:

1. Acquire and retain all control, memory and previous-owner obligations. Stop
   all requester sources and previous producers; poll explicit quiescence for
   every unit. Remote IOTLBs must be disabled and empty, with ATS/PASID/PPR work
   resolved independently. PCI BME changes and CPU parking do not prove this.
2. Verify and publish all disconnected deny banks, then compare fresh snapshots
   with the admitted binding. Refuse drift before command submission.
3. Append exact `INVALIDATE_IOMMU_ALL` plus `COMPLETION_WAIT` commands to each
   existing queue, using its checked ring geometry and one reserved slot. Stores
   use separate once-only private completion cells, nonzero values, s=1, i=0,
   f=1. Publish memory before the tail. The previous owner must have surrendered
   the queue, and no old/fetched command may write the new completion cells.
4. Poll each exact completion with acquire ordering and fresh status checks.
   Head progress only frees command slots; it never proves execution or drain.
   Only after **every** old unit drains may command/event processing stop. Poll
   both Run bits to zero before replacing any queue/event pointer.
5. Install the prepared deny tables and new buffers, retaining IommuEn=1
   throughout. Start the new command/event processors, then issue another global
   invalidation and distinct completion. All units must complete before the
   transaction reports `OwnedQuiesced`. Sources remain silent: the deny image
   is not an ordinary Windows device policy and is not permission to resume DMA.

`begin_publication` accepts the next exact unit/epoch/generation key only. It
rechecks all-unit source quiescence and supplies the backend an explicit inactive
`PublicationSlot`. The composition callback must replace **all** old-generation
links with a complete validated image, including interrupt policy, before the
physical invalidation is submitted. From generation 3 onward the reused slot
includes the exact preceding mapping drain receipt. That preceding completed
replacement makes the inactive slot reusable; the other slot remains active.
Both allocations stay pinned throughout. Completion cells never recycle: two
takeover drains leave at most 510 mapping publications in the current lifetime.
Exhaustion refuses before any composition effect.

Every call is nonblocking by backend contract. The engine bounds both total
steps and caller-supplied monotonic ticks, so even a frozen clock exhausts its
step budget. A timeout, hardware error, event, snapshot drift or stale completion
enters a terminal state. Side-effect masks are set before fallible operations,
including posted writes that may take effect before reporting failure. No error
or Drop restores old roots, restarts requesters, releases controls or frees old
tables/queues/events/new banks. Reset, suspend, power, control-integrity, memory
integrity and guest-table-tracking loss revoke the current owner; there is no
same-epoch restart. Actual backend allocation retention must outlive the Rust
transaction and every reachable hardware reference.

Shared correlation types live in `memory::iommu::physical` so the virtual device
does not import the firmware module. Receivers require the complete key and the
mapping-publication purpose, consume each completion once and invalidate their
owner epoch on lifecycle loss. Injected backends can produce synthetic receipts;
the types themselves deliberately assert no native hardware authority.

The saved Binary Ninja 6.0.10601 evidence was reused without executing firmware
or acquiring live state. Its raw alias-builder call at 0x403307, four A5/40 F0
records and five PEI B8/BC selector operands narrow the investigation. They do
not prove the installed flash matches the supplied image, resolve the A0/A5
settings or ff00..ffff routing, establish IVMD bypass policy, or close all reset,
power and SMM paths. Those gaps, plus current DMA/control integrity, quiescence,
old-command completion-cell exclusivity, resources, guest-table write tracking
and Windows interrupt/event/lifecycle behavior, remain native admission blockers.

Manuals read using INDEX/TOC, text and PNGs (physical pages): `48882-3.11`
pp124-126 (completion/invalidations), pp136-139 (global invalidation and ordering),
pp214-217,221-226,228 (registers/profile), pp252-256 (pointer/run/status rules).
Global invalidation does not flush remote IOTLBs (p136). Its matching completion
provides the architectural invalidation drain (pp124,139); f=1 separately prevents
subsequent independent commands from launching before the wait finishes (p124).
