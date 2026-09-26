# Disconnected command-buffer preparation

`CommandBuffer::prepare` borrows real caller-owned `CommandPage` storage and a
separate `CompletionPage`, validates their complete numeric physical assignments,
and clears them. Both complete spans must fit inside the caller's numeric
protected extent and must be disjoint. The same `AddressPolicy` is applied to all
backing bytes, including unused command slots and completion cells. Every
constructor error preserves all supplied storage.

This is a preparation component. It does not allocate or pin memory, establish
the mapping between Rust and physical addresses, prove system-RAM/cache type,
retention or CPU/DMA protection, adopt a live ring, or install/submit commands.
The caller must keep these ordinary Rust storage objects disconnected from all
hardware consumers throughout their use. There is no MMIO adapter, installed
flag, publication operation, hardware polling or teardown operation.

## Geometry and emission

| Property | Implemented bound |
| --- | --- |
| Command size | 16 bytes, two explicitly serialized little-endian words |
| Command base | 4 KiB aligned; whole span checked against physical/encryption policy |
| Command size range | Power-of-two 256–32768 entries, equivalently 1–128 pages |
| Base register value | Numeric ComBase[51:12] and ComLen[59:56]=log2(entries), all reserved bits zero |
| Head/tail | Raw 16-byte-aligned **byte offsets**, bits 18:4; invalid bits and offsets refused |
| Capacity | One slot always unused; the minimum ring holds 255 commands |
| Completion storage | One 4 KiB aligned page, containing 512 eight-byte cells |
| Completion reuse | At most one emitted command per cell for a producer lifetime |

`enqueue` accepts the existing restricted `HostCommand` values. Capacity and all
command operands, completion confinement and freshness checks are completed
before the first memory/state change. On success, only the selected ring slots
and producer metadata change. `PreparedBatch` reports the prepared byte offsets
and count; it does not publish the tail. All errors are transactional, including
a bad completion after an otherwise valid prefix.

Completion commands are revalidated under this buffer's address policy. Their
destinations must identify complete cells in the borrowed completion page, even
when another destination is within the wider protected extent. The queue cannot
emit a completion store to its own command memory, adjacent tables, an event log,
unused protected memory or arbitrary guest RAM.

## Numeric observation and freshness limits

`observe_head` accepts a raw numeric offset, checks forward movement against the
current prepared interval, and makes fetched command slots available in this
offline model. It cannot verify sample origin, freshness or reset epoch. A stale
sample from a previous wrap may be numerically indistinguishable. Hardware head
movement itself reports fetching/validation, not execution. It does not complete
invalidations, drain DMA, or release completion cells or other resources.

Each completion cell is cleared initially, then can be targeted once. Store data
must be nonzero and strictly increasing across the producer's whole lifetime.
Duplicate cells, repeated/decreasing values, values already present in a cell,
and counter wrap are refused. This is a bounded local freshness discipline,
not proof that hardware has executed the prepared command. There is no reset,
cell-recycling or live-ring adoption operation. Constructing another producer
does not make outstanding hardware references safe.

`compare_completion` compares an injected number to the expected value for an
issued cell. It performs no physical or volatile read and changes no state, even
when equal. Neither an equal comparison nor head movement allows reusing a cell.
The 512 one-use cells deliberately avoid requiring a trusted completion producer
to authorize recycling in this preparation step. Further completion commands
require a future reviewed lifecycle, not wrapping the counter or reconstructing
this object around live memory.

No result here establishes invalidation completion, fabric drain, resource
reclamation, readiness, authenticated reading or DMA ownership. A native owner
still needs exclusive control and retained backing, appropriate invalidations
(including the admitted remote-IOTLB and interrupt commands where needed), coherent command
visibility before tail publication, real fresh completion observations, bounded
error handling and retention through timeout/reset. IOMMU-originated stores are
untranslated, making command and completion backing part of that boundary.

## References

The complete `48882-3.11/INDEX.json` and relevant TOC entries were read before
physical page text and the applicable PNG layouts:

- p49: IOMMU-originated transactions are untranslated.
- pp120–121: initialization of base/head/tail and enabling controls.
- pp122–123 (text and PNG): contiguous circular buffer, command size, fetch vs.
  execution, actual tail publication and stopped-state restart requirements.
- pp124–125 (text and PNG): `COMPLETION_WAIT` address/data and s/i/f fields.
- pp138–139: invalidation ordering and fabric-drain obligations.
- p215 (text and PNG): ComBase/ComLen layout, minimum/maximum power-of-two size.
- pp252–253 (text and PNG): raw pointer layouts, wrap and never-catching-head rule.

All page numbers are physical PDF pages. Existing `commands` codecs serialize
command operands; this module does not redefine their formats.
