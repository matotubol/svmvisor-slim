# Offline host-page-table images

`build` writes actual four-level AMD host translation pages into caller-owned
`TablePage` storage. Each aligned page is exactly 4096 bytes containing 512 u64
words. The returned image borrows an immutable view of the used prefix and offers
a bounds-checked numeric word lookup for `host_walk::walk`.

The physical backing base is an explicit numeric assignment. It is not derived
from the Rust pointer, dereferenced, allocated, pinned or verified as protected
physical memory. The image is not an ownership or reader authorization object.
It contains no DTE, requester assignment or interrupt policy and has no runtime
integration, hardware access, activation, invalidation or teardown behavior.

Mappings are nonempty page-aligned ranges from unsigned 48-bit DVA to physical
output, sorted by DVA with no overlap. Each output byte preserves its offset.
Different DVAs may alias unprotected output pages. Every mapping explicitly
chooses all four IR/IW combinations and either FC behavior. Directory links use
IR=IW=1 so their cumulative permissions preserve the leaf choice. A None leaf is
still present and is never used as a substitute for excluding protected memory.

Protected physical ranges are likewise nonempty, page-aligned, sorted and
nonoverlapping. The builder validates complete ranges with `AddressPolicy`,
including their last byte and any intervening encryption-bit toggle. It rejects
every output intersection with either the supplied protected ranges or the
entire assigned backing span, including unused capacity. This checks physical
destinations, so changing the DVA cannot evade exclusion. The caller remains
responsible for supplying the complete protected set and valid address policy.

All validation and encoding preparation finishes before storage changes. Every
returned error leaves all pages byte-for-byte unchanged. On success, only the
exact used prefix is initialized, and unused storage remains unchanged. The
commit phase only combines already validated addresses with flags obtained from
the existing entry codecs. It has no error-returning or allocation operations.
An empty mapping list requires one all-absent root, not a zero/passthrough DTE.

Bounds are 4096 mapping ranges, 4096 protected ranges, and 32,768 table pages
(128 MiB of caller storage). Limits are checked before traversing input slices.
Preflight validates protection once and binary-searches each mapping's output,
taking O(P + M log(P + 1)) work. It counts distinct 2 MiB, 1 GiB and 512 GiB
prefixes arithmetically, sharing boundary prefixes between adjacent ranges.
Insufficient capacity is reported before iterating over individual pages; a
32 GiB mapping needs 16,418 table pages and can be sized with a tiny buffer.
Successful emission and clearing are bounded by 512 times the available table
page count, with at most four levels and no heap storage or unsafe code.

The output can be checked using a separately constructed lower-half
`HostDeviceEntry` and the immutable `read_word` callback. A successful walk only
checks this snapshot. Hardware capabilities, all requester and alias routes,
exclusions and bypasses, active caches, control ownership, full DTE/interrupt
policy and physical retention remain outside this component.

References: `docs/48882-3.11` physical pp79-85, text and corresponding PNGs
checked. Table 15 defines unsigned indices; Figures 8-10 and Tables 16-18 define
the absent, leaf and directory entries and cumulative IR/IW/FC behavior.
