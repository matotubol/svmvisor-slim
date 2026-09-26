# Stopped NPF scalar MOV preparation

`prepare` is an executable, hardware-independent operand/continuation boundary
for a future MMIO effect owner. It does not read or write an MMIO address, alter
NPT permissions, forward PCI configuration, activate an IOMMU model, or authorize
a native effect. The resident NPF dispatcher still refuses ECAM writes and has
no guest-IOMMU register owner. Passing these tests does not establish hardware
ownership or Windows coexistence.

The caller must own the actual same-CPU stopped VMCB and register frame, retain
hardware exit and DecodeAssists provenance, complete pending-event bookkeeping,
and preserve the instruction/paging snapshot through the later effect. Public
VMCB fixtures can exercise the code but cannot prove those conditions.

## Admitted instruction boundary

- An NPF (`400h`) at the guest final physical address, data access only. NPF
  page-table, instruction-fetch, reserved-bit, shadow-stack and all other
  unowned indications are refused. Read/write direction must match the decoded
  instruction; NPF U/S is not treated as the original CPL.
- Enumerated DecodeAssists support and hardware byte count `1..15`. Only those
  bytes are decoded. The count may cover more bytes than this instruction; only
  its exact consumed length determines the continuation. nRIP is never used.
- CPL0, long64, four-level paging, baseline unencrypted nested controls, no UAI,
  no TF or enabled DR7 breakpoints, and no incompatible event/control state.
- Only `88h..8Bh` register/memory MOV and `A0h..A3h` accumulator/moffs MOV. Natural
  alignment is required for scalar widths 1, 2, 4 and 8. One `66h`, one `67h`,
  and an optional final REX prefix are supported. Address calculations include
  ModRM/SIB, signed displacement, RIP relative and address32 truncation.
- Register lanes include all 16 GPRs and non-REX AH/CH/DH/BH. Byte/word loads
  preserve other bits, dword loads zero-extend, and qword loads replace the full
  register. RAX and RSP live solely in the VMCB; other GPRs live in the frame.

Immediate MOV (`C6h/C7h`), string/vector/atomic instructions, segment overrides,
duplicate prefixes, REX before a legacy prefix, unsupported modes, and incomplete
bytes remain explicit refusals. These are subset limits, not guest faults or
evidence that the guest requested an invalid operation.

## Operand evidence and deferred commit

Preparation checks the complete canonical, naturally aligned linear span and
the reported physical span against the admitted physical/encryption policy.
Their page offsets must match. Natural alignment and the maximum eight-byte
width keep the operand within one 4 KiB page.

`translate_span(&Vmcb, LinearAccess)` must validate the **whole current guest
span**, including guest permissions, effective cache policy and consistency of
the guest page-table walk. It returns the first GPA, which must exactly equal
NPF EXITINFO2. The callback must not read or write the operand. Its result is
translation evidence and grants no device-access permission. The current
module does not provide a native page-table walker for this callback.

The returned token exclusively borrows both stopped state objects. Its numeric
`access()` describes width, direction, linear/GPA address and a narrowed source
value for writes. `accumulator_operand()` plus width lets a future ECAM owner
require specifically AL/AX/EAX; AH, other GPRs and RAX are outside that policy.
This predicate does not establish ECAM cache type or register effects.
The PPR's no-DWORD-crossing rule permits some unaligned operands, such as AX
at DWORD offset 1. This preparer's natural-alignment rule deliberately refuses
those too; it is not complete coverage of PPR-legal ECAM accesses.

The effect owner must separately admit the exact device/register operation and
finish the real or virtual effect before calling `commit_read(value)` or
`commit_write()`. The commit applies only the register/RIP result and existing
RF/interrupt-shadow completion semantics. Wrong-direction calls, preparation
failures and dropped tokens preserve the complete VMCB and register frame.
There is no public instruction-length constructor: `DecodedMov` is sealed and
only feeds the matching NPF continuation helper.

## Source basis and integration dependencies

All page numbers below are physical `page_<N>` numbers in the indexed manuals.
Relevant whole INDEX files, targeted TOC entries, page text and layout PNGs were
read before implementing their fields.

- `24593_3.44_APM_Vol2` pp574-575: DecodeAssists NPF byte count and bytes at
  VMCB `D0h/D1h`; pp613-614: final-GPA versus guest-page-table NPF and flags.
- `24594_3.37_APM_Vol3` pp45-65: prefix and ModRM/SIB/REX/address-size behavior;
  p80: register lanes; pp276-278: MOV encodings and effects.
- `24593_3.44_APM_Vol2` p457: DR7 enable layout; pp465-466,470: breakpoint and
  single-step completion.
- `48882-3.11` p214: naturally aligned power-of-two 1/2/4/8-byte IOMMU accesses.
- `57896-3.00_PPR` pp40-42: ECAM UC and AL/AX/EAX MOV/no-DWORD-crossing rules;
  p101: target DecodeAssists feature. ECAM policy is narrower than this decoder.

The next executable integration needs a current guest operand walker over
admitted RAM, protected real IOMMU apertures, a complete effect owner, and the
resident NPF dispatcher wired to that owner. For Windows DMA this also requires
a coherent guest IOMMU register/command model composed into monitor-owned real
tables, with requester/alias/interrupt/invalidation/reset ownership. A static
identity DMA table is not a replacement for Windows' DMA-address programming.
Neither a successful decoder test nor an inferred register allowlist satisfies
these dependencies. The current full ECAM write guard remains installed.

`tests/svm_mmio.rs` uses inert fixtures only. It checks register results and
unrelated state, address encodings, the bounded hardware byte count, nRIP
independence, exact GPA binding, complete-span bounds and transactional refusal.
