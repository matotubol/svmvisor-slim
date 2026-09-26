# Supported dump subsets

`--format full-dump` accepts only traditional AMD64 `PAGE` / `DU64` dumps with
`DumpType = 1`. This does not mean every file that Windows calls a complete memory
dump is supported: bitmap-full (`5`), summary, triage, active,
automatic, compressed, and minidump formats are not implemented.

`--format bitmap-kernel` separately accepts AMD64 type `6` with the `SDMP` / `DUMP`
bitmap header described below. Selecting one format does not silently admit the other.

## Layout evidence

The primary layout source inspected on 2026-09-22 is the installed Microsoft
Windows SDK header:

`C:/Program Files (x86)/Windows Kits/10/Include/10.0.28000.0/um/mindumpdef.h`

It defines `DUMP_HEADER64`, `PHYSICAL_MEMORY_DESCRIPTOR64`,
`PHYSICAL_MEMORY_RUN64`, `DUMP_FILE_ATTRIBUTES`, and `DUMP_TYPES`. Microsoft's
[generated DUMP_HEADER64 reference](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/struct.DUMP_HEADER64.html)
also exposes the structure. The SDK declaration was compiled with installed
Clang targeting Windows x64; static assertions verified header size and the
physical descriptor, run, context, dump type, required size, and attribute offsets.

| Field | Byte offset / size |
| --- | --- |
| Header | `0x2000` bytes |
| Signature / ValidDump | `0x000` / `0x004`, four bytes each |
| MajorVersion / MinorVersion | `0x008` / `0x00c`, u32 each |
| DirectoryTableBase | `0x010`, u64 |
| PsLoadedModuleList / PsActiveProcessHead | `0x020` / `0x028`, u64 each |
| MachineImageType | `0x030`, u32; AMD64 is `0x8664` |
| PhysicalMemoryBlock.NumberOfRuns | `0x088`, u32 |
| PhysicalMemoryBlock.NumberOfPages | `0x090`, u64 |
| PhysicalMemoryBlock.Run | `0x098`; each run is two u64 values |
| ContextRecord | `0x348` |
| DumpType | `0xf98`, u32; traditional full is `1` |
| RequiredDumpSpace | `0xfa0`, 64-bit integer |
| Attributes | `0x1050`, u32 |

The 700-byte physical-memory buffer is in an 8-byte-aligned union, occupying
704 bytes. There are 43 complete 16-byte run slots after the 16-byte descriptor
prefix, before ContextRecord. No structure is cast from untrusted file bytes;
the parser decodes little-endian fields explicitly.

Payload organization is independently corroborated by the primary
[QEMU Windows dump writer](https://github.com/qemu/qemu/blob/master/dump/win_dump-x86.c):
`write_runs` writes each run's pages in descriptor order immediately after the
header, and `patch_header` computes header size plus the number of pages times
4096. Its [layout definitions](https://github.com/qemu/qemu/blob/master/include/qemu/win_dump_defs.h)
also specify 43 physical runs. The implementation uses these format facts, not
copied writer code. Unsorted nonoverlapping physical runs are supported; their
file offsets remain in descriptor order.

## Traditional full-dump admission

The type-1 parser requires 1 through 43 nonempty runs; checked physical and file
arithmetic; no overlapping runs; matching aggregate page count; and exact
agreement between file size, RequiredDumpSpace, and header plus run payload.
Trailing secondary data and other extensions are currently rejected, including
otherwise valid dumps containing such extensions. This is an implementation
subset, not a claim that all Windows dumps lack trailers.

## Bitmap-kernel layout and bounded index

The SDK names `DUMP_TYPE_BITMAP_KERNEL = 6`, but does not define its secondary
bitmap header. This part is **reverse-engineered format evidence**, not a
Microsoft-published binary layout. The primary implementation inspected is
Axel Souchet's [kdmp-parser BMP_HEADER64](https://github.com/0vercl0k/kdmp-parser/blob/master/src/lib/kdmp-parser-structs.h)
and [BuildPhysmemBMPDump](https://github.com/0vercl0k/kdmp-parser/blob/master/src/lib/kdmp-parser.h),
which explicitly route type 6 through the bitmap reader. Its fields and ordering
were corroborated against the supplied Windows 11 live kernel capture and the
installed Microsoft debugger's structural output on 2026-09-22.

At absolute file offset `0x2000`:

| Relative offset | Meaning |
| --- | --- |
| `0x000` / `0x004` | `SDMP` / `DUMP` signatures |
| `0x020` | u64 absolute offset of first payload page |
| `0x028` | u64 count of present payload pages |
| `0x030` | u64 count of physical page bits represented |
| `0x038` | bitmap bytes, least-significant bit first in each byte |

Bit `p` represents physical page `p`; a set bit consumes one 4096-byte payload
page, in increasing bit order. A zero bit has no payload. The reader counts set
bits preceding a requested page to locate its payload; it does not copy the
upstream implementation's per-page hash table.

The supported subset requires the payload immediately after page-aligned bitmap
metadata, and exact equality of payload end, file size, and RequiredDumpSpace.
Padding between bitmap and page boundary is not interpreted. Present count must
equal the bitmap population; unused high bits in the final bitmap byte must be
zero. Type 5, alternate `FDMP` headers, RDMP variants, trailers, and different
metadata placement remain rejected.

Admission caps bitmap storage at 16 MiB (a represented physical span up to
512 GiB), independently of input claims. A rank prefix is stored every 512
bitmap bytes, adding at most 256 KiB. Reads count at most 511 preceding bytes
inside one rank block; no giant per-page mapping allocation occurs. This is an
explicit tool limit, not a Windows format limit. Physical-width validation
conservatively includes the bitmap's entire represented span, even zero tail bits.

The supplied capture reports `0x83dd80` represented page bits, `0x2acc00` present
pages and first payload at `0x10a000`. Its length is 11,489,288,192 bytes, equal to
payload offset plus present pages times 4096. Structural parsing, a known kernel
PE signature, a debugger-verified user-space PEB pointer, and an unavailable
process image page have been checked through the actual CLI. This validates
these specific captured reads, not completeness of arbitrary process memory.

## Shared trust and I/O limits

Attributes marking insufficient size, kernel triage, filtering, encryption, or
unknown flags are rejected. Known informational flags, including a decrypted
dump flag, do not establish authenticity or completeness. WriterStatus and
other header context are not a trust attestation.

Missing physical runs produce an error, never synthesized zeros. A read crossing
a gap leaves its destination unchanged; an I/O failure may modify a prefix and
the caller must discard it. Underlying filesystem sparse extents within a
declared run still have the filesystem's ordinary zero-read semantics; the
parser cannot infer whether those zeros are genuine captured memory.

Header roots and kernel pointers are untrusted observations only. CLI context
remains explicitly supplied and independently established; the header is not
used to select a kernel profile or silently initialize translation. External
kernel/PDB identity checks do not prove that the capture belongs to that kernel.

Files must remain unchanged while open. Initial file-length validation cannot
make concurrent changes consistent. Synthetic adversarial fixtures cover both
formats; the available real capture validates bitmap-kernel only. No real
traditional type-1 dump has been tested.
