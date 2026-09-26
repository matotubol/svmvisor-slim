# Supplied-image memory reader

The resident now also uses the bounded [local VMMCALL batch interface](../../LOCAL-READ.md)
for same-PC process reads. The image-reader APIs below remain useful for offline
captures and initial client-side discovery; repeated live samples execute in the
resident batch engine.

This `no_std` library translates addresses, reads bytes, and discovers processes in
caller-supplied memory images. The [hypervisor](README.md)
target provides the resident DXE continuation built by `cargo xtask resident`.
Linking this reader library alone does not provide a live process-memory service.

## Reading an image

1. Construct `paging::PagingConfig` from the image's known physical-address width,
   NX-enable state, and 1 GiB page support. The profile is unencrypted, four-level
   AMD64 paging with PAT support and canonical 48-bit virtual addresses.
2. Supply the aligned physical address of the PML4. This is not a raw CR3 value:
   PCID/control bits must not be included. No Windows offsets are assumed.
3. Implement a callback that copies the requested physical bytes from the supplied
   image into its scratch slice. Return `PagingError::PhysicalRead` if any byte is
   unavailable. Returning success promises that every requested byte was supplied.
4. Use `paging::translate` for one numerical translation or `read::read_virtual`
   for a bounded contiguous read into a caller-owned output slice.

A read accepts at most 64 KiB and performs at most 17 page walks, each with at most
four table reads, plus one data read per walk. Callback execution time is controlled
by the caller. There are no retries or allocations. The copy uses a 4 KiB scratch
buffer, so callers must budget that stack space.

`ReadReport::bytes_read` identifies the completed prefix. On failure, the rest of the
output is untouched, including when a callback modifies scratch and then fails.
Unavailable data is never reported as a successful zero-filled read. Empty output
succeeds without reading or validating the root. Preflight range failures perform
no reads and leave the entire output untouched.

## Finding a process in an image

`process::ProcessProfile::new` validates caller-supplied `ProcessLayoutEvidence`: the
EPROCESS size, field alignment, complete field spans, nonoverlap, and the explicitly
permitted low directory-table-base bits. Structural validation does not establish
that offsets match a particular Windows kernel. The library embeds no Windows offsets.

Provide `process::find` with that profile, the image's kernel PML4 physical address,
the virtual address of the process-list sentinel `LIST_ENTRY`, a PID, and a node limit.
The sentinel address is not a pointer-variable address or a process's embedded links.
Kernel symbol RVAs also require the kernel's actual load base from the supplied image.

The walker inspects the complete list before returning a match or `None`. It checks
backlinks and sentinel closure, rejects duplicate matching PIDs, and limits traversal
to at most 4,096 process nodes. Missing image pages, invalid pointers, malformed links,
and exhausted bounds return explicit errors; a provisional match is never returned
from an incomplete list. Work is bounded in callback count, not callback execution time.

`ProcessObservation` contains the observed PID, EPROCESS address, optional creation
time, and normalized process kernel PML4 address. The creation time remains absent
when the supplied profile omits it. These are image observations, not retained process
handles or lifetime guarantees. The root can be passed to `read::read_virtual` to read
a buffer mapped by that address space. User/kernel address-space separation remains
part of the supplied image's profile; a kernel root does not establish every user mapping.

The directory-table-base mask is a caller-declared interpretation of the stored field.
Only mask bits within 11:0 are accepted; the parser strips exactly those declared bits
and checks alignment and physical width afterward. It never guesses PCID state or
removes high metadata or encryption bits.

### Recorded kernel evidence

[The recorded profile](profiles/ntoskrnl-26100.9457.json) contains PE/PDB identity,
public-symbol type records, field offsets, and process-list symbol RVAs for the inspected
kernel file `10.0.26100.9457`. The host reports OS build `26200.9457`; those version
strings are recorded separately. Match the capture's actual kernel identity rather than
selecting offsets from its OS marketing/version label. The profile's PE/DBI age is 1
and its GUID is `C29EBFB0-6B78-B3C0-20DC-A66D99713F9E`; the PDB information-stream age
is separately recorded as 6.
[The evidence notes](profiles/ntoskrnl-26100.9457.md) explain the age-matching rule,
Binary Ninja cross-check, secondary reference comparison, and reproduction procedure.

The verified layout has EPROCESS size `0x840`, active links at `0x1d8`, PID at `0x1d0`,
creation time at `0x1f8`, and the embedded KPROCESS directory-table base at `0x028`.
These values remain profile evidence, not defaults in the library. A synthetic integration
test uses this layout to discover a process and read a known buffer through its distinct
root. This proves the composed parser behavior on constructed bytes, not a real capture.

## Offline file command

`cargo xtask capture` connects the library to a read-only file backend. It requires an
explicit format, kernel root, runtime list-head VA, paging flags, PID, requested VA, and
operation bounds. Raw input also requires its physical base. It does not acquire a capture or infer
runtime addresses. Run `cargo xtask capture --help` for the complete argument list.

Example PowerShell invocation, with runtime values established independently for the image:

```powershell
cargo xtask capture `
  --input C:\captures\physical.raw --format raw --physical-base 0 `
  --kernel C:\captures\ntoskrnl.exe --pdb C:\captures\ntkrnlmp.pdb `
  --kernel-root 0x1000 --list-head 0xfffff80000f05dc0 --physical-bits 48 `
  --nxe true --page-1g true --max-nodes 4096 `
  --pid 1234 --address 0x10000 --length 32 --hex
```

The numeric addresses and PID above are placeholders, not defaults or discovered values.
The command accepts only the recorded kernel/PDB profile. It verifies the exact size and
SHA-256 of both supplied files with bounded streaming reads, then constructs the validated
layout from the embedded evidence JSON. It never selects offsets by OS version. Matching
these external files does not establish that the memory image contains the same kernel.
The command requires the stored process directory-table base to be aligned: it strips no
low bits because the recorded symbols do not establish a tagged storage interpretation.

Use `--output <new-file>` instead of `--hex` for up to 64 KiB. Output must not already
exist; creation uses exclusive creation so existing files and aliases cannot be overwritten.
Hex output is limited to 256 requested bytes. Process details and read status go to stderr;
hex bytes go to stdout. The exit codes are:

| Code | Meaning |
|---|---|
| 0 | Complete read |
| 1 | Profile, inspection, or I/O error |
| 2 | Invalid or incomplete arguments |
| 3 | PID absent from the completely traversed list |
| 4 | Partial virtual read; only the completed prefix is output |

A partial read with no completed bytes creates an empty output file. An output I/O error
may leave a prefix and returns code 1. Lookup failure creates no output. The input file is
opened read-only and is never loaded wholesale: physical reads use seeks and bounded
buffers. It must remain stable during inspection.

Raw format means file offset zero is the declared physical base and every file byte is
supplied physical data. Do not pass a container as raw memory. Filesystem sparse holes are file-provided zeros, not
markers for unknown physical memory. A raw file cannot represent unavailable interior runs;
do not flatten an incomplete capture into a zero-filled file and treat it as complete.

### Traditional Windows full crash dumps

Use `--input C:\captures\MEMORY.DMP --format full-dump` instead of the raw input/format/base
arguments above. `--physical-base` is forbidden for this format. Only traditional AMD64
`PAGE`/`DU64` full dumps (dump type 1) are accepted by this option. Bitmap dumps require
the separate format below. Active, minidump, compressed, and other variants are rejected;
a `.dmp` extension or a Windows
"complete dump" setting alone does not establish that a file uses this supported encoding.
This strict subset requires file length and `RequiredDumpSpace` to equal the header plus
declared physical pages exactly; appended secondary data and trailers are unsupported.
The [format evidence](../xtask/src/capture/image/FORMAT.md) records the Microsoft SDK layout,
compiled offset assertions, physical-run ordering, attribute policy, and supported subset.

The reader maps physical runs to their original positions in the file. Gaps are unavailable
memory, not zero-filled pages. Malformed, overlapping, overflowing, or truncated run maps
are rejected before process traversal. Input reads remain bounded and read-only.

Header directory-table base, process-list head, module-list head, and version fields are
reported to stderr as **unverified metadata**. Inspection still uses the mandatory explicit
`--kernel-root` and `--list-head` values supplied by the caller. Header context neither
authenticates the capture nor proves it matches the supplied kernel/PDB. A caller may use
a separately validated root differing from the header root; the command does not silently
replace it. Physical width and paging flags also remain explicit.

### Windows bitmap kernel dumps

Use `--format bitmap-kernel` for supported AMD64 `PAGE`/`DU64` type-6 bitmap kernel dumps.
This is a separate explicit format, not automatic fallback from `full-dump`. It also forbids
`--physical-base` and requires caller-validated runtime context. The bitmap maps physical
page numbers to packed file pages; absent bits represent unavailable pages and never zeros.
The parser validates bitmap bounds, set-bit counts, unused tail bits, and payload size before reads.
See the [format evidence](../xtask/src/capture/image/FORMAT.md) for exact admission limits.

A kernel dump can omit user pages even when a process's page tables describe a present
mapping. Some pages associated with a user process may be available, but this format does
not establish complete process memory. A missing requested page returns partial status
(exit 4), possibly with zero bytes; the tool never retrieves omitted pages from the live OS.

### Checking an already obtained capture

Open a stable copy of the existing capture in WinDbg (File > Open Crash Dump, or
`windbg -z C:\captures\MEMORY.DMP`). Configure Microsoft symbols with `.symfix` and
`.reload /f nt`. Record `lmvm nt` output, the actual kernel base, symbol identity,
`x nt!PsActiveProcessHead`, and the relevant `!process 0 0` records. See Microsoft's
[dump analysis instructions](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/analyzing-a-kernel-mode-dump-file-with-windbg),
[symbol setup](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path),
and [process inspection reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-process).

Independently establish an aligned kernel PML4 physical root that translates the list head,
the target EPROCESS/PID and directory base, and a present target VA with known expected bytes.
WinDbg's process context can be selected with `.process <EPROCESS>` for dump inspection;
read the same buffer using `db <VA> L<length>` and retain the transcript. See the
[process-context reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-process--set-process-context-).
Do not confuse WinDbg's usual hexadecimal number display with this tool's decimal-by-default
arguments: use an explicit `0x` prefix. Record the capture's hash, encoding, kernel/PDB hashes,
runtime context, paging configuration, and expected bytes with the comparison result.

These steps inspect an existing file; this tool does not acquire memory, trigger a crash,
change Windows settings, or install a driver.

## Limits

The callback defines which bytes are available; translation does not establish
ownership or authorization. Guest page permissions and protection keys are not
evaluated as access grants. The reader changes no source page-table entries or data.
Its callback is responsible for preserving that property.

Only present mappings are interpreted. There is no Windows page-in, compressed-memory
decoder, five-level paging, or encrypted-memory support. Changes between callbacks can
produce an inconsistent observation; a read is not an atomic snapshot. The supplied
image should be stable when consistency is required.

Process-list consistency checks cannot authenticate a guest-maintained list, discover
processes deliberately removed from it, or prevent a PID from being reused in a later
image. A matching kernel binary/PDB establishes layout evidence, not a memory capture.
Real captured-image validation requires a known kernel load base, kernel root, list head,
and independently checked process/buffer values. Results apply only to the checked capture
and ranges, not every process or omitted page.

The dependency on `svmvisor-hypervisor` supplies shared architectural constants.
The library itself selects no resident-runtime feature. The separate payload's explicit
continuation feature selects its shared runtime backend through a direct dependency.

### Mutable-source diagnostics

The callback is a caller-controlled capability, not a restricted memory backend. The library
passes physical addresses and scratch slices to it; it neither acquires memory nor limits the
callback's other effects. The source-read-only contract therefore depends on the callback as
well as the reader. A callback can change its own supplied byte array, as the diagnostic tests
deliberately do. Returning `Ok(())` must still mean that its entire requested slice was filled.

Bounds and error reporting remain meaningful when the source changes, but success establishes
only that each requested fragment was supplied and each sampled structure passed the checks.
It does not establish any of these stronger claims:

- The page-table entries sampled in one walk belonged to one mapping generation, or the
  translated physical page still belonged to that mapping when data was copied.
- The PID, directory root, and creation time coexisted in one process object, or the list was
  consistent at one instant. A successful absent-PID result also depends on source stability.
- A complete output buffer existed at any single instant, even with a stable process root.
- An observed EPROCESS, PID, creation time, or root remains associated with a later read.
  Reused numerical addresses are not retained handles, and creation time is another sampled field.

Repeated reads or before/after comparisons can expose some changes. Equal samples cannot exclude
intervening changes and restoration, so automatic retries cannot turn this API into a snapshot.
The library performs no such retries. Use the same stable supplied image for discovery and reads
when those results must refer to one image state. Profile validation still checks structure only;
kernel/PDB identity and capture provenance require independent evidence.

The reproducible harness runs entirely against constructed byte arrays through the public API:

```text
cargo test -p svmvisor-hypervisor --test reader_process_read_mutation
cargo test -p svmvisor-hypervisor --test reader_read
```

It schedules mutations at specific callbacks to demonstrate mixed process fields, PID/object/root
reuse, and successful mixed-generation output. Reader tests additionally cover mapping replacement
before the data callback and mapping removal after a completed fragment, checking exact callback
counts, errors, and preserved output tails. These tests document limitations; they do not add
coherence detection or exercise concurrent hardware.

Future verification against an authorized debugger-backed source needs an independently established
stable capture or suspension boundary covering the relevant writers, plus evidence tying kernel
identity, list context, process identity, mappings, and expected bytes to that same state. Record
the actual backend's availability and consistency guarantees and measure its effects separately.
The existing capture comparison validates only its recorded ranges; these synthetic tests establish
neither a live backend's lifetime guarantees nor the interference or boot behavior of a future
preboot implementation.

## Validation

Run from the workspace root:

```text
cargo test -p svmvisor-hypervisor
cargo test -p xtask capture
cargo check -p svmvisor-hypervisor --target x86_64-unknown-uefi
cargo fmt --all -- --check
```

Synthetic-image tests cover page sizes, reserved versus available bits, physical
width, canonical addresses, missing pages, partial-copy behavior, process-list integrity,
profile validation, and operation limits.
The end-to-end process/read fixtures use both invented offsets and the recorded symbol
layout; every process and memory buffer in those tests is synthetic.
Command tests compose a synthetic file backend, process lookup, and target-root read; they
cover partial output, absent PIDs, strict arguments, profile identity failures, and existing
file/hard-link output aliases. Full-dump cases exercise physical runs in nonascending file
order, omitted pages, malformed payloads, and preservation of explicit caller context.
These portable tests inject a synthetic validated profile
inside the test build only; the shipping command has no profile-verification bypass.
The actual command was also exercised with the recorded real kernel/PDB files and a synthetic
raw image using their verified offsets: it returned the expected eight bytes `CAPTURE!` and
rejected a same-size kernel file with a mismatched SHA-256. These constructed fixtures
remain synthetic validation.
The compiled command was additionally exercised with the same real kernel/PDB and synthetic
full dumps: complete reads returned `CAPTURE!`, a missing physical page returned only `CAPT`
with partial status, and truncated input or a mismatched kernel created no output. The raw
command still returned the original expected bytes. All supplied capture files remained
byte-identical after these checks.
An actual type-6 kernel capture was also checked against independent Windows SDK debugger
observations: a two-byte kernel header and an eight-byte Explorer PEB field matched exactly;
an omitted Explorer image page returned partial status with no bytes. See the
[real-capture comparison](profiles/capture-validation.md) for identity evidence, context,
commands, and limitations. This establishes these narrow reads, not a complete user-memory
capture or a live hypervisor implementation.
Hardware-dependent future work requires a separate boot and memory-backend review;
passing these tests does not establish Windows boot compatibility.
