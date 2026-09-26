# Real offline capture comparison

Validated on 2026-09-22 using a local, already obtained capture. The shipping CLI and
Windows SDK `kd.exe` independently read the same non-sensitive bytes. No capture was
uploaded, acquired, or modified by this validation.

## Capture and kernel evidence

- Working-copy length: `11,489,288,192` bytes.
- SHA-256: `82c9bfd061b8a462e23ab058e2d15e8fe17bbc2827107d636a5979452d7289aa`.
- Encoding: `PAGE`/`DU64`, dump type 6, bitmap kernel; attributes `0x10` (live dump).
- Bitmap covers `0x83dd80` physical page numbers; `0x2acc00` pages are present.
- Packed page payload begins at file offset `0x10a000`.
- Kernel loaded at `0xfffff8008b000000`; captured physical CodeView RSDS at
  `0x10025b130` contains GUID `C29EBFB0-6B78-B3C0-20DC-A66D99713F9E`, age 1,
  and `ntkrnlmp.pdb`. These match the recorded profile. The debugger loaded the matching
  local PDB normally, without forcing a mismatched symbol file.
- CLI separately verified both supplied kernel/PDB file hashes against the pinned profile.

Direct physical `!db` checks establish that compared bytes came from the dump rather than
a debugger image-file fallback. Matching identity is still not an authenticity guarantee
for every byte in the capture.

## Independently established runtime context

SDK debugger `r cr3` reported `0x801b73000`. `x nt!PsActiveProcessHead` resolved
`0xfffff8008bf05dc0`, and `!vtop` translated it to physical `0x101105dc0`.
The command used these explicit root/list-head inputs; it did not accept header context
as verified merely because the header contained it.

Physical width 48 and 1-GiB page support were measured using current same-machine CPUID
(`80000008.EAX=0x3030`, `80000001.EDX=0x2fd3fbff`). Captured CR4 `0xb50ef8`
does not enable five-level paging. `--nxe true` is an interpretation supported by the
valid, present user PEB PTE `0x810000027b7ac867` with NX set. Captured EFER was unavailable
to the debugger; this is an explicit inference, not a measured saved MSR value.

## Compared results

| Target | VA and length | Independent expected result | Shipping CLI |
| --- | --- | --- | --- |
| System PID 4 | `0xfffff8008b000000`, 2 bytes | `4d 5a` (kernel DOS signature) | Exact match; exit 0 |
| Explorer PID 4084 | `0xeeb010`, 8 bytes | `00 00 5f 1e f7 7f 00 00` (PEB ImageBaseAddress) | Exact match; exit 0 |
| Explorer PID 4084 | `0x7ff71e5f0000`, 2 bytes | Physical image page absent | Zero bytes; partial exit 4 |

System EPROCESS was `0xffffe7084776a040`, root `0x1ae000`; Explorer EPROCESS was
`0xffffe708743ea080`, root `0x27bb84000`. The reader discovered these through the
validated process list. Debugger translations and physical reads independently identified
the kernel header at `0x100200000`, the PEB field at `0x27b7ac010`, and the unavailable
Explorer image page at `0x27b6e0000`.

Reproduction from the repository root for this capture only:

```powershell
cargo xtask capture `
  --input target/capture-validation/livedump.DMP --format bitmap-kernel `
  --kernel target/kernel-analysis/ntoskrnl.exe --pdb target/kernel-analysis/ntkrnlmp.pdb `
  --kernel-root 0x801b73000 --list-head 0xfffff8008bf05dc0 `
  --physical-bits 48 --nxe true --page-1g true --max-nodes 4096 `
  --pid 4084 --address 0xeeb010 --length 8 --hex
```

These runtime addresses are capture-specific observations, not defaults for later captures.
Local transcripts are under `target/capture-validation/`: `debugger-evidence.json`,
`debugger-physical.txt`, `debugger-user-bytes.txt`, and `capture-hash.json`. Actual binary
output comparisons were recorded in `cli-be51531c539d438db6fb2e37b566b26d/report.json`.
The capture's length and last-write timestamp remained unchanged through CLI validation;
the reader opens it read-only.

## Limits

Only these bounded observations were compared. This kernel dump does not contain every
user page; an existing virtual mapping cannot supply omitted physical bytes. No bytes were
recovered from the live OS, guessed, or substituted with zeros. These checks do not validate
all processes, capture consistency against a changing live system, process-list completeness
against malicious modification, or any bootable/live hypervisor path.
