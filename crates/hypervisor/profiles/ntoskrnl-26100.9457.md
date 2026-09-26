# Static symbol evidence: ntoskrnl 10.0.26100.9457

Collected on 2026-09-22 from a copy of `C:\Windows\System32\ntoskrnl.exe`.
The machine reported Windows 11 25H2 build 26200.9457; the file's version resource
reported **10.0.26100.9457**. The filename here describes that file version, not an
assumption that every 25H2 image uses this layout. The companion JSON binds these
findings to the PE hash and CodeView identity. There is no memory capture or
validation against a captured process list in this evidence.

## Identity and matching public symbols

| Property | Value |
| --- | --- |
| PE SHA-256 | `d90c69cfa925d42037ef1cdba3ff5b3f13cc14e16060938073b97e396fdde2f2` |
| PE file bytes / SizeOfImage | 13,104,632 / `0x1450000` |
| PE machine / preferred base | AMD64 (`0x8664`) / `0x140000000` |
| PE timestamp / checksum | `0xfda9ed74` / `0xc817d5` |
| RSDS PDB filename | `ntkrnlmp.pdb` |
| RSDS and PDB GUID | `C29EBFB0-6B78-B3C0-20DC-A66D99713F9E` |
| PE RSDS age / PDB DBI age / PDB info age | 1 / 1 / 6 |
| PDB SHA-256 | `2f2408d5c6b19264970814b2e9175aa2434cabd09ecbbf9b8d0c335e2b380e6a` |
| PDB bytes / stripped flag | 11,497,472 / true |

The PDB came from the [Microsoft public symbol server](https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/C29EBFB06B78B3C020DCA66D99713F9E1/ntkrnlmp.pdb).
The distinct info-stream age is intentional evidence, not a hidden mismatch:
Microsoft's `PDB1::OpenValidate4` checks equal GUID, PDB info age at least the PE
age, and a nonzero DBI age equal to the PE age. This file satisfies all three.
The extractor is stricter about the legacy zero-DBI-age case and rejects it.
See [Microsoft's validation implementation](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/pdb.cpp#L805-L883).
The PE contains a reproducible-build debug record, so its timestamp is recorded
as an identity field; it is not interpreted as a calendar build date.

## Minimum layout

Offsets are relative to the start of `_EPROCESS`, including the two nested `Pcb`
members because `Pcb` is at offset zero. Integers and pointers are little-endian.

| Field | Offset | Bytes | PDB evidence |
| --- | --- | --- | --- |
| `Pcb` | `0x000` | `0x1c8` | `0x18B5` forward reference resolves to `_KPROCESS` `0x1B49` |
| `Pcb.DirectoryTableBase` | `0x028` | 8 | `unsigned __int64`, type `0x0023` |
| `Pcb.UserDirectoryTableBase` | `0x158` | 8 | `unsigned __int64`, type `0x0023` |
| `UniqueProcessId` | `0x1d0` | 8 | AMD64 `void*`, type `0x0603` |
| `ActiveProcessLinks` | `0x1d8` | 16 | `_LIST_ENTRY`, full type `0x106C` |
| `CreateTime` | `0x1f8` | 8 | `_LARGE_INTEGER`, full type `0x10AD` |
| `Peb` | `0x2e0` | 8 | AMD64 pointer, type `0x1A44` |
| `WoW64Process` | `0x310` | 8 | AMD64 pointer, type `0x1C4F` |
| `ImageFileName` | `0x338` | 15 | `unsigned char[15]`, array type `0x1C50` |
| `SeAuditProcessCreationInfo.ImageFileName` | `0x350` | 8 | pointer to `_OBJECT_NAME_INFORMATION`, type `0x2C87` |

`_EPROCESS` is `0x840` bytes (full type `0x1C75`, field list `0x1C74`).
`_KPROCESS` is `0x1c8` bytes (full type `0x1B49`, field list `0x1B48`).
`_SE_AUDIT_PROCESS_CREATION_INFO` is 8 bytes with `ImageFileName` at zero.
`_OBJECT_NAME_INFORMATION` is 16 bytes with its `_UNICODE_STRING` `Name` at zero;
`_UNICODE_STRING` is 16 bytes with `Length` at zero and `Buffer` at eight.
`_LIST_ENTRY` is 16 bytes with `Flink` at zero and `Blink` at eight. The JSON
retains selected raw LLVM type records, including forward-reference resolution
and field-list offsets. LLVM 22.1.8 produced those records. The 15-byte image
name is a fixed array and must not be assumed to have a trailing zero.

## Static symbols and the list sentinel

| Symbol | PDB section:offset | PE section RVA | Symbol RVA | Binary Ninja address |
| --- | --- | --- | --- | --- |
| `PsActiveProcessHead` | 26:1072576 | `0xe00000` | `0xf05dc0` | `0x140f05dc0` |
| `PsInitialSystemProcess` | 27:6896 | `0xfc5000` | `0xfc6af0` | `0x140fc6af0` |

Use `PsActiveProcessHead` as the circular list's sentinel. Its virtual address in
a supplied capture is the capture's independently established kernel load base
plus `0xf05dc0`. The preferred PE base above is not a captured ASLR base.
`PsInitialSystemProcess` is a pointer variable, not the list sentinel; using the
System process's embedded links as a sentinel would omit that process.
These static bytes provide neither the captured base nor a captured paging root.

## Binary Ninja cross-check

Binary Ninja **6.0.10601.0** was accessed through its already running built-in
`binaryninja_ui_mcp` server at the documented loopback endpoint. The local
`docs/guide/mcp.html` was read before the MCP handshake and `tools/list` schema
discovery. See the [official MCP guide](https://docs.binary.ninja/guide/mcp.html).
Only the copied kernel under `target/kernel-analysis/` was opened.

The PE view reports AMD64, eight-byte addresses, the Windows kernel platform,
and the preferred base shown above. Imported debug types appear as `_EPROCESS_1`
and `_KPROCESS_1` because the platform already supplies opaque names without
usable layouts. `bn_type_info` confirms widths 2112 and 456, the required member
types, `_LARGE_INTEGER_1` width eight, and `_LIST_ENTRY_1` width 16. The MCP type
response does not expose individual member offsets; those come from the exact
PDB's LLVM field records. `bn_symbol_list` independently agrees with both symbol
addresses in the table. No user types, renames, patches, or debugger sessions
were created. Original binaries and Binary Ninja settings were not modified.

## Comparison with the supplied reference

The supplied [Vergilius 25H2 `_EPROCESS` page](https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_EPROCESS)
agrees with all five selected top-level offsets, the 15-byte image name, and
the `0x840` structure size. Its linked
[`_KPROCESS` page](https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_KPROCESS)
also agrees with `0x028`, `0x158`, and size `0x1c8`.
No discrepancy was found for these fields. `Peb`, `WoW64Process` and the audit
image-name path were added later from the same PDB with the same extractor and
have not been compared.
This is a secondary comparison only:
a release-labelled page does not bind its layout to this PE GUID or establish
compatibility with another monthly kernel update. The accepted values above
come from the matching Microsoft PDB.

## Reproduction

Keep PE/PDB inputs under `target/` or another caller-owned analysis directory;
do not commit them. Download the public PDB URL above if it is absent. With
Python 3 and `llvm-pdbutil` on PATH, run from the repository root:

```powershell
python crates/hypervisor/profiles/extract.py --image target/kernel-analysis/ntoskrnl.exe --pdb target/kernel-analysis/ntkrnlmp.pdb --output target/kernel-analysis/profile.json
```

Compare that JSON to `ntoskrnl-26100.9457.json`. The script reads the PE debug
directory itself, applies GUID/age matching, extracts the selected LLVM TPI
records, and converts public symbol section offsets using the PE section table.
It never downloads files, opens live memory, or selects a profile by OS label.
The JSON is evidence for caller review, not an automatically trusted built-in
profile. An actual capture must independently establish matching kernel identity,
load base, root, paging configuration, and image provenance before these offsets
can be applied to its bytes.
