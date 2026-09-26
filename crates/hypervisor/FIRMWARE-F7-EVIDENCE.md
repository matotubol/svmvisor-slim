# Static F7 firmware evidence

This is a bounded investigation of the BIOS image supplied by the user on
2026-09-26. It identifies observed firmware code paths relevant to
[IOMMU ownership](IOMMU-OWNERSHIP.md). It is not a chipset programming manual,
an allowlist, a current hardware reading or evidence of a successful takeover.
No firmware image or flash utility was executed.

## Reproducible inputs and tools

- Input: `docs/vendor/bios-f7/B850AELITEWF7.F7`, 33,554,432 bytes,
  SHA-256 `41a4a72c5166dc2c2f3ad8db9d8636f5e1a3b83b213375458cf9e9530e9a17b8`.
- Windows SMBIOS reports F7 and release date 2025-11-20. This is a reported
  version match, not proof that current flash bytes equal the supplied image.
- Static analysis used **Binary Ninja 6.0.10601**, headless, with user plugins
  disabled, from `C:\Users\mato\AppData\Local\Programs\Vector35\BinaryNinja`.
  The separate `C:\Program Files\Vector35\BinaryNinja` installation reports
  5.3.9757 and was used only for the initial SDK/version check, not these analyses.
- Extraction used the official
  [UEFIExtract NE A75 Windows x64 release](https://github.com/LongSoft/UEFITool/releases/tag/A75).
  Downloaded archive SHA-256
  `20ff18208913d32c99e3b002717abeddaa3b6509ac62e6699e462b0f533be646` matched
  the release asset digest before execution. Extraction ran on a verified copy
  under `target/private-reader-ownership-validation/bios-f7`.

UEFIExtract returned success and warned that the last VTF appears inside a
compressed item. A75 does not enable its experimental AMD-image parser; this
investigation uses extracted standard firmware volumes and does not claim
complete PSP or platform-image coverage. The inventory contains 506 PE/TE
sections. Only six selected modules were analysed with Binary Ninja:

| Module | Format / functions found | Extracted image SHA-256 |
| --- | --- | --- |
| AmdNbioIOMMUDxe | PE / 127 | `93448dd5860f31fb2e7ab1f8d2dc8e5e9a99baf688f45b1714319e71718ecaf7` |
| AmdNbioIOMMURPLPei | TE / 61 | `955d1cfd8482b916e990114484d91910e42a5b8d0e750b6ba51a99f99598e46e` |
| FchProm21Dxe | PE / 33 | `828d92a0ec925946e1cec1d51e3b7d2d7738d37088cf77b32a22aade741a26cb` |
| FchProm21Pei | TE / 112 | `9de8f4798c4b1b544498ad491d184524e846ac9a259f7a436ce0f550eaece883` |
| ResetSystemRuntimeDxe | PE / 55 | `d4d0a45ded05f4123abb88d001babf9baa341eea46e9cd490d45180a430e9437` |
| ResetSmi | PE / 59 | `426fe88cb22b332da0a07321fcc38859fd17e5de586ff0697a4cf0dd759c932b` |

Local evidence is in `target/private-reader-ownership-validation/bios-f7/bn6`:
the inventory and per-module JSON record hashes and extraction paths; `.bndb`
files retain analysis; `.analysis.txt` files contain raw disassembly and inferred
HLIL. `target/private-reader-ownership-validation/analyze_f7.py` reproduces these
outputs and refuses an SDK whose version does not start with 6. One combined
analysis process exited early; both PEI modules completed successfully in
separate runs. Findings below were checked against raw instructions. Addresses
are Binary Ninja image virtual addresses, not observed runtime addresses.

## IVRS alias and special-source construction

`AmdNbioIOMMUDxe`, FFS GUID `C96C3984-429E-4FAD-8A61-C1E86BA43BF8`,
contains the debug-labelled `SbCreateIvhdEntries` routine at `0x4032d4`.
The raw instruction sequence shows:

1. At `0x403307`, call `sub_403478(0x000a5018, 3, &value)`. Its width-3 path
   reads a DWORD at `0xe0000000 + address` (`0x4034b5`): this input selects
   PCI `00:14.5`, offset `0x18`, with the image's implicit segment/base.
2. Emit alias-range start type `0x43`, settings `0`, source `0x00a5`, and
   start ID `value & 0xff00`. Emit range-end type `4` with end ID
   `(((value >> 16) & 0xff) << 8) | 0xff`.
3. Emit HPET special entry source `0x00a0`, settings `0`. Conditionally emit
   IOAPIC special entry source `0x00a0`, settings `0xd7`, with its handle
   obtained from a firmware configuration service.

There is no all-ones/absent-function rejection around this read in this routine.
An input of `0xffffffff` would therefore produce exactly `ff00..ffff -> 00a5`,
matching the unusual range in the saved Windows IVRS fixture. This is a
conditional explanation, not a finding that hardware actually returned that
value. Other inputs with the same bus bytes produce the same range.

This code also explains how differing HPET/IOAPIC settings for source 00a0 can
be emitted. It supplies no rule allowing those settings to be merged, no alias
precedence rule, and no proof that current requester routing matches the table.
The current resolver must continue refusing unresolved conflicts.

The same module's static table at `0x409370`, with record stride `0x2c`, contains
four records starting `a5 00 40`, followed by `AMDI0020` and UIDs `ID00` through
`ID03`. The raw records are saved in `bn6/f0-input-records.json`. The function
at `0x407c14` conditionally retains these for bus zero with source `00a5`;
`NbioIvhdAddF0DeviceEntries` at `0x402b00` copies their settings into type-F0
entries. This provides a concrete construction path whose four emitted records
match the captured fixture byte for byte, including settings `40` alongside the
alias routine's `00`. It does not prove that this supplied image executed or
supply a valid combined policy for the shared source.

## Indirect initialization path

`AmdNbioIOMMURPLPei`, FFS GUID
`31AD0D89-75B3-4CF3-A1C2-877394EDC601`, calls `sub_9b83c05` from its
entry routine. That helper constructs a bus-specific configuration index
address `(bus << 20) | 0xb8`, reads the selected 32-bit value, computes
`(old & and_mask) | or_mask`, and writes the result through the paired data
register at index-address +4. Helpers `0x9b853f5` and `0x9b8544e` save and
restore the prior index. The underlying read/write helpers at `0x9b8530d` and
`0x9b85320` use a 32-bit `0xe0000000` ECAM-style base.

Observed selector operands in entry code include `0x13f00004`, `0x13b10034`,
`0x147000dc`, `0x148000dc` and `0x13f00080`. These are observations of an
indirect register path; this report assigns no undocumented meaning to their
fields and does not authorize their execution at runtime.

`FchProm21Pei` independently contains the same B8/BC pattern: `0x9b4e59a`
writes index offset B8 and reads `0xe00000bc`; `0x9b4e5b6` writes the index and
then data offset BC. This is concrete reason to preserve mediation of the host
configuration function when ordinary PCI configuration effects are implemented.
The existing blanket ECAM-write refusal already stops guest use of these writes;
it does not make the current build Windows-compatible.

## Reset and power paths

`ResetSystemRuntimeDxe` contains actual `out dx,al` instructions to port
`0xcf9` at `0x4025b5` and `0x4025bb`. Branches choose sequences `02,06` or
`0a,0e`. The code also modifies a byte at platform-base +`0x310`, reads
`0xfed803d2`, and has a power-off branch that obtains I/O ports from
platform-base +`0x360`, +`0x362` and +`0x368`. The module initializes that
platform base to `0xfed80000` and registers a runtime pointer conversion.

CF9 is inside the already intercepted CF8-CFF window. The accompanying platform
MMIO and dynamically selected PM ports still require explicit lifecycle policy.
This does not establish a complete reset/power map, nor does analysing `ResetSmi`
prove containment of SMM. No platform control was read or programmed by this
investigation.

## What this closes

The supplied image and working Binary Ninja 6 API replace several generic
questions with exact modules, instructions and register paths. They narrow the
platform investigation and make the IVRS anomaly reproducible at the firmware
algorithm level. Fresh topology, complete control coverage, device quiescence,
physical publication/completion and Windows validation remain required by the
[selected coexistence contract](WINDOWS-IOMMU.md).
