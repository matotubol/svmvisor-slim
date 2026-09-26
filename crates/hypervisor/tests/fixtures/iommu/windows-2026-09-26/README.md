# Untrusted Windows ACPI snapshot

Copied byte-for-byte from `target/fresh-private-interface-review` for offline
parser regression tests. `acpi-capture.json` retains the original capture
metadata and original paths; the binary copies here are the test inputs.

Captured 2026-09-26 12:16:32 UTC through read-only Windows
`EnumSystemFirmwareTables` / `GetSystemFirmwareTable` (ACPI provider).
The API returns the first matching table if a signature repeats. The record
reported one instance of each signature. This is guest-reported evidence,
not firmware authenticity, protected boot evidence or hardware ownership.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| IVRS.bin | 484 | `103bb8e3c4699698f6bdb1f3e0091f01838c3db316ef99bde8dbac0001afcf79` |
| MCFG.bin | 60 | `8b78e1f2270e77c06f5421167e736c2f7fa1955a6e22c13c80ac1fe07ff817cb` |

Both snapshots pass their byte checksums. IVRS describes one unit using 10h,
11h and 40h forms, overlapping numeric requester/alias ranges, four distinct
AMDI0020 ACPI instances sharing source 00a5, and three IVMD exclusion pages
associated with the preceding 11h form. The parser preserves these declarations
and reports ambiguity; this fixture does not establish defective hardware.
Exclusion denotes translation bypass/read-write treatment, not denied DMA.

These inputs are never used to authorize MMIO/PCI access or reader activation.
