# Offline numeric requester resolution

`Resolver` borrows a parsed `Ivrs`, or a complete `Discovery` through
`from_discovery`. `resolve(Query { segment, requester })` resolves one **actual
numeric peripheral ID** to its declared unit, IOMMU-visible source ID and raw
source settings. It has no allocator, mutable output, hardware adapter or reader
interface. The original inventory and diagnostics stay unchanged on every path.

Success answers this local declaration question only. It does not identify a
real enumerated device, validate every requester, reconcile IVMD reservations,
corroborate MMIO/PCI state, establish freshness/integrity, or authorize table,
control or reader use. The consumer must retain the other inventory obligations.
`Resolution` exposes all matching requester declarations, all declarations using
the source, every unit form and the original diagnostics; it is numeric evidence,
not an ownership or readiness token.

## Resolution rules

1. Numeric actual-requester declarations in the requested segment must name one
   unit. A second unit fails even if the settings or source ID agree.
2. Within each form, only structurally identical repetitions are locally
   redundant. Kind, complete inclusive range, alias source, DTE byte and optional
   extended field must all match. Different shapes remain an overlap refusal,
   even if they give the same answer at the queried ID. There is no select/range,
   alias/ordinary, most-specific, first-entry or last-entry precedence.
3. Every form of that unit must contain the same structural declaration for the
   query. Missing coverage and differing declarations are separate errors. No
   10h/11h/40h form is preferred. Exact repeated entries may have different counts
   without changing the local answer; the parser's corresponding diagnostics
   remain unresolved and visible. Unrelated form scope differences are not
   claimed to be resolved.
4. A selected unit with `ReservedIvhdBits` or `FormPropertiesDiffer` is refused.
   This is a conservative local policy over the existing parser diagnostic, not
   a new hardware rule. Legacy 10h feature reporting and 11h/40h attributes have
   different encodings and are **not** compared as equal raw words. Every raw
   form remains available; this resolver does not reconcile feature support.
5. An alias source must independently resolve to a non-alias numeric declaration
   in the same unit and every form. Alias chains are not followed. An ambiguous
   source has an error with `subject_requester` set to that source, while `query`
   still identifies the original actual peripheral.
6. All declarations using the resulting source in the segment are checked,
   including disjoint actual alias ranges, special devices and ACPI entries.
   Another unit using that source fails. DTE bytes must agree; two present
   extended fields must agree. An absent extended field supplies no constraint,
   so an explicit source field can contribute ATS/CXL settings to an alias whose
   format has no extended field. Raw values are preserved; ATS/CXL policy is not
   implemented or granted by success.
7. Compatible special-device source sharing is retained as evidence. A matching
   IOAPIC/HPET identity cannot change its source or unit, and each unit form must
   repeat the relevant special identity. Equal repetitions are local redundant
   evidence and retain `DuplicateSpecialIdentity` diagnostics. No MADT/HPET
   identity lookup is performed.
8. ACPI source sharing is explicitly unsupported for numeric identity, even when
   its settings agree. HID/CID/UID and enumeration evidence are needed to explain
   that coexistence. A numeric source ID alone also cannot resolve an ACPI,
   IOAPIC or HPET entry when no actual numeric declaration exists. Conflicting
   source settings are reported before the ACPI identity limitation.

Errors carry up to two typed slice-index/form-index/table-offset witnesses.
Checks run in the order above; source-unit collisions precede source settings,
then special identity and ACPI identity checks. An error is a bounded witness,
not an exhaustive diagnostic list. Witness ordering may follow input ordering;
it never selects an accepted winner. Parser behavior, diagnostic kinds and
`requires_resolution()` are unchanged. Local redundant evidence is not a claim
that duplicated firmware entries satisfy every IVRS conformance requirement.

## Range work and bounds

`resolve_interval` returns a suffix starting at the query and ending immediately
before the next actual-requester or source endpoint. `first` is the resolution
at the interval's first ID; `source_id(id)` applies identity or constant-alias
mapping to another member. It may split more than the minimum necessary.

`validate_range` validates an inclusive numeric range by visiting those endpoints,
returning the first failing interval start with its witness. It neither expands
65,536 entries nor invokes callbacks with partial results. Its summary reports
the range and number of intervals, without claiming global inventory validity.
Each numeric scope contributes at most four actual/source endpoints and each
special/ACPI entry two; `MAX_INTERVALS` is 1,281 under the parser's existing bounds
(256 scopes, 64 special entries, 64 ACPI entries). A one-form ALL declaration
requires one query for the entire 16-bit space. All calculations use a 65,536
sentinel wide enough to handle the last ID without wraparound. Memory use is
constant apart from the borrowed bounded inventory.

## Captured Windows fixture and limitations

The untrusted `tests/fixtures/iommu/windows-2026-09-26` snapshot has three forms
of unit `0000:0002`, MMIO base `0xf7600000`. The numeric span `1000h..FEFFh`
resolves locally to the same source IDs. This leaves its reservations, source
conflicts and other diagnostics untouched.

`FF00h..FFFEh` is covered by both an ordinary `0003h..FFFEh` range and an alias
`FF00h..FFFFh -> 00A5h` range in every form. The resolver rejects this overlap.
`FFFFh` is covered only by the alias, but still fails: its numeric/alias source
settings are `00h`, while the four ACPI declarations of source `00A5h` specify
`40h`. Source `00A0h` separately has disagreeing numeric/special settings.
The manual provides no precedence that repairs these declarations. Firmware or
platform evidence must settle them; this component does not infer a working
Windows configuration or defective hardware from guest-reported bytes.

Tests use independently assembled binary IVRS tables and that exact fixture.
They cover redundant declarations, conflicting forms/ranges/aliases/settings,
source and actual collisions across units/segments, source identity limitations,
interior range conflicts, all 256 scope slots, empty inputs and `0000h`/`FFFFh`
boundaries. They do not establish live DMA behavior.

## Manual basis

All references are physical PDF pages from `docs/48882-3.11`; relevant text and
layout PNGs were checked after the full INDEX and targeted IVHD TOC entries.

- pp293-294: numeric device coverage, separate declaration of alias sources,
  inclusive ranges and same-segment requirement.
- pp298-301: separate 11h/40h forms, raw extended feature images and attributes;
  the generic p293 reserved label at +32 is superseded by the detailed EFR2 rows.
- pp303-305: entry kinds, actual versus source IDs, common-source alias ranges,
  and explicit prohibition of ordinary ALL/select/range covering alias peripherals.
- pp304-306: DTE settings, extended ATS/CXL fields, IOAPIC/HPET identities.
- pp306-307: numeric/ACPI coexistence limitation and permitted distinct ACPI
  instances sharing an IOMMU-visible source; shared source alone is not identity.
