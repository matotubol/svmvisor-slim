# Offline host and interrupt entry formats

This module encodes numeric AMD IOMMU host translation and interrupt fields.
It allocates no tables, reads no physical memory, installs no mappings, and
performs no hardware access. Its output is not an isolation or authentication
credential.

The profile is deliberately restricted:

| Item | Supported encoding | Rejected or omitted |
|---|---|---|
| Device translation | DTE bits 127:0; V=TV=1, Mode=4, explicit 16-bit DomainID and IR/IW | V=0, TV=0, Mode=0 and other depths, every optional lower-half field |
| Complete device entry | All 256 bits with explicit `DteInterruptPolicy`; IV=1, five pass bits=0, IG=0, word 3=0 | IV=0, interrupt passthrough, guest interrupt virtualization, every optional upper-half field |
| Controlled interrupt abort | `AbortControlled`: IntCtl=00; ignored root and length zero | Nonzero ignored table fields; **SMI is not controlled by the DTE** |
| Basic interrupt remapping | `RemapBasic`: IntCtl=10; 128-byte aligned root; 1..512 power-of-two 32-bit entries | IntCtl=01 or 11, 1024/2048-entry tables, extended/guest IRTEs; **GAEn=0 is an external prerequisite** |
| Basic interrupt entry | Canonical zero target abort, or RemapEn=1 with fixed physical delivery, destination 00h..FEh and vector 10h..FFh | Logical/arbitrated delivery, broadcast destination FFh, GuestMode, RqEoi, SupIOPF, all reserved bits and nonzero stale abort fields |
| Directory | PR=1; one level down in a 4→3→2→1 walk; explicit IR/IW | Skipped/equal/higher levels, all optional and ignored bits |
| Leaf | PR=1; NextLevel=0 at level one; 4 KiB page; explicit IR/IW and FC | Larger or replicated leaves, U, A/D updates, migration state, ignored bits |
| Absent page entry | Canonical word zero | Nonzero ignored/stale fields with PR=0 |
| Physical address | Existing AddressPolicy checks every byte of a host 4 KiB page and the entire `4 * entry_count` interrupt-table extent | Misalignment, overflow/out-of-width ranges, encoded encryption bit including a crossing anywhere within the extent |

`HostDeviceEntry::words()` retains the existing two-u64 API for offline translation
walks and images. `CompleteHostDeviceEntry::new` requires that lower half plus an
explicit interrupt policy and revalidates both against the supplied address
policy. Its `words()` returns four u64 values, least significant first; its decoder
validates all 256 bits. The Rust struct itself is not a hardware memory layout.
Appending zero words to the lower half would choose IV=0 and forward interrupts
without remapping; the complete decoder rejects that input. No `Default` or
implicit lower-to-complete conversion selects interrupt behavior.

Both interrupt policies clear Lint0Pass, Lint1Pass, NMIPass, InitPass and EIntPass.
`AbortControlled` also target aborts fixed/arbitrated messages. **This is not a
block-all interrupt policy:** SMI requests pass unmapped regardless of IV or those
pass bits unless a separate supported and enabled SMI filter blocks them. SysMgt=0
in the lower half does not supply that filter. SysMgt=0 and IoCtl=0 also refuse
their respective special-message and port-I/O classes; this codec does not
silently adapt firmware IOAPIC, HPET, INTx or other special-device requirements.
Requester and special-device admission remains a separate obligation.

`BasicInterruptTable` describes an encoded numeric extent, not allocated storage.
Its 128-byte alignment is stricter than the pointer field's 64-byte granularity;
raw DTE bit 134 is rejected when set. Its full extent is validated, including the
last byte, with no masking or truncation of addresses. Additional allocator
padding is not represented and needs its own range validation and protection.
The 512-entry cap avoids depending on optional 2K interrupt routing. GAEn=0 must
be corroborated separately: the DTE does not encode the IRTE size, and GAEn=1
would make this basic 32-bit backing the wrong format. No feature-ready object
or MMIO observation is manufactured by the codec.

`BasicInterruptEntry::ABORT` is word zero: RemapEn=0 means target abort, unlike
DTE V=0 or IV=0. The fixed-delivery constructor emits only destination, vector and
RemapEn; all other fields are zero. The caller still must allocate a destination
and vector, program the device's MSI/index consistently, establish table contents
and index coverage, and own interrupt delivery. Numeric values do not prove that
an APIC destination exists, that a vector is free, or that Windows can use it.

`Permissions::None` is an explicit pair of cleared IR/IW bits, not proof of
system-wide DMA denial. Zero physical address and DomainID zero remain legal
numeric values. The codec does not claim either is allocated, unique, or usable.
In particular a zero DTE is not a default deny entry: V=0 permits untranslated
forwarding. The decoder rejects that state.

AddressPolicy is caller-supplied numeric validation, not independently acquired
platform evidence. Successful encoding says nothing about HATS support, active
IOMMU controls, route and alias coverage, exclusion ranges, interrupts, device
ATS state, fabric bypass, memory encryption state, protected backing storage,
cache types, current translations or ownership. DomainIDs must be assigned
consistently across devices that share a translation context. A caller must not
copy these words into active tables without a separately designed lifecycle,
invalidation/completion protocol and ownership boundary.

No complete requester/device-table or interrupt-table builder is provided.
No function dereferences a physical address. The page decoder validates a word
in its supplied containing level; a separate image audit must validate graph
structure, allocated table pages, address coverage, exclusions and effective
permissions. Raw decoders are strict validators for this profile, not general
decoders of firmware or Windows tables. They reject otherwise hardware-ignored
nonzero bits rather than silently normalizing them.

## References

All page references below are physical page numbers in `docs/48882-3.11`.

- pp61–63 Figure 7 and pp64–75 Tables 7–10: complete DTE fields, validity,
  interrupt control/pass behavior, host and interrupt root fields, DomainID and
  every optional/reserved field. The text and every corresponding PNG were checked.
- pp47,55,75: optional separate SMI filtering; DTE interrupt policy alone does
  not block SMI. The p55 and p75 PNGs were checked.
- pp90–93 Table 19, Figures 14–15 and Tables 20–21: ordinary interrupt routing,
  basic 32-bit IRTE layout, target abort, fixed physical delivery and the GAEn
  format prerequisite. All corresponding text and PNGs were checked.
- p77: DTE/interrupt-table changes need a separately owned invalidation protocol;
  this codec does not perform one. Text and PNG were checked.
- pp79–81: 4 KiB host tables, decreasing translation levels, page alignment,
  permission accumulation and unsigned device address space.
- p82 Figures 8–9 / Tables 15–16, pp83–84 Table 17 and p85 Figure 10 /
  Table 18: absent, leaf and directory word layouts. Text and PNG were checked.

The field definitions on p83 give bits 58:57 optional migration meaning even
though Figure 9 on p82 labels the larger area reserved. This profile always
rejects those bits, so it relies on neither optional migration support nor an
interpretation of the diagram's older reserved label.

`24593_3.44_APM_Vol2` physical pp707,709 (text and PNG checked) supplies the
physical APIC/broadcast and ordinary vector-register constraints for the narrow
basic IRTE profile. Destination FFh is a deliberate unsupported broadcast case.
