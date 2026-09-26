# Complete offline device-table images

`build` writes exactly 65,536 complete restricted DTEs, covering DeviceIDs
0000h through FFFFh. Entries occupy 32 bytes each in 512 contiguous pages
(2 MiB). The base requires 4 KiB alignment, not 2 MiB alignment. With device
table segmentation disabled, MMIO Offset 0000h uses that base and Size=1FFh:
the size field is the number of 4 KiB pages minus one, not a logarithm.

The caller supplies an explicit `CompleteHostDeviceEntry` default and sorted,
inclusive `Assignment` ranges. The default must have V=TV=IV=1, Mode=4, no I/O
read/write permissions, and `AbortControlled` interrupt policy. A zero DTE is
passthrough and cannot be supplied as the default. Overrides may select the
existing codec's explicit permissions and interrupt policy; this builder makes
no device, alias, phantom-function or Windows policy decision.

The builder re-decodes every supplied entry under the current `AddressPolicy`,
including the complete numeric interrupt-table extent for basic remapping. It
rejects reversed ranges, overlap, ordering errors, and differing host roots for
emitted entries sharing one DomainID. Modes are uniformly four. A default fully
covered by overrides is still validated but does not participate in that domain
consistency check because it is not emitted.

All checks precede mutation, and every returned error leaves the entire storage
slice unchanged. All assigned backing is checked for alignment, physical width,
overflow and encryption-bit crossings, including unused capacity. Success writes
only the first 512 pages; additional pages remain unchanged. The API distinguishes
the emitted table extent from the entire assigned extent requiring protection.
`DeviceTablePage::ZERO` initializes storage only; it is not a valid table image.

Bounds are 4,096 assignment ranges and 1,024 backing pages (4 MiB). Preflight is
O(A^2) for the domain-consistency comparisons, using constant scratch storage.
Emission visits exactly 65,536 entries and allocates nothing. Callers must never
build into storage already visible to an IOMMU or device. The image and register
value are inert data, with no installation or readiness authority.

Actual physical allocation, CPU mappings, retained lifetime, DMA integrity and
cache attributes are external. This builder does not follow host roots, inspect
IRTE contents, prove exclusion of protected outputs, or establish ownership of
referenced backing and its padding. Cross-IOMMU domain consistency and complete
fabric/requester coverage must also be established externally. Identical numeric
roots do not authenticate the underlying table contents.

Future installation still requires hardware feature/global-mode admission,
DevTblSegEn=0, GAEn=0 for basic remapping, separately owned command/log/completion
buffers, fresh observation, quiescence, invalidation/completion, and reset/failure
retention. EX=0 does not defeat a global exclusion Allow bypass. I=0 does not
drain device ATS/IOTLB state. SMI needs a separately established filter because
the DTE interrupt controls do not block it. An image with no read/write grants
does not by itself prove DMA denial or functional Windows coexistence.

Manual evidence is from `48882-3.11`, physical PDF pages: 60-61 (index/extent),
63 (four-word layout), 65-75 (entry semantics and SMI exception), 70 (DomainID
consistency), 78-79 (segmentation), 214 (base/size register), and 223 (exclusion
bypass). Relevant layouts and tables were cross-checked against PNGs. The
existing complete-entry codec supplies the field-level encoding restrictions.
