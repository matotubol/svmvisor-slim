OUTPUT_FORMAT(elf64-x86-64)
ENTRY(entry_uefi)
SECTIONS {
    . = 0x100000;
    image_start = .;
    .text : { *(.text.entry*) *(.text .text.*) }
    . = ALIGN(4096);
    text_end = .;
    .rodata : { *(.rodata .rodata.*) *(.srodata .srodata.*) }
    . = ALIGN(4096);
    data_start = .;
    .data : { *(.data .data.*) *(.sdata .sdata.*) *(.got .got.*) }
    /* A file-backed alignment byte makes the flat-image extent unambiguous. */
    .padding : { BYTE(0); . = ALIGN(4096); }
    image_load_end = .;
    /* Pack page-aligned storage first, avoiding holes between small statics. */
    .bss (NOLOAD) : { *(SORT_BY_ALIGNMENT(.bss.*)) *(.bss) *(COMMON) }
    . = ALIGN(4096);
    image_bss_end = .;
    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
/* Image base plus IMAGE_LIMIT_OFFSET; shared cache aliases start at f0000. */
ASSERT(image_bss_end <= 0x1f0000, "resident image overlaps the shared cache aliases")
