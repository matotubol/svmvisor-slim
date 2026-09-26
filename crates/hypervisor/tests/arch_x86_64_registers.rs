use core::mem::{align_of, offset_of, size_of};

use svmvisor_hypervisor::arch::x86_64::registers::GuestRegisters;

#[test]
fn every_field_has_the_documented_assembly_offset_without_hidden_padding() {
    assert_eq!(size_of::<GuestRegisters>(), 112);
    assert_eq!(align_of::<GuestRegisters>(), 8);
    let offsets = [
        offset_of!(GuestRegisters, rcx),
        offset_of!(GuestRegisters, rdx),
        offset_of!(GuestRegisters, rbx),
        offset_of!(GuestRegisters, rbp),
        offset_of!(GuestRegisters, rsi),
        offset_of!(GuestRegisters, rdi),
        offset_of!(GuestRegisters, r8),
        offset_of!(GuestRegisters, r9),
        offset_of!(GuestRegisters, r10),
        offset_of!(GuestRegisters, r11),
        offset_of!(GuestRegisters, r12),
        offset_of!(GuestRegisters, r13),
        offset_of!(GuestRegisters, r14),
        offset_of!(GuestRegisters, r15),
    ];
    assert_eq!(offsets, [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104]);
}
