//! MOV register lanes; RAX/RSP reside only in the VMCB, never in the frame.
//! APM3 physical pp64-65,80: REX byte lanes and 32-bit zero extension.

use crate::{arch::x86_64::registers::GuestRegisters, svm::vmcb::Vmcb};

#[derive(Clone, Copy)]
pub(super) struct RegisterLane {
    index: u8,
    shift: u8,
}

impl RegisterLane {
    pub(super) fn new(encoded: u8, width: u8, rex: bool) -> Self {
        if width == 1 && !rex && encoded >= 4 {
            Self { index: encoded - 4, shift: 8 }
        } else {
            Self { index: encoded, shift: 0 }
        }
    }

    pub(super) fn accumulator(self) -> bool {
        self.index == 0 && self.shift == 0
    }

    pub(super) fn read(self, vmcb: &Vmcb, frame: &GuestRegisters, width: u8) -> u64 {
        (read(vmcb, frame, self.index) >> self.shift) & mask(width)
    }

    /// Return the complete new RAX value for the common instruction commit.
    /// Preparation proved the lane/width; there are no fallible operations here.
    pub(super) fn write(
        self,
        vmcb: &mut Vmcb,
        frame: &mut GuestRegisters,
        width: u8,
        value: u64,
    ) -> u64 {
        let old = read(vmcb, frame, self.index);
        let value = value & mask(width);
        let full = if width >= 4 {
            value
        } else {
            (old & !(mask(width) << self.shift)) | (value << self.shift)
        };
        match self.index {
            0 => return full,
            1 => frame.rcx = full,
            2 => frame.rdx = full,
            3 => frame.rbx = full,
            4 => vmcb.commit_emulated_stack_pointer(full),
            5 => frame.rbp = full,
            6 => frame.rsi = full,
            7 => frame.rdi = full,
            8 => frame.r8 = full,
            9 => frame.r9 = full,
            10 => frame.r10 = full,
            11 => frame.r11 = full,
            12 => frame.r12 = full,
            13 => frame.r13 = full,
            14 => frame.r14 = full,
            15 => frame.r15 = full,
            _ => unreachable!("decoder produces only four-bit GPR indices"),
        }
        vmcb.guest_rax()
    }
}

pub(super) fn read(vmcb: &Vmcb, frame: &GuestRegisters, index: u8) -> u64 {
    match index {
        0 => vmcb.guest_rax(),
        1 => frame.rcx,
        2 => frame.rdx,
        3 => frame.rbx,
        4 => vmcb.guest_rsp(),
        5 => frame.rbp,
        6 => frame.rsi,
        7 => frame.rdi,
        8 => frame.r8,
        9 => frame.r9,
        10 => frame.r10,
        11 => frame.r11,
        12 => frame.r12,
        13 => frame.r13,
        14 => frame.r14,
        15 => frame.r15,
        _ => unreachable!("decoder produces only four-bit GPR indices"),
    }
}

fn mask(width: u8) -> u64 {
    match width {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        8 => u64::MAX,
        _ => unreachable!("decoder produces scalar MOV widths"),
    }
}
