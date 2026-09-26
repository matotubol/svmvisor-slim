//! Exact long64 register/memory MOV forms, with no memory access or effects.
//! APM3 physical pp45-47,53,55-65,276-278. See the module README for scope.

use crate::{arch::x86_64::registers::GuestRegisters, svm::vmcb::Vmcb};

use super::{
    Direction, LinearAccess,
    registers::{self, RegisterLane},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    UnsupportedPrefix,
    UnsupportedOpcode(u8),
    RegisterOnly,
}

/// Sealed decoder result used only to derive the matching NPF continuation.
/// There is no public constructor, and no caller-supplied instruction length.
pub(crate) struct DecodedMov {
    rip: u64,
    length: u8,
    access: LinearAccess,
    register: RegisterLane,
}

impl DecodedMov {
    pub(crate) fn rip(&self) -> u64 {
        self.rip
    }
    pub(crate) fn instruction_bytes(&self) -> u8 {
        self.length
    }
    pub(super) fn access(&self) -> LinearAccess {
        self.access
    }
    pub(super) fn register(&self) -> RegisterLane {
        self.register
    }
}

#[derive(Default)]
struct Prefixes {
    operand16: bool,
    address32: bool,
    rex: Option<u8>,
}

struct Bytes<'a> {
    bytes: &'a [u8],
    used: usize,
}

impl Bytes<'_> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let value = *self.bytes.get(self.used).ok_or(DecodeError::Truncated)?;
        self.used += 1;
        Ok(value)
    }

    fn unsigned(&mut self, bytes: u8) -> Result<u64, DecodeError> {
        let mut value = 0;
        for index in 0..bytes {
            value |= u64::from(self.byte()?) << (index * 8);
        }
        Ok(value)
    }

    fn displacement(&mut self, bytes: u8) -> Result<u64, DecodeError> {
        match bytes {
            1 => Ok(self.byte()? as i8 as i64 as u64),
            4 => Ok(self.unsigned(4)? as u32 as i32 as i64 as u64),
            _ => unreachable!("only disp8/disp32 are used by these forms"),
        }
    }

    fn prefixes(&mut self) -> Result<(Prefixes, u8), DecodeError> {
        let mut prefixes = Prefixes::default();
        loop {
            let byte = self.byte()?;
            match byte {
                0x66 if !prefixes.operand16 && prefixes.rex.is_none() => {
                    prefixes.operand16 = true;
                }
                0x67 if !prefixes.address32 && prefixes.rex.is_none() => {
                    prefixes.address32 = true;
                }
                0x40..=0x4f if prefixes.rex.is_none() => prefixes.rex = Some(byte),
                0x26 | 0x2e | 0x36 | 0x3e | 0x64..=0x67 | 0x40..=0x4f | 0xf0 | 0xf2 | 0xf3 => {
                    return Err(DecodeError::UnsupportedPrefix);
                }
                opcode => return Ok((prefixes, opcode)),
            }
        }
    }
}

enum Address {
    Offset(u64),
    RipRelative(u64),
}

pub(super) fn decode(
    instruction: &[u8],
    vmcb: &Vmcb,
    frame: &GuestRegisters,
) -> Result<DecodedMov, DecodeError> {
    let mut bytes = Bytes { bytes: instruction, used: 0 };
    let (prefixes, opcode) = bytes.prefixes()?;
    if !matches!(opcode, 0x88..=0x8b | 0xa0..=0xa3) {
        return Err(DecodeError::UnsupportedOpcode(opcode));
    }
    let rex = prefixes.rex.unwrap_or(0);
    let width = if opcode & 1 == 0 {
        1
    } else if rex & 8 != 0 {
        8
    } else if prefixes.operand16 {
        2
    } else {
        4
    };
    let direction = if matches!(opcode, 0x8a | 0x8b | 0xa0 | 0xa1) {
        Direction::Read
    } else {
        Direction::Write
    };
    let (register, address) = if opcode >= 0xa0 {
        let address = bytes.unsigned(if prefixes.address32 { 4 } else { 8 })?;
        (RegisterLane::new(0, width, prefixes.rex.is_some()), Address::Offset(address))
    } else {
        let modrm = bytes.byte()?;
        if modrm >> 6 == 3 {
            return Err(DecodeError::RegisterOnly);
        }
        let register =
            RegisterLane::new(((modrm >> 3) & 7) | ((rex & 4) << 1), width, prefixes.rex.is_some());
        let address =
            effective_address(&mut bytes, modrm, rex, |index| registers::read(vmcb, frame, index))?;
        (register, address)
    };
    let rip = vmcb.guest_rip();
    let address = match address {
        Address::Offset(address) => address,
        Address::RipRelative(displacement) => {
            rip.wrapping_add(bytes.used as u64).wrapping_add(displacement)
        }
    };
    // APM3 pp63-64: 67h truncates the computed RIP-relative address as well.
    let address = if prefixes.address32 { u64::from(address as u32) } else { address };
    Ok(DecodedMov {
        rip,
        length: bytes.used as u8,
        access: LinearAccess { address, bytes: width, direction },
        register,
    })
}

fn effective_address(
    bytes: &mut Bytes<'_>,
    modrm: u8,
    rex: u8,
    register: impl Fn(u8) -> u64,
) -> Result<Address, DecodeError> {
    let mode = modrm >> 6;
    let rm = modrm & 7;
    let mut displacement = 0;
    let base = if rm == 4 {
        let sib = bytes.byte()?;
        let index = ((sib >> 3) & 7) | ((rex & 2) << 2);
        let scaled = if index == 4 { 0 } else { register(index).wrapping_shl(u32::from(sib >> 6)) };
        // APM3 p65: REX.B does not change the mod00/base101 no-base form.
        let base = if mode == 0 && sib & 7 == 5 {
            displacement = bytes.displacement(4)?;
            0
        } else {
            register((sib & 7) | ((rex & 1) << 3))
        };
        base.wrapping_add(scaled)
    } else if mode == 0 && rm == 5 {
        // REX.B also does not change this RIP-relative form (APM3 p63).
        return Ok(Address::RipRelative(bytes.displacement(4)?));
    } else {
        register(rm | ((rex & 1) << 3))
    };
    if mode == 1 {
        displacement = bytes.displacement(1)?;
    }
    if mode == 2 {
        displacement = bytes.displacement(4)?;
    }
    Ok(Address::Offset(base.wrapping_add(displacement)))
}
