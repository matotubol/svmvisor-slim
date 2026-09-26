//! Classify the SVM enable mismatch behind an intercepted instruction #GP(0).
//!
//! APM2 physical page 577 checks #GP before SVM instruction interception. The
//! mandatory backing SVME can therefore expose a privilege or operand #GP even
//! when the logical SVME requires #UD. This classifier changes no guest state,
//! consumes no next RIP, and never interprets an event-delivery #GP as an opcode.

use crate::{
    arch::x86_64::msr::{EFER_SVME, EFER_UAIE},
    svm::{
        events::EVENT_VALID,
        exit::EXIT_GP,
        instructions::{NativeSvmInstruction, NativeSvmInstructions},
        vmcb::Vmcb,
    },
};

const MAX_INSTRUCTION_BYTES: usize = 15;
const CR0_PE: u64 = 1;
const RFLAGS_VM: u64 = 1 << 17;
const PREFIX_OPERAND: u8 = 1;
const PREFIX_ADDRESS: u8 = 1 << 1;
const PREFIX_SEGMENT: u8 = 1 << 2;
const PREFIX_REX: u8 = 1 << 3;
const OPCODE_ESCAPE: u8 = 0x0f;
const OPCODE_SYSTEM: u8 = 0x01;
const SVM_OPCODES: [(u8, NativeSvmInstruction); 7] = [
    (0xd8, NativeSvmInstruction::Vmrun),
    (0xda, NativeSvmInstruction::Vmload),
    (0xdb, NativeSvmInstruction::Vmsave),
    (0xdc, NativeSvmInstruction::Stgi),
    (0xdd, NativeSvmInstruction::Clgi),
    (0xde, NativeSvmInstruction::Skinit),
    (0xdf, NativeSvmInstruction::Invlpga),
];

/// Identify only an SVM instruction whose logical enable state requires #UD.
///
/// `logical_efer` must already have been reconciled against this stopped VMCB by
/// its EFER owner. The reader must fetch the indicated byte of the instruction
/// at saved CS:RIP with the guest's mode, segment limits, execute permissions,
/// page tables and unchanged backing. It must not substitute unreadable bytes.
/// Reads are sequential, never exceed the 15-byte instruction limit, and stop
/// as soon as the full three-byte opcode or a non-SVM encoding is recognized.
/// Fetch failures remain errors, separately from encodings that preserve #GP.
///
/// Real-mode and VM86 SVM instructions already #UD in hardware with backing
/// SVME set. A #GP there, a nonzero error code, or interrupted delivery is not
/// evidence for this correction. No CPL restriction is imposed: with logical
/// SVME clear, an operand #GP at CPL0 also loses to #UD (APM3 p534).
pub fn classify<E>(
    owner: &NativeSvmInstructions,
    logical_efer: u64,
    vmcb: &Vmcb,
    read: impl FnMut(usize) -> Result<u8, E>,
) -> Result<Option<NativeSvmInstruction>, E> {
    let exit = vmcb.exit_snapshot();
    if exit.code != EXIT_GP
        || exit.info1 != 0
        || vmcb.interrupted_event() & EVENT_VALID != 0
        || logical_efer & EFER_SVME != 0
        || vmcb.guest_cr0() & CR0_PE == 0
        || vmcb.guest_rflags() & RFLAGS_VM != 0
    {
        return Ok(None);
    }

    let long64 = vmcb.guest_in_64_bit_code();
    let null_segments = long64 && logical_efer & EFER_UAIE == 0;
    Ok(decode(long64, null_segments, read)?.filter(|&instruction| owner.requires_svme(instruction)))
}

/// APM3 physical pages 44-53 define prefix groups, ignored long64 segment
/// prefixes and REX placement; page 571 defines the fixed SVM opcode group.
/// LOCK and REP are not accepted SVM modifiers. Repeated ordinary prefix
/// groups and misplaced REX have no admitted interpretation, so preserve #GP.
/// VMMCALL uses the separate bootstrap/unclaimed-call dispatcher and is absent here.
fn decode<E>(
    long64: bool,
    null_segments: bool,
    mut read: impl FnMut(usize) -> Result<u8, E>,
) -> Result<Option<NativeSvmInstruction>, E> {
    let mut prefixes = 0;
    for index in 0..MAX_INSTRUCTION_BYTES {
        let byte = read(index)?;
        if byte == OPCODE_ESCAPE {
            if index + 2 >= MAX_INSTRUCTION_BYTES || read(index + 1)? != OPCODE_SYSTEM {
                return Ok(None);
            }
            let opcode = read(index + 2)?;
            return Ok(SVM_OPCODES
                .iter()
                .find_map(|&(encoding, instruction)| (encoding == opcode).then_some(instruction)));
        }
        if prefixes & PREFIX_REX != 0 {
            return Ok(None);
        }
        let prefix = match byte {
            0x66 => PREFIX_OPERAND,
            0x67 => PREFIX_ADDRESS,
            0x26 | 0x2e | 0x36 | 0x3e if null_segments => 0,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => PREFIX_SEGMENT,
            0x40..=0x4f if long64 => PREFIX_REX,
            _ => return Ok(None),
        };
        if prefixes & prefix != 0 {
            return Ok(None);
        }
        prefixes |= prefix;
    }
    Ok(None)
}
