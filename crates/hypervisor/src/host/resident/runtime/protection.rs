//! #GP dispatch: bounded instruction evidence and transactional event reflection.

use crate::{
    host::resident::{
        fetch,
        runtime::{State, exit::retry_routing, guest_reader::GuestReader, stop::stop},
        terminal,
    },
    svm::{events::EVENT_VALID, exit::EXIT_GP, protection, vmcb::Vmcb},
};

/// # Safety
/// Same-CPU stopped guest, private NPT and scratch mapping owned, GIF/IF clear.
pub(super) unsafe fn handle(state: &mut State, vmcb: &mut Vmcb) -> bool {
    let startup_owned = state.startup_owned;
    let count = state.count;
    let mut reader = None;
    handle_with_reader(state, vmcb, |stopped, index| {
        // Lazy construction avoids even physical control sampling for faults
        // during delivery, nonzero selector errors, or logical SVME already set.
        if reader.is_none() {
            // SAFETY: inherited same-CPU stopped ownership; no guest pointer is dereferenced.
            reader = Some(
                unsafe { GuestReader::new(stopped, startup_owned, count) }
                    .map_err(|error| error as u16)?,
            );
        }
        let reader = reader.as_mut().unwrap();
        let result = fetch::general_protection_byte(
            stopped,
            reader.width,
            reader.guest_pat,
            index,
            // SAFETY: the reader checks each physical range and drops its scratch alias.
            |address, bytes| unsafe { reader.read(address, bytes) },
        );
        result.map_err(|error| {
            reader.failure.map_or_else(|| terminal::fetch_failure_code(error), |e| e as u16)
        })
    })
}

/// Reader substitution permits testing the complete dispatch decision without
/// touching hardware. Failed evidence never fabricates a different exception.
pub(super) fn handle_with_reader(
    state: &mut State,
    vmcb: &mut Vmcb,
    mut read: impl FnMut(&Vmcb, usize) -> Result<u8, u16>,
) -> bool {
    let exit = vmcb.exit_snapshot();
    if exit.code != EXIT_GP {
        return stop(state, exit.code, exit.rip, 0xf115, 0);
    }
    if vmcb.event_injection() & EVENT_VALID != 0 {
        return stop(state, exit.code, exit.rip, 0xf115, 3);
    }
    let replacement = if exit.info1 == 0 && vmcb.interrupted_event() & EVENT_VALID == 0 {
        let (Some(owner), Some(efer)) = (&state.svm_instructions, &state.efer) else {
            return stop(state, exit.code, exit.rip, 0xf115, 1);
        };
        let Ok(logical) = efer.observe_backing(vmcb.guest_cr0(), vmcb.guest_efer()) else {
            return stop(state, exit.code, exit.rip, 0xf115, 2);
        };
        match protection::classify(owner, logical, vmcb, |index| read(vmcb, index)) {
            Ok(instruction) => instruction.is_some(),
            // A proven instruction-fetch address/segment boundary cannot supply
            // a complete SVM opcode. Preserve the hardware #GP in these cases.
            Err(9 | 0x12) => false,
            Err(error) if error == terminal::FetchReadFailure::MemoryControlBusy as u16 => {
                return retry_routing(state, vmcb);
            }
            Err(error) => return stop(state, exit.code, exit.rip, 0xf001, u64::from(error)),
        }
    } else {
        false
    };
    match vmcb.reflect_general_protection_after_exit(&mut state.pending_fault, replacement) {
        Ok(_) => {
            state.routing_retries = 0;
            true
        }
        Err(_) => stop(state, exit.code, exit.rip, 0xf115, exit.info1),
    }
}
