//! EVENTINJ clearing after an exit and interrupted-delivery reinjection.

use crate::svm::{
    events::{DeliveryError, EVENT_ERROR_VALID, EVENT_VALID, ReflectedException, ReflectionError},
    exit::{EXIT_GP, EXIT_SHUTDOWN},
    vmcb::{V_IRQ, Vmcb},
};

const EXITINTINFO_OFFSET: usize = 0x088;
const EVENTINJ_OFFSET: usize = 0x0a8;

// Exception reflection and reinjection.
impl Vmcb {
    /// Retained interrupted-delivery evidence, not a newly queued injection.
    pub fn interrupted_event(&self) -> u64 {
        self.read_u64::<EXITINTINFO_OFFSET>()
    }

    /// Resolve one actual #GP exit before ordinary interrupted-event reinjection.
    ///
    /// The caller owns the stopped VMCB and its prior injection obligation. Only
    /// a proven instruction-origin #GP(0), with no interrupted delivery, may be
    /// replaced with #UD. Delivery faults instead combine with EXITINTINFO under
    /// APM2 physical pages 309, 314 and 571-573. A prior #DF means shutdown.
    ///
    /// Actual VMEXIT clears EVENTINJ (APM3 physical page 540). Any valid event
    /// found here is a new/conflicting request and is never overwritten. Success
    /// replaces the old obligation with the queued event; all failures preserve
    /// the VMCB and obligation. RIP, error evidence, CR2 and debug state survive.
    /// Injected exceptions bypass the exception intercept (APM2 physical p593).
    pub fn reflect_general_protection_after_exit(
        &mut self,
        pending_injection: &mut bool,
        invalid_opcode: bool,
    ) -> Result<ReflectedException, ReflectionError> {
        let exit = self.exit_snapshot();
        if exit.code != EXIT_GP {
            return Err(ReflectionError::UnsupportedExit { code: exit.code });
        }
        let error_code = u32::try_from(exit.info1).map_err(|_| {
            ReflectionError::InvalidGeneralProtectionError { error_code: exit.info1 }
        })?;
        self.validate_virtual_interrupt_controls().map_err(ReflectionError::Control)?;
        if self.virtual_interrupt_control() & V_IRQ != 0 {
            return Err(ReflectionError::PendingVirtualInterrupt);
        }
        if self.event_injection() & EVENT_VALID != 0 {
            return Err(ReflectionError::PendingInjection);
        }
        let protected_mode = self.guest_cr0() & 1 != 0;
        let interrupted = self.interrupted_event();
        let exception = if interrupted & EVENT_VALID != 0 {
            if invalid_opcode {
                return Err(ReflectionError::NestedDeliveryUnsupported);
            }
            combine_general_protection(interrupted, error_code, protected_mode)?
        } else if invalid_opcode {
            if error_code != 0 {
                return Err(ReflectionError::InvalidGeneralProtectionError {
                    error_code: exit.info1,
                });
            }
            ReflectedException::InvalidOpcode
        } else {
            ReflectedException::GeneralProtection { error_code }
        };
        let mut injection = exception.encoding();
        // Real/paged-real handlers receive FLAGS, CS and IP, without an error
        // code (APM2 physical p331). VM86 has PE set and uses protected delivery.
        // EVENTINJ.EV describes the actual frame to push (physical p594).
        if !protected_mode {
            injection &= u64::from(u32::MAX) & !EVENT_ERROR_VALID;
        }
        self.write_u64::<EVENTINJ_OFFSET>(injection);
        *pending_injection = true;
        Ok(exception)
    }

    /// Complete event bookkeeping after one actual, exclusively stopped guest entry.
    ///
    /// `pending_injection` belongs to the caller that queued the preceding entry's
    /// EVENTINJ request. A failed completion preserves that obligation. Only successful
    /// clearing consumes it. No new request may have been queued after this exit.
    ///
    /// This path excludes intercepted exceptions: #GP exits must use
    /// `reflect_general_protection_after_exit` instead, before this method runs.
    /// Other supported exits need only retry the interrupted delivery.
    /// Supported events are re-injected before the exit's own handler can queue another
    /// event. Software INTn and conflicting requests refuse. APM volume 2 physical
    /// pages 571–573 and 593–594; this does not enable interrupts or authorize VMRUN.
    pub fn complete_event_delivery(
        &mut self,
        pending_injection: &mut bool,
    ) -> Result<(), DeliveryError> {
        // Invalid entry and shutdown cannot establish any saved event/guest state.
        if matches!(self.exit_snapshot().code, u64::MAX | EXIT_SHUTDOWN) {
            return Err(DeliveryError::UnusableGuestState);
        }
        if self.exit_snapshot().code == EXIT_GP {
            return Err(ReflectionError::UnsupportedExit { code: EXIT_GP }.into());
        }
        // An injection interrupted by another exit is still owed. Actual
        // hardware cleared EVENTINJ; retry EXITINTINFO without discarding that
        // obligation. Refuse stale/new requests before any mutation.
        if *pending_injection && self.interrupted_event() & EVENT_VALID != 0 {
            if self.event_injection() & EVENT_VALID != 0 {
                return Err(ReflectionError::NestedDeliveryUnsupported.into());
            }
            return match self.reinject_interrupted_delivery() {
                ReinjectOutcome::Reinjected { .. } => Ok(()),
                ReinjectOutcome::Unsupported { interrupted } => {
                    Err(DeliveryError::UnsupportedInterruptedEvent { interrupted })
                }
                _ => Err(DeliveryError::ConflictingInterruptedEvent {
                    interrupted: self.interrupted_event(),
                }),
            };
        }
        if *pending_injection {
            self.clear_event_injection_after_exit()?;
            *pending_injection = false;
        }
        match self.reinject_interrupted_delivery() {
            ReinjectOutcome::Reinjected { .. } | ReinjectOutcome::NoEvent => Ok(()),
            ReinjectOutcome::Unsupported { interrupted } => {
                Err(DeliveryError::UnsupportedInterruptedEvent { interrupted })
            }
            ReinjectOutcome::Conflict => Err(DeliveryError::ConflictingInterruptedEvent {
                interrupted: self.read_u64::<0x088>(),
            }),
        }
    }

    /// Clear the previous entry's injection request after a completed exit.
    ///
    /// EVENTINJ is an input request (APM 15.20), not a delivery acknowledgement.
    /// The caller must account for failed entry and EXITINTINFO before clearing;
    /// valid EXITINTINFO requires delivery recovery outside this bounded API.
    /// Never clear a newly queued request before the intended VMRUN.
    pub fn clear_event_injection_after_exit(&mut self) -> Result<(), ReflectionError> {
        if self.read_u64::<0x070>() == 0x7f {
            return Err(ReflectionError::GuestShutdown);
        }
        if self.read_u64::<0x070>() == u64::MAX {
            return Err(ReflectionError::InvalidEntry);
        }
        if self.read_u64::<0x088>() & (1 << 31) != 0 {
            return Err(ReflectionError::NestedDeliveryUnsupported);
        }
        self.write_u64::<0x0a8>(0);
        Ok(())
    }

    /// Complete an interrupted event delivery by re-injecting EXITINTINFO
    /// through EVENTINJ before the next VMRUN.
    ///
    /// APM2 rev3.44 15.7.2 p509-510, 15.7.3 p510-511 and 15.20 p531: when an
    /// intercept fires while the guest is delivering an event through the IDT,
    /// EXITINTINFO (offset 088h) records that event and the VMM completes
    /// delivery by re-injecting it through EVENTINJ (offset 0A8h), whose
    /// encoding matches EXITINTINFO. Intercepted #GP must instead go through
    /// `reflect_general_protection_after_exit`, which combines it with the
    /// interrupted event rather than repeatedly retrying a failing delivery.
    ///
    /// Only TYPE 0 (external/virtual interrupt), 2 (NMI) and 3 (exception) are
    /// re-injected. EXITINTINFO records INT3/INTO as TYPE 3 (15.7.2 p510), and
    /// 15.20 p531 makes an injected TYPE 3 with vector 3 or 4 behave as the
    /// corresponding trap, so those complete correctly. TYPE 4 (INTn software
    /// interrupt) needs the nRIP-based injection emulation of 15.20 p531-532
    /// that this bounded path does not implement, and reserved types are
    /// undefined; both are refused as `Unsupported`. A re-injected NMI sets
    /// V_NMI_MASK on the next VMRUN under NMI virtualization (15.21.10 p537).
    /// RIP, RSP, RFLAGS, RAX and EXITINTINFO are retained (they are uncached,
    /// 15.15.3 p528); success writes only the explicitly uncached EVENTINJ.
    pub fn reinject_interrupted_delivery(&mut self) -> ReinjectOutcome {
        let interrupted = self.read_u64::<0x088>();
        if interrupted & (1 << 31) == 0 {
            return ReinjectOutcome::NoEvent;
        }
        // Shutdown/invalid entry cannot describe a recoverable delivery
        // (15.14.3 p528); the caller already stopped on those, so this is a
        // defensive guard.
        let code = self.read_u64::<0x070>();
        if code == EXIT_GP {
            return ReinjectOutcome::Unsupported { interrupted };
        }
        if code == 0x7f || code == u64::MAX {
            return ReinjectOutcome::Conflict;
        }
        let kind = ((interrupted >> 8) & 7) as u8;
        if !matches!(kind, 0 | 2 | 3) {
            return ReinjectOutcome::Unsupported { interrupted };
        }
        // Rebuild a clean EVENTINJ. EV=0 leaves the error code (63:32) and the
        // reserved bits (30:12) undefined (15.7.2 p510), so copy them only when
        // EV=1.
        let mut event = (1u64 << 31) | (u64::from(kind) << 8) | (interrupted & 0xff);
        if interrupted & (1 << 11) != 0 {
            event |= (1 << 11) | (interrupted & (0xffff_ffffu64 << 32));
        }
        // Never overwrite a different event. #VMEXIT clears EVENTINJ (APM3
        // rev3.37 VMRUN p505), so one found here was queued after this exit.
        let pending = self.event_injection();
        if pending & (1 << 31) != 0 && pending != event {
            return ReinjectOutcome::Conflict;
        }
        self.write_u64::<0x0a8>(event);
        ReinjectOutcome::Reinjected { kind, vector: interrupted as u8 }
    }
}

/// APM2 physical pages 309/314 classify the prior event, not its vector alone:
/// INTn and external interrupts stay benign even with an exception-number vector.
fn combine_general_protection(
    interrupted: u64,
    error_code: u32,
    protected_mode: bool,
) -> Result<ReflectedException, ReflectionError> {
    let kind = ((interrupted >> 8) & 7) as u8;
    let vector = interrupted as u8;
    let has_error = interrupted & EVENT_ERROR_VALID != 0;
    let prior_error = (interrupted >> 32) as u32;
    match kind {
        0 | 2 | 4 if !has_error => Ok(ReflectedException::GeneralProtection { error_code }),
        3 => {
            let requires_error =
                protected_mode && matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30);
            if has_error != requires_error
                || (has_error && matches!(vector, 8 | 17) && prior_error != 0)
            {
                return Err(ReflectionError::InvalidInterruptedEvent { event: interrupted });
            }
            match vector {
                8 => Err(ReflectionError::GuestShutdown),
                0 | 10..=14 | 21 | 29 | 30 => Ok(ReflectedException::DoubleFault),
                1 | 3..=7 | 16..=19 | 28 => {
                    Ok(ReflectedException::GeneralProtection { error_code })
                }
                _ => Err(ReflectionError::UnsupportedInterruptedEvent { event: interrupted }),
            }
        }
        _ => Err(ReflectionError::InvalidInterruptedEvent { event: interrupted }),
    }
}

/// Outcome of `Vmcb::reinject_interrupted_delivery`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReinjectOutcome {
    /// EXITINTINFO.V=0: no interrupted delivery to complete.
    NoEvent,
    /// EXITINTINFO copied to EVENTINJ; the next VMRUN re-delivers `vector`
    /// with the recorded TYPE (`kind`).
    Reinjected { kind: u8, vector: u8 },
    /// EXITINTINFO records a TYPE this bounded path cannot re-inject (TYPE 4
    /// software interrupt or a reserved TYPE). Terminal.
    Unsupported { interrupted: u64 },
    /// EVENTINJ already holds a different pending event, or the exit is
    /// shutdown/invalid entry. Terminal.
    Conflict,
}
