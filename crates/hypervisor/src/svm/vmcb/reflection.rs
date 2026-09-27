//! EVENTINJ clearing after an exit and interrupted-delivery reinjection.

use crate::svm::{
    events::{DeliveryError, ReflectionError},
    exit::EXIT_SHUTDOWN,
    vmcb::Vmcb,
};

// Exception reflection and reinjection.
impl Vmcb {
    /// Complete event bookkeeping after one actual, exclusively stopped guest entry.
    ///
    /// `pending_injection` records an owned injection for the preceding entry. A
    /// successful replay replaces it with a next-entry obligation; an exit without
    /// interrupted delivery retires it. Refusal preserves both ownership and VMCB.
    /// Call before queuing any new request after this exit.
    ///
    /// This bounded path assumes guest exceptions are not intercepted: EXITINTINFO
    /// names the interrupted delivery, including any hardware-combined exception.
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
        // #VMEXIT clears EVENTINJ (APM3 physical p540). EXITINTINFO, not the
        // previous input request, determines whether delivery needs replay. Check
        // support and conflicts before changing the old software obligation.
        match self.reinject_interrupted_delivery() {
            ReinjectOutcome::Reinjected { .. } => {
                *pending_injection = true;
                Ok(())
            }
            ReinjectOutcome::NoEvent => {
                if *pending_injection {
                    self.clear_event_injection_after_exit()?;
                    *pending_injection = false;
                }
                Ok(())
            }
            ReinjectOutcome::Unsupported { interrupted } => {
                Err(DeliveryError::UnsupportedInterruptedEvent { interrupted })
            }
            ReinjectOutcome::Conflict => Err(DeliveryError::ConflictingInterruptedEvent {
                interrupted: self.read_u64::<0x088>(),
            }),
        }
    }

    /// Retire injection bookkeeping after an exit without interrupted delivery.
    ///
    /// EVENTINJ is an input request (APM 15.20), not a delivery acknowledgement.
    /// The caller must account for failed entry and EXITINTINFO before clearing;
    /// valid EXITINTINFO requires delivery recovery outside this bounded API.
    /// Hardware has cleared EVENTINJ on #VMEXIT (APM3 physical p540). A valid
    /// request here was queued after the exit and must not be erased.
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
        if self.event_injection() & (1 << 31) != 0 {
            return Err(ReflectionError::PendingInjection);
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
    /// encoding matches EXITINTINFO. This runtime intercepts no exceptions
    /// (`configure_native_boot_intercepts` leaves offset 008h zero), so an
    /// intercept never fires *because of* the delivered event and EXITINTINFO
    /// records the event hardware was delivering, possibly an aggregate such as
    /// #DF (APM2 physical p572). Replay that event, without reconstructing the
    /// original injection or combining it again with an intercepted exception.
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
    /// A separately pending V_NMI remains queued, and software never clears
    /// V_NMI_MASK to force the replay; hardware reestablishes NMI blocking.
    pub fn reinject_interrupted_delivery(&mut self) -> ReinjectOutcome {
        let interrupted = self.read_u64::<0x088>();
        if interrupted & (1 << 31) == 0 {
            return ReinjectOutcome::NoEvent;
        }
        // Shutdown/invalid entry cannot describe a recoverable delivery
        // (15.14.3 p528); the caller already stopped on those, so this is a
        // defensive guard.
        let code = self.read_u64::<0x070>();
        if code == 0x7f || code == u64::MAX {
            return ReinjectOutcome::Conflict;
        }
        let kind = ((interrupted >> 8) & 7) as u8;
        if !matches!(kind, 0 | 2 | 3) {
            return ReinjectOutcome::Unsupported { interrupted };
        }
        // Rebuild a clean EVENTINJ: always discard reserved bits (30:12),
        // and copy the error code (63:32) only when EV=1. With EV=0 that
        // error code is undefined (APM2 physical pp571-572, 594).
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
