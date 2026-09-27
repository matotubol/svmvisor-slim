//! Pending-event and virtual-interrupt control validation.

use crate::svm::{
    events::ExternalInterruptError,
    vmcb::{
        EventIntercept, SUPPORTED_VIRTUAL_INTERRUPT_CONTROL, V_NMI, V_NMI_ENABLE, V_NMI_MASK,
        VIRTUAL_INTERRUPT_CONTROL, Vmcb,
    },
};

// External interrupts.
impl Vmcb {
    /// Arm hardware NMI blocking using this CPU's Fn8000000A.EDX evidence.
    /// Install after the native bootstrap intercept profile, before first entry.
    /// APM volume 2 physical pages 598-599 and 802: VNMI needs both the
    /// physical NMI intercept and V_NMI_ENABLE. Neither pending delivery nor
    /// hardware masking is reset here; unsupported input leaves every byte intact.
    pub fn configure_native_nmi_virtualization(
        &mut self,
        svm_features_edx: u32,
    ) -> Result<(), ExternalInterruptError> {
        if svm_features_edx & (1 << 25) == 0 {
            return Err(ExternalInterruptError::ControlMismatch);
        }
        self.validate_virtual_interrupt_controls()?;
        self.set_event_intercept(EventIntercept::Nmi, true);
        self.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(
            self.virtual_interrupt_control() | V_NMI_ENABLE,
        );
        Ok(())
    }

    /// Queue a physical NMI already consumed by the private host NMI handler.
    ///
    /// V_NMI is independent of EVENTINJ and may wait while V_NMI_MASK is set;
    /// another request coalesces into the same pending latch. Hardware clears
    /// the request, sets the mask on recognition, and clears the mask after a
    /// successful guest IRET or interrupted delivery (APM2 physical p599).
    /// Never replace an exception/replay or clear hardware-owned blocking.
    #[cfg(any(feature = "resident-runtime", test))]
    pub(crate) fn queue_native_nmi(&mut self) -> Result<(), ExternalInterruptError> {
        match self.exit_snapshot().code {
            u64::MAX | 0xffff_ffff => return Err(ExternalInterruptError::InvalidEntry),
            0x7f => return Err(ExternalInterruptError::GuestShutdown),
            _ => {}
        }
        self.validate_virtual_interrupt_controls()?;
        if !self.nmi_virtualization_enabled() {
            return Err(ExternalInterruptError::ControlMismatch);
        }
        self.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(self.virtual_interrupt_control() | V_NMI);
        Ok(())
    }

    pub(crate) fn validate_external_interrupt_conflicts(
        &self,
    ) -> Result<(), ExternalInterruptError> {
        // No saved IRQ/control field can establish ownership after shutdown.
        if self.read_u64::<0x070>() == 0x7f {
            return Err(ExternalInterruptError::GuestShutdown);
        }
        if self.event_injection() & (1 << 31) != 0 {
            return Err(ExternalInterruptError::PendingInjection);
        }
        if self.read_u64::<0x088>() & (1 << 31) != 0 {
            return Err(ExternalInterruptError::NestedDeliveryUnsupported);
        }
        Ok(())
    }

    pub(crate) fn validate_virtual_interrupt_controls(&self) -> Result<(), ExternalInterruptError> {
        let control = self.virtual_interrupt_control();
        // Explicitly excludes AVIC, virtual GIF, V_IGN_TPR and reserved bits.
        if control & !SUPPORTED_VIRTUAL_INTERRUPT_CONTROL != 0 {
            return Err(ExternalInterruptError::UnsupportedControl { control });
        }
        // V_NMI/V_NMI_MASK have an owner only when virtualization is armed.
        // Hardware refuses V_NMI_ENABLE without NMI interception (APM2 p598).
        if (control & (V_NMI | V_NMI_MASK) != 0 && control & V_NMI_ENABLE == 0)
            || (control & V_NMI_ENABLE != 0 && !self.event_intercept(EventIntercept::Nmi))
        {
            return Err(ExternalInterruptError::ControlMismatch);
        }
        let control = self.read_u64::<0x090>();
        // Classic unencrypted SVM only; NP enable is the only admitted field.
        // SEV/ES/SNP and alternate injection require different state owners.
        if control & !1 != 0 {
            return Err(ExternalInterruptError::UnsupportedNestedControl { control });
        }
        Ok(())
    }
}
