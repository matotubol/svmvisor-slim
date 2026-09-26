//! Pending-event and virtual-interrupt control validation.

use crate::svm::{
    events::ExternalInterruptError,
    vmcb::{SUPPORTED_VIRTUAL_INTERRUPT_CONTROL, Vmcb},
};

// External interrupts.
impl Vmcb {
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
        // Explicitly excludes AVIC, virtual GIF/NMI, V_IGN_TPR and reserved bits.
        if control & !SUPPORTED_VIRTUAL_INTERRUPT_CONTROL != 0 {
            return Err(ExternalInterruptError::UnsupportedControl { control });
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
