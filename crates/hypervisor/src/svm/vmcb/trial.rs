//! One-shot unchanged-mappings GMET/#PF control experiment.
//!
//! APM2 rev.3.44 sections 15.7, 15.25 and Appendix B. This owns only
//! GMET and the #PF intercept while borrowing a stopped VMCB. It is not
//! itself an entry engine, does not execute VMRUN, and grants no
//! permission to resume after an error. No target-memory alias is created.

use super::{GUEST_ASID, GUEST_CR3, NESTED_CR3, ReflectedException, Vmcb};

const EXCEPTIONS: usize = 0x008;
const NESTED_CONTROL: usize = 0x090;
const CR2: usize = 0x640;
const GMET: u64 = 1 << 3;
const PF: u32 = 1 << 14;
const VALID: u64 = 1 << 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Admission,
    ControlDrift,
    PendingEvent,
    InvalidEntry,
    Shutdown,
    UnsupportedExit,
    FetchEvidence,
    EntryAlreadyIssued,
    EntryNotIssued,
    Identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// First supervisor instruction fetch was gated. This does not identify
    /// the preceding transition or rule out implicit event-delivery accesses.
    SupervisorFetchGated,
    /// Canonical controls restored and the original #PF queued at unchanged RIP.
    PageFaultReflected,
    /// Physical interrupt remains pending for canonical native delivery.
    InterruptPending,
    /// Canonical controls restored; ordinary #GP dispatch must process this exit.
    GeneralProtectionIntercepted,
}

/// Caller-owned stable NPT walk, never inferred from the exit's U/S bit.
#[derive(Clone, Copy, Debug)]
pub struct FetchEvidence {
    pub nested_root: u64,
    pub guest_physical_address: u64,
    /// Effective permission through every level: present, U/S=1, NX=0.
    pub user_executable: bool,
}

/// Exclusive borrow binds completion to one VMCB and consumes the trial token.
/// Dropping restores owned controls but is not authorization to enter the guest.
#[must_use]
pub struct Trial<'a> {
    vmcb: &'a mut Vmcb,
    guest_root: u64,
    nested_root: u64,
    asid: u32,
    // Intercept words, including the CR/DR and instruction intercept profiles.
    intercepts: [u32; 6],
    pointer_issued: bool,
    physical_stop: bool,
}

impl<'a> Trial<'a> {
    /// Arm a single unchanged-mappings entry. Refusal leaves every byte untouched.
    ///
    /// # Safety
    /// Caller owns this stopped, otherwise valid VMCB on its owning CPU. The
    /// supplied Fn8000000A.EDX is from that CPU with SVM usable. NPT mappings
    /// remain stable and unchanged throughout the trial. Every intended code
    /// mapping is effectively present, U/S=1, NX=0. Event-delivery memory is
    /// canonical; this experiment does not claim pre-delivery isolation.
    /// Caller must provide a bounded external stop mechanism even if the
    /// guest loops at CPL3 without faulting. GMET alone cannot bound execution.
    pub unsafe fn begin(vmcb: &'a mut Vmcb, svm_features: u32) -> Result<Self, Error> {
        if svm_features & ((1 << 17) | 1) != ((1 << 17) | 1)
            || vmcb.guest_cpl() != 3
            || !vmcb.guest_in_64_bit_code()
            || vmcb.read_u64::<NESTED_CONTROL>() != 1
            || vmcb.read_u32::<EXCEPTIONS>() & !super::NATIVE_EXCEPTION_INTERCEPTS != 0
            || vmcb.read_u32::<GUEST_ASID>() == 0
            || vmcb.virtual_interrupt_control() != 0
        {
            return Err(Error::Admission);
        }
        if pending_event(vmcb) {
            return Err(Error::PendingEvent);
        }
        let guest_root = vmcb.guest_cr3();
        let nested_root = vmcb.read_u64::<NESTED_CR3>();
        let asid = vmcb.read_u32::<GUEST_ASID>();
        let mut intercepts = [0; 6];
        for (value, bytes) in intercepts.iter_mut().zip(vmcb.bytes[..24].chunks_exact(4)) {
            *value = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        vmcb.write_u64::<NESTED_CONTROL>(1 | GMET);
        vmcb.write_u32::<EXCEPTIONS>(intercepts[2] | PF);
        vmcb.request_full_tlb_flush();
        vmcb.invalidate_all();
        Ok(Self {
            vmcb,
            guest_root,
            nested_root,
            asid,
            intercepts,
            pointer_issued: false,
            physical_stop: false,
        })
    }

    /// Final stopped-state guard, after every potential event producer.
    pub fn check_entry(&self) -> Result<(), Error> {
        self.check_controls()?;
        if pending_event(self.vmcb) {
            return Err(Error::PendingEvent);
        }
        if self.vmcb.guest_cpl() != 3 || !self.vmcb.guest_in_64_bit_code() {
            return Err(Error::Admission);
        }
        if self.vmcb.bytes[0x05c] != 1 {
            return Err(Error::ControlDrift);
        }
        Ok(())
    }

    /// Obtain storage for a separately implemented entry adapter.
    ///
    /// # Safety
    /// Pointer is valid only during this exclusive borrow. Caller must perform
    /// exactly one same-CPU entry/exit, preserve external GPRs, and never mutate
    /// semantic controls or queue events after this guard. Final cache-owner
    /// bookkeeping may only clear CLEAN_BITS, without altering guest state or
    /// event/control semantics. Caller handles host NMI,
    /// startup and stop requests before calling. This is a virtual pointer;
    /// physical address resolution and hardware ownership are caller duties.
    pub unsafe fn entry_pointer(&mut self) -> Result<*mut Vmcb, Error> {
        if self.pointer_issued {
            return Err(Error::EntryAlreadyIssued);
        }
        self.check_entry()?;
        self.pointer_issued = true;
        Ok(self.vmcb as *mut Vmcb)
    }

    /// Consume one exit and restore canonical controls before reflecting a #PF.
    /// Every error requires stopping the experiment, not native dispatch fallback.
    ///
    /// # Safety
    /// Exactly one actual entry/exit has completed on the guarded VMCB, or an
    /// invalid-entry result was captured. Fetch evidence must be an independent
    /// stable walk of the active NPT covering EXITINFO2, on the owning CPU.
    /// Returned outcomes are observations, not general guest-resume authority.
    pub unsafe fn finish(mut self, evidence: Option<FetchEvidence>) -> Result<Outcome, Error> {
        // Invalid-entry and shutdown state-save fields are not evidence.
        // Drop restores owned controls without interpreting those fields.
        match self.vmcb.read_u64::<0x070>() {
            u64::MAX | 0xffff_ffff => return Err(Error::InvalidEntry),
            0x7f => return Err(Error::Shutdown),
            _ => {}
        }
        if !self.pointer_issued {
            return Err(Error::EntryNotIssued);
        }
        let controls = self.check_controls();
        self.restore();
        controls?;
        let exit = self.vmcb.exit_snapshot();
        if exit.code == crate::svm::exit::EXIT_GP
            && self.intercepts[2] == super::NATIVE_EXCEPTION_INTERCEPTS
            && self.vmcb.event_injection() & VALID == 0
            && self.vmcb.virtual_interrupt_control() == 0
        {
            return Ok(Outcome::GeneralProtectionIntercepted);
        }
        if pending_event(self.vmcb) || self.vmcb.virtual_interrupt_control() != 0 {
            return Err(Error::PendingEvent);
        }
        match exit.code {
            0x60 if self.physical_stop => Ok(Outcome::InterruptPending),
            0x400 => {
                // GMET erratum: do not use NPF U/S as the original access CPL.
                // Refuse all other fault flags, including shadow-stack faults
                // and future encodings outside this deliberately narrow trial.
                let fetch = 1 | (1 << 4) | (1 << 32);
                if self.vmcb.guest_cpl() != 0 || exit.info1 & !(1 << 2) != fetch {
                    return Err(Error::UnsupportedExit);
                }
                let Some(proof) = evidence else { return Err(Error::FetchEvidence) };
                if !proof.user_executable
                    || proof.nested_root != self.nested_root
                    || proof.guest_physical_address != exit.info2
                {
                    return Err(Error::FetchEvidence);
                }
                Ok(Outcome::SupervisorFetchGated)
            }
            // Stage one deliberately supports only ordinary CPL3 read #PFs.
            0x4e if self.vmcb.guest_cpl() == 3 && matches!(exit.info1, 4 | 5) => {
                let fault = ReflectedException::PageFault {
                    error_code: exit.info1 as u32,
                    address: exit.info2,
                };
                self.vmcb.write_u64::<CR2>(exit.info2);
                self.vmcb.write_u64::<0x0a8>(fault.encoding());
                Ok(Outcome::PageFaultReflected)
            }
            _ => Err(Error::UnsupportedExit),
        }
    }

    fn check_controls(&self) -> Result<(), Error> {
        let vmcb = &self.vmcb;
        if vmcb.read_u64::<NESTED_CONTROL>() != 1 | GMET
            || vmcb.read_u64::<NESTED_CR3>() != self.nested_root
            || vmcb.read_u64::<GUEST_CR3>() != self.guest_root
            || vmcb.read_u32::<GUEST_ASID>() != self.asid
            || vmcb.virtual_interrupt_control() != 0
        {
            return Err(Error::ControlDrift);
        }
        for (index, bytes) in vmcb.bytes[..24].chunks_exact(4).enumerate() {
            let expected = self.intercepts[index]
                | if index == 2 { PF } else { 0 }
                | if index == 3 && self.physical_stop { 1 } else { 0 };
            if u32::from_le_bytes(bytes.try_into().unwrap()) != expected {
                return Err(Error::ControlDrift);
            }
        }
        Ok(())
    }

    fn restore(&mut self) {
        let nested = self.vmcb.read_u64::<NESTED_CONTROL>();
        self.vmcb.write_u64::<NESTED_CONTROL>(nested & !GMET);
        self.vmcb.update_intercept::<EXCEPTIONS>(PF, false);
        if self.physical_stop {
            self.vmcb.update_intercept::<0x00c>(1, false);
        }
        self.vmcb.request_full_tlb_flush();
        // Experimental control ownership always returns through a cold VMCB.
        self.vmcb.invalidate_all();
    }
}

impl Drop for Trial<'_> {
    fn drop(&mut self) {
        self.restore();
    }
}

fn pending_event(vmcb: &Vmcb) -> bool {
    (vmcb.event_injection() | vmcb.read_u64::<0x088>()) & VALID != 0
}

/// Owned continuation across the resident assembly boundary. No Rust reference
/// survives VMRUN. Only the same identity-mapped VMCB may consume this ticket.
#[must_use]
pub struct Ticket {
    vmcb_address: usize,
    guest_root: u64,
    nested_root: u64,
    asid: u32,
    intercepts: [u32; 6],
}

impl Ticket {
    /// Final native entry commit, after all event producers.
    ///
    /// # Safety
    /// Same requirements as `Trial::begin`, plus an admitted physical timer
    /// capable of forcing INTR within a bounded interval. The native assembly
    /// must run exactly once next, with no intervening guest state or semantic
    /// control/event mutation. Final `VmcbCacheOwner::prepare_entry` may only
    /// clear CLEAN_BITS before that entry.
    pub unsafe fn arm(vmcb: &mut Vmcb, features: u32) -> Result<Self, Error> {
        if vmcb.read_u32::<0x00c>() & 1 != 0 {
            return Err(Error::Admission);
        }
        let mut trial = unsafe { Trial::begin(vmcb, features) }?;
        trial.physical_stop = true;
        trial.vmcb.update_intercept::<0x00c>(1, true);
        let pointer = unsafe { trial.entry_pointer() }?;
        let result = Self {
            vmcb_address: pointer as usize,
            guest_root: trial.guest_root,
            nested_root: trial.nested_root,
            asid: trial.asid,
            intercepts: trial.intercepts,
        };
        // Ownership moves into the non-borrowing, one-use assembly ticket.
        core::mem::forget(trial);
        Ok(result)
    }

    /// Restore first, then classify the actual assembly-owned exit.
    ///
    /// # Safety
    /// Caller establishes same-CPU actual entry/exit identity and supplies a
    /// stable NPT walk, as `Trial::finish`. The VMCB is exclusively stopped.
    pub unsafe fn finish(
        self,
        vmcb: &mut Vmcb,
        evidence: Option<FetchEvidence>,
    ) -> Result<Outcome, Error> {
        let trial = self.attach(vmcb)?;
        unsafe { trial.finish(evidence) }
    }

    /// Canonicalize a refused assembly boundary without reading saved state.
    pub fn cancel(self, vmcb: &mut Vmcb) -> Result<(), Error> {
        drop(self.attach(vmcb)?);
        Ok(())
    }

    fn attach(self, vmcb: &mut Vmcb) -> Result<Trial<'_>, Error> {
        if vmcb as *mut Vmcb as usize != self.vmcb_address {
            return Err(Error::Identity);
        }
        Ok(Trial {
            vmcb,
            guest_root: self.guest_root,
            nested_root: self.nested_root,
            asid: self.asid,
            intercepts: self.intercepts,
            pointer_issued: true,
            physical_stop: true,
        })
    }
}

#[cfg(test)]
mod tests;
