//! Guest continuation state and committed instruction outcomes.

use crate::{
    arch::x86_64::descriptors::SegmentState,
    svm::{
        events::ExternalInterruptError,
        exit::ResumeCandidate,
        vmcb::{
            GUEST_CR0, GUEST_CR3, GUEST_CR4, GUEST_EFER, GUEST_ISST_ADDR, GUEST_RAX, GUEST_RFLAGS,
            GUEST_RIP, GUEST_RSP, GUEST_S_CET, VIRTUAL_INTERRUPT_CONTROL, Vmcb,
        },
    },
};

const INTERRUPT_SHADOW_OFFSET: usize = 0x068;
const EVENT_INJECTION_OFFSET: usize = 0x0a8;
const GUEST_DR6_OFFSET: usize = 0x568;
const GUEST_DBGCTL_OFFSET: usize = 0x670;
const TRAP_FLAG: u64 = 1 << 8;
const RESUME_FLAG: u64 = 1 << 16;
const BRANCH_SINGLE_STEP: u64 = 1 << 1;
const DR6_BREAKPOINTS: u64 = 0xf;
const DR6_SINGLE_STEP: u64 = 1 << 14;
const DEBUG_TRAP_INJECTION: u64 = (1 << 31) | (3 << 8) | 1;

// Continuation and committed instruction state.
impl Vmcb {
    /// RAX is uninterpreted register data.
    pub fn set_guest_rax(&mut self, rax: u64) {
        self.write_u64::<GUEST_RAX>(rax);
    }

    /// Core-only application of the native adapter's prepared bootstrap state.
    /// All destination checks precede the first write. APM2 rev3.44 15.5.1/2,
    /// 15.7 and Appendix B; only VMSAVE-defined auxiliary fields are imported.
    /// Source control/reserved/exit bytes are never interpreted as CPU state.
    pub(crate) fn apply_native_continuation(
        &mut self,
        prepared: &crate::guest::continuation::PreparedNativeContinuation<'_>,
    ) -> Result<(), crate::guest::continuation::NativeContinuationError> {
        use crate::guest::continuation::NativeContinuationError as E;
        if self.event_injection() != 0
            || self.read_u64::<0x088>() != 0
            || self.read_u64::<0x068>() != 0
            || self.read_u64::<0x070>() != 0
            || self.virtual_interrupt_control() & !(0xf | (1 << 24)) != 0
            || self.read_u64::<0x090>() & !1 != 0
            || self.read_u64::<0x0b8>() != 0
        {
            return Err(E::DestinationEventState);
        }
        let r = &prepared.request;
        let s = r.entry;
        self.write_segment::<0x410>(prepared.segments[0]);
        self.write_segment::<0x420>(prepared.segments[1]);
        self.write_segment::<0x430>(prepared.segments[2]);
        self.write_segment::<0x400>(prepared.segments[3]);
        let gdtr = r.gdt.table();
        self.write_segment::<0x460>(SegmentState {
            selector: 0,
            attributes: 0,
            limit: u32::from(gdtr.limit),
            base: gdtr.base,
        });
        self.write_segment::<0x480>(SegmentState {
            selector: 0,
            attributes: 0,
            limit: u32::from(r.idtr.limit),
            base: r.idtr.base,
        });
        for (start, end) in [(0x440, 0x460), (0x470, 0x480), (0x490, 0x4a0), (0x600, 0x640)] {
            self.bytes[start..end].copy_from_slice(&r.auxiliary.bytes()[start..end]);
        }
        self.bytes[0x4cb] = 0;
        self.write_u64::<GUEST_EFER>(s.efer | (1 << 12));
        self.write_u64::<GUEST_CR0>(s.cr0);
        self.write_u64::<GUEST_CR3>(s.cr3);
        self.write_u64::<GUEST_CR4>(s.cr4);
        self.write_u64::<GUEST_RFLAGS>(s.rflags);
        self.write_u64::<GUEST_RIP>(s.rip);
        self.write_u64::<GUEST_RSP>(s.rsp);
        self.write_u64::<GUEST_RAX>(s.rax);
        self.write_u64::<0x640>(r.cr2);
        self.write_u64::<0x560>(r.dr7);
        self.write_u64::<0x568>(r.dr6);
        self.write_u64::<0x668>(r.pat);
        self.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(
            (self.virtual_interrupt_control() & !0xf) | r.cr8,
        );
        self.request_full_tlb_flush();
        // Initial context replaces cached and VMLOAD-only state, including
        // raw auxiliary copies and CPL. Never reuse an earlier page occupant.
        self.invalidate_all();
        Ok(())
    }

    /// Import the separately sampled native CET MSRs before the first entry.
    /// VMSAVE does not capture these fields (APM3 rev3.37 VMSAVE); their VMCB
    /// locations are APM2 rev3.44 Table B-2. CR4.CET must still be disabled at
    /// this initial boundary. This does not capture a dormant hardware SSP or
    /// authorize an already active shadow-stack continuation. U_CET, PLn_SSP
    /// and XSS remain live on the same physical CPU, unused by the monitor.
    /// The caller must have enumerated CET_SS before reading these MSRs.
    pub fn initialize_native_cet_msrs(
        &mut self,
        s_cet: u64,
        isst_addr: u64,
    ) -> Result<(), crate::guest::continuation::NativeContinuationError> {
        use crate::guest::continuation::NativeContinuationError as E;
        if self.read_u64::<GUEST_CR4>() & (1 << 23) != 0 || s_cet & !3 != 0 {
            return Err(E::UnsupportedCr4);
        }
        if !crate::memory::address::is_canonical_48(isst_addr) {
            return Err(E::NoncanonicalAddress);
        }
        self.write_u64::<GUEST_S_CET>(s_cet);
        self.write_u64::<GUEST_ISST_ADDR>(isst_addr);
        Ok(())
    }

    /// Only the crate's dispatcher may commit a checked instruction outcome.
    /// This changes stored state; it does not run the guest or flush a TLB.
    pub(crate) fn commit_emulated_instruction(&mut self, rax: u64, next: ResumeCandidate) {
        self.write_u64::<GUEST_RAX>(rax);
        self.write_u64::<GUEST_RIP>(next.address());
    }

    /// EFER policy has checked the logical value and its architectural faults.
    /// Preserve mandatory hardware SVME and invalidate translations after a
    /// paging-permission change (APM2 15.16, Appendix B TLB_CONTROL=1).
    pub(crate) fn commit_native_efer(&mut self, logical: u64) {
        let backing = logical | (1 << 12);
        let previous = self.guest_efer();
        self.write_u64::<GUEST_EFER>(backing);
        // APM2 physical p591 lists NXE/LMA/LME as paging state. A legal
        // guest WRMSR preserves LMA (PPR57896 p186); keeping it here also
        // covers any future owner that commits a complete mode transition.
        if (previous ^ backing) & ((1 << 8) | (1 << 10) | (1 << 11)) != 0 {
            self.request_guest_rap_clear();
        }
        self.request_full_tlb_flush();
    }

    /// Prepare retirement of an already validated, successful RDMSR/WRMSR.
    ///
    /// The caller owns a real stopped MSR intercept, its mode and continuation,
    /// and must resolve architectural faults before calling this method. No
    /// faulting instruction retires or raises a single-step trap (APM2 physical
    /// pages 305, 470, 570). Commit this result only to the same stopped VMCB,
    /// without changing event or debug state between preparation and commit.
    ///
    /// Saved DBGCTL is authoritative only with the admitted hardware LBR switch
    /// (physical pages 602, 807). BTF steps control transfers, so these sequential
    /// MSR instructions do not raise #DB when BTF is set (pages 460, 472).
    /// A shadow does not identify its STI/MOV-SS origin or deferred debug cause;
    /// keep that case bounded until it has a separate owner (pages 306, 597, 803).
    pub(crate) fn prepare_native_msr_retirement(
        &self,
    ) -> Result<PreparedNativeMsrRetirement, NativeRetirementError> {
        self.validate_external_interrupt_conflicts().map_err(NativeRetirementError::EventState)?;
        if self.guest_rflags() & TRAP_FLAG == 0 {
            return Ok(PreparedNativeMsrRetirement { debug_status: None });
        }
        if !self.native_lbr_enabled() {
            return Err(NativeRetirementError::DebugControlUnavailable);
        }
        if self.read_u64::<INTERRUPT_SHADOW_OFFSET>() & 1 != 0 {
            return Err(NativeRetirementError::InterruptShadow);
        }
        let debug_status = if self.read_u64::<GUEST_DBGCTL_OFFSET>() & BRANCH_SINGLE_STEP != 0 {
            None
        } else {
            // RDMSR/WRMSR have no data or I/O operand. Instruction breakpoints
            // precede the intercept, and RF suppresses their conditions (APM2
            // physical pages 467, 570). Thus this pure single-step trap has no
            // address-breakpoint cause. Preserve sticky BS/BD/BT and BLD, clear
            // B0-B3, then set BS (pages 455-456, 469, 825-826).
            Some((self.read_u64::<GUEST_DR6_OFFSET>() & !DR6_BREAKPOINTS) | DR6_SINGLE_STEP)
        };
        Ok(PreparedNativeMsrRetirement { debug_status })
    }

    /// Commit the prepared retirement after the caller commits the MSR result
    /// and next RIP. Returns whether a post-instruction #DB is now queued.
    ///
    /// Leave TF, DR7.GD, DBGCTL and branch records intact for architectural #DB
    /// entry through EVENTINJ. Hardware pushes TF=1 and applies normal exception
    /// entry effects; doing those early would corrupt a failed delivery (APM2
    /// physical pages 458, 470-472, 593-594). This also preserves pending virtual
    /// NMIs; #DB precedes NMI and INTR (physical page 327).
    pub(crate) fn complete_native_msr_retirement(
        &mut self,
        prepared: PreparedNativeMsrRetirement,
    ) -> bool {
        self.complete_native_instruction_state();
        if let Some(debug_status) = prepared.debug_status {
            self.write_u64::<GUEST_DR6_OFFSET>(debug_status);
            self.write_u64::<EVENT_INJECTION_OFFSET>(DEBUG_TRAP_INJECTION);
            true
        } else {
            false
        }
    }

    /// Consume the shadow and RF after successful instruction completion
    /// (APM2 physical pages 116, 597). Callers that support single stepping use
    /// prepared MSR retirement; other bounded owners must reject TF themselves.
    pub(crate) fn complete_native_instruction_state(&mut self) {
        self.write_u64::<INTERRUPT_SHADOW_OFFSET>(self.read_u64::<INTERRUPT_SHADOW_OFFSET>() & !1);
        self.write_u64::<GUEST_RFLAGS>(self.guest_rflags() & !RESUME_FLAG);
    }
}

/// Prevalidated retirement; deliberately not Copy so one completion consumes it.
#[derive(Debug)]
pub(crate) struct PreparedNativeMsrRetirement {
    debug_status: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRetirementError {
    DebugControlUnavailable,
    InterruptShadow,
    EventState(ExternalInterruptError),
}
