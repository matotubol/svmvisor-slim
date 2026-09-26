//! Permanent per-vCPU configuration route checks and strict effect refusals.
//!
//! No ECAM aperture is ever reopened. Only the documented DWORD CF8 selector
//! cycle and unchanged route-MSR state can complete in the native default.
//! An explicit virtual PCI owner has a separate prepare/effect/commit path,
//! exercised offline; native admission and retained backing remain unavailable.
//! Indirect fabric, reset and route changes need a complete platform owner.
//! This intermediate policy is not ready for ordinary Windows deployment.

use core::{arch::asm, ptr};

use crate::{
    arch::x86_64::{
        msr::{
            HWCR, HWCR_IO_CFG_GP_FAULT, MMIO_CFG_BASE_ADDR, SMI_ON_IO_TRAP_CTL_STS,
            SMI_ON_IO_TRAP_ENABLE,
        },
        registers::GuestRegisters,
    },
    host::resident::runtime::{
        IOPM, MSRPM, State, exit::retry_routing, msr::read_msr, startup::mailboxes, stop::stop,
    },
    svm::{
        configuration::{LegacySelector, handle_route_msr},
        diagnostic_config::{SelectorAccess, prepare_io},
        pci::{ConfigAccess, transport},
        startup::try_lock_routes,
        vmcb::Vmcb,
    },
};

/// Check the same physical CPU at every exit and immediately before entry.
/// Guest INIT resets neither this owner nor its required intercepts. Trusted
/// firmware/SMM is still a prerequisite; this detects sampled drift only.
pub(super) unsafe fn verify(state: &mut State, vmcb: &Vmcb) -> bool {
    let exit = vmcb.exit_snapshot();
    let Some(route) = state.configuration else {
        return stop(state, exit.code, exit.rip, 0xf206, 0);
    };
    if !route.intercepts_installed(
        unsafe { &*ptr::addr_of!(IOPM) },
        unsafe { &*ptr::addr_of!(MSRPM) },
        vmcb,
    ) {
        return stop(state, exit.code, exit.rip, 0xf206, 1);
    }
    if !state.platform_io.is_some_and(|platform| {
        platform.validate(route, state.count)
            && platform.installed(unsafe { &*ptr::addr_of!(IOPM) })
    }) {
        return stop(state, exit.code, exit.rip, 0xf206, 2);
    }
    // Exact-target admission in arm precedes this same-CPU MSR access.
    let observed = unsafe { read_msr(MMIO_CFG_BASE_ADDR) };
    if route.verify(observed).is_err() {
        return stop(state, exit.code, exit.rip, 0xf206, observed);
    }
    true
}

/// Actual IOIO exit under GIF/IF=0. Unsupported effects never issue native I/O
/// or commit guest state. The shared startup route gate has no card dependency.
pub(super) unsafe fn handle_io(state: &mut State, vmcb: &mut Vmcb) -> bool {
    let exit = vmcb.exit_snapshot();
    if !unsafe { verify(state, vmcb) } {
        return false;
    }
    // The event owner has retained interrupted delivery; retry after delivery
    // before preparing or executing a new instruction.
    if vmcb.event_injection() & (1 << 31) != 0 {
        return true;
    }
    if !state.startup_owned || !(1..=32).contains(&state.count) {
        return stop(state, exit.code, exit.rip, 0xf200, 0);
    }
    let Ok(_guard) = try_lock_routes(unsafe { mailboxes(state.count) }) else {
        return retry_routing(state, vmcb);
    };
    complete_io(
        state,
        vmcb,
        |index| unsafe { read_msr(index) },
        |access| unsafe { selector_cycle(access) },
    )
}

/// The caller owns the same stopped CPU, admitted route and shared route gate,
/// with GIF/IF clear. Substituted effects let inert tests prove refusal ordering;
/// they confer no hardware authority. Native callers sample controls afresh.
fn complete_io(
    state: &mut State,
    vmcb: &mut Vmcb,
    mut sample: impl FnMut(u32) -> u64,
    cycle: impl FnOnce(SelectorAccess) -> u32,
) -> bool {
    // No complete physical/virtual owner or shared mutable backing has been
    // admitted by arm. Historical inventory must never fill this option.
    complete_owned_io(state, vmcb, &mut sample, cycle, None)
}

fn complete_owned_io(
    state: &mut State,
    vmcb: &mut Vmcb,
    mut sample: impl FnMut(u32) -> u64,
    cycle: impl FnOnce(SelectorAccess) -> u32,
    owner: Option<&mut dyn ConfigAccess>,
) -> bool {
    let exit = vmcb.exit_snapshot();
    let prepared = match prepare_io(vmcb) {
        Ok(prepared) => prepared,
        Err(_) => return stop(state, exit.code, exit.rip, 0xf201, exit.info1),
    };
    // IOIO interception precedes this instruction-specific architectural fault
    // (APM2 p579; PPR p203). It applies even to refused CF9/overlapping scalars.
    if sample(HWCR) & HWCR_IO_CFG_GP_FAULT != 0 {
        if prepared.fault_if_disabled().is_err() {
            return stop(state, exit.code, exit.rip, 0xf204, exit.info1);
        }
        state.pending_fault = true;
        state.routing_retries = 0;
        return true;
    }
    if let Some(owner) = owner {
        if state.configuration != Some(owner.route()) {
            return stop(state, exit.code, exit.rip, 0xf206, 3);
        }
        // Virtual and native selector modes must never be mixed. Every CPU
        // shares this virtual selector and its effect owner under the gate.
        let trap_control = sample(SMI_ON_IO_TRAP_CTL_STS);
        if trap_control & SMI_ON_IO_TRAP_ENABLE != 0 {
            return stop(state, exit.code, exit.rip, 0xf20a, trap_control);
        }
        if transport::complete_io(prepared, Some(owner)).is_err() {
            return stop(state, exit.code, exit.rip, 0xf207, exit.info1);
        }
        state.routing_retries = 0;
        return true;
    }
    let access = match prepared.selector_access() {
        Ok(access) => access,
        Err(_) => return stop(state, exit.code, exit.rip, 0xf207, exit.info1),
    };
    // PPR57896 physical p208: a matching enabled trap suppresses the I/O
    // instruction. Refuse the entire enabled mechanism instead of claiming
    // that a returned host IN/OUT completed the guest's selector effect.
    // HWCR's architectural #GP priority and operand admission precede this
    // same-CPU sample; no SMM emulation or guest fault is synthesized here.
    let trap_control = sample(SMI_ON_IO_TRAP_CTL_STS);
    if trap_control & SMI_ON_IO_TRAP_ENABLE != 0 {
        return stop(state, exit.code, exit.rip, 0xf20a, trap_control);
    }
    let value = cycle(access);
    if matches!(access, SelectorAccess::Read) && LegacySelector::admit(value).is_err() {
        return stop(state, exit.code, exit.rip, 0xf208, u64::from(value));
    }
    prepared.commit(value);
    state.routing_retries = 0;
    true
}

/// Only complete_io calls this after its fresh same-CPU control checks.
unsafe fn selector_cycle(access: SelectorAccess) -> u32 {
    match access {
        SelectorAccess::Read => {
            let value: u32;
            // PPR p42 identifies this exact DWORD access as the selector,
            // independently of its ConfigEn bit. No data/reset port is read.
            unsafe {
                asm!("in eax,dx", in("dx") 0xcf8u16, out("eax") value,
                    options(nostack, preserves_flags));
            }
            value
        }
        SelectorAccess::Write(selector) => {
            // A selector write chooses an address; it never emits a PCI data
            // cycle. Preserve the native selector rather than inventing a
            // cross-CPU shadow-sharing model for this hardware register.
            unsafe {
                asm!("out dx,eax", in("dx") 0xcf8u16, in("eax") selector.raw(),
                    options(nostack, preserves_flags));
            }
            0
        }
    }
}

pub(super) unsafe fn handle_msr(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> bool {
    let exit = vmcb.exit_snapshot();
    if !unsafe { verify(state, vmcb) } {
        return false;
    }
    if vmcb.event_injection() & (1 << 31) != 0 {
        return true;
    }
    let (Some(route), Some(capabilities)) = (state.configuration, state.capabilities) else {
        return stop(state, exit.code, exit.rip, 0xf206, 2);
    };
    // Resample immediately before this scalar action as well as at exit entry.
    let observed = unsafe { read_msr(MMIO_CFG_BASE_ADDR) };
    if handle_route_msr(&route, observed, vmcb, frame, &capabilities, state.startup_owned).is_err()
    {
        let requested = u64::from(vmcb.guest_rax() as u32) | (u64::from(frame.rdx as u32) << 32);
        return stop(state, exit.code, exit.rip, 0xf202, requested);
    }
    state.routing_retries = 0;
    true
}

/// Every ECAM write remains a stopped unsupported operation. EXITINFO2 only
/// identifies the faulting GPA; it does not establish operand length or PCI
/// effects. Do not decode a guessed width, write memory, or advance the RIP.
pub(super) fn refuse_ecam(state: &mut State, vmcb: &Vmcb) -> bool {
    let exit = vmcb.exit_snapshot();
    stop(state, exit.code, exit.rip, 0xf209, exit.info2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arch::x86_64::msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
        host::resident::runtime::INITIAL_STATE,
        svm::configuration::ConfigurationRoute,
        svm::pci::Bus,
    };

    fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
        // SAFETY: exclusively owned inert VMCB, with in-bounds constant offsets.
        unsafe {
            ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
        }
    }

    fn io_fixture(input: bool, port: u16, width: u8) -> Vmcb {
        let mut vmcb = Vmcb::new();
        for (offset, value) in [
            (0x068, 1),
            (0x070, 0x7b),
            (0x078, (u64::from(port) << 16) | (u64::from(width) << 4) | u64::from(input)),
            (0x080, 0x4002),
            (0x0c8, u64::MAX),
            (0x410, 0x29b << 16),
            (0x4d0, 0x1500),
            (0x570, 0x10002),
            (0x578, 0x4000),
            (0x5f8, 0xaabb_ccdd_8000_1230),
        ] {
            put(&mut vmcb, offset, value);
        }
        vmcb
    }

    #[test]
    fn enabled_smi_io_traps_refuse_before_selector_cycle_without_guest_changes() {
        for input in [false, true] {
            // Refuse the global enable even when all individual enables are clear.
            for enables in 0u64..16 {
                let control = (1 << 15)
                    | ((enables & 1) << 1)
                    | ((enables & 2) << 2)
                    | ((enables & 4) << 3)
                    | ((enables & 8) << 4);
                let mut vmcb = io_fixture(input, 0xcf8, 4);
                let before = *vmcb.bytes();
                let mut state = INITIAL_STATE;
                state.routing_retries = 3;
                let mut samples = 0;
                assert!(!complete_io(
                    &mut state,
                    &mut vmcb,
                    |index| {
                        let expected = [HWCR, SMI_ON_IO_TRAP_CTL_STS][samples];
                        assert_eq!(index, expected);
                        samples += 1;
                        if index == HWCR { 0 } else { control }
                    },
                    |_| panic!("SMI-trapped selector issued native I/O"),
                ));
                assert_eq!(samples, 2);
                assert_eq!(*vmcb.bytes(), before);
                assert_eq!((state.stopped, state.stopped_rip), (0x7b, 0x4000));
                assert_eq!((state.stopped_info1, state.stopped_info2), (0xf20a, control));
                assert!(state.stopped_valid);
                assert!(!state.pending_fault);
                assert_eq!(state.routing_retries, 3);
            }
        }
    }

    #[test]
    fn disabled_smi_traps_allow_only_the_previously_admitted_selector_cycle() {
        for input in [false, true] {
            for control in [0, 0xaa] {
                let mut vmcb = io_fixture(input, 0xcf8, 4);
                let mut state = INITIAL_STATE;
                let samples = core::cell::Cell::new(0);
                let cycles = core::cell::Cell::new(0);
                assert!(complete_io(
                    &mut state,
                    &mut vmcb,
                    |index| {
                        assert_eq!(index, [HWCR, SMI_ON_IO_TRAP_CTL_STS][samples.get()]);
                        samples.set(samples.get() + 1);
                        if index == HWCR { 0 } else { control }
                    },
                    |access| {
                        assert_eq!(samples.get(), 2, "cycle preceded fresh control sample");
                        cycles.set(cycles.get() + 1);
                        assert_eq!(
                            access,
                            if input {
                                SelectorAccess::Read
                            } else {
                                SelectorAccess::Write(LegacySelector::admit(0x8000_1230).unwrap())
                            }
                        );
                        0x8000_7740
                    },
                ));
                assert_eq!(cycles.get(), 1);
                assert_eq!(vmcb.guest_rip(), 0x4002);
                assert_eq!(
                    vmcb.guest_rax(),
                    if input { 0x8000_7740 } else { 0xaabb_ccdd_8000_1230 }
                );
                assert_eq!(vmcb.event_injection(), 0);
                assert!(!state.stopped_valid);
            }
        }
    }

    #[test]
    fn hwcr_fault_priority_and_unsupported_operands_precede_trap_sampling() {
        for (port, width) in [(0xcf8, 4), (0xcf9, 1), (0xcfc, 4), (0xcf8, 1)] {
            for input in [false, true] {
                for disabled in [false, true] {
                    if !disabled && port == 0xcf8 && width == 4 {
                        continue;
                    }
                    let mut vmcb = io_fixture(input, port, width);
                    let before = *vmcb.bytes();
                    let mut state = INITIAL_STATE;
                    let mut samples = 0;
                    let completed = complete_io(
                        &mut state,
                        &mut vmcb,
                        |index| {
                            assert_eq!(index, HWCR, "trap sample preceded fault/operand admission");
                            samples += 1;
                            if disabled { HWCR_IO_CFG_GP_FAULT } else { 0 }
                        },
                        |_| panic!("fault or unsupported operand issued native I/O"),
                    );
                    assert_eq!(samples, 1);
                    assert_eq!(completed, disabled);
                    assert_eq!(state.pending_fault, disabled);
                    assert_eq!(vmcb.guest_rip(), 0x4000);
                    assert_eq!(vmcb.guest_rax(), 0xaabb_ccdd_8000_1230);
                    if disabled {
                        assert_eq!(vmcb.event_injection(), (1 << 31) | (1 << 11) | (3 << 8) | 13);
                        assert!(!state.stopped_valid);
                    } else {
                        assert_eq!(*vmcb.bytes(), before);
                        assert_eq!(state.stopped_info1, 0xf207);
                    }
                }
            }
        }
        let mut vmcb = io_fixture(false, 0xcf8, 4);
        vmcb.set_guest_rax(0x8100_0000); // Unsupported legacy extended selector.
        let before = *vmcb.bytes();
        let mut state = INITIAL_STATE;
        assert!(!complete_io(
            &mut state,
            &mut vmcb,
            |index| {
                assert_eq!(index, HWCR);
                0
            },
            |_| panic!("unsupported selector issued native I/O")
        ));
        assert_eq!(*vmcb.bytes(), before);
        assert_eq!(state.stopped_info1, 0xf207);
    }

    #[test]
    fn every_ecam_function_and_access_kind_stays_stopped_without_an_endpoint() {
        let route =
            ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 0xe0000021)
                .unwrap();
        for bdf in 0..=u16::MAX {
            for (offset, info) in [(0, 7), (4095, 7), (0, 0x17), (0, u64::MAX)] {
                let mut state = INITIAL_STATE;
                state.configuration = Some(route);
                let mut vmcb = Vmcb::new();
                let address = 0xe000_0000 + (u64::from(bdf) << 12) + offset;
                for (field, value) in [
                    (0x070, 0x400),
                    (0x078, info),
                    (0x080, address),
                    (0x0a8, 0x8000_0051),
                    (0x578, 0x1000),
                    (0x570, 0x10102),
                    (0x5f8, 0xa5a5_a5a5_a5a5_a5a5),
                ] {
                    put(&mut vmcb, field, value);
                }
                let before = *vmcb.bytes();
                assert!(!refuse_ecam(&mut state, &vmcb));
                assert_eq!(*vmcb.bytes(), before);
                assert_eq!(state.configuration, Some(route));
                assert!(state.stopped_valid);
                assert_eq!((state.stopped_info1, state.stopped_info2), (0xf209, address));
                assert!(state.terminal_endpoint.is_none());
            }
        }
    }

    #[test]
    fn missing_configuration_owner_refuses_before_any_hardware_sample() {
        let mut state = INITIAL_STATE;
        let vmcb = Vmcb::new();
        let before = *vmcb.bytes();
        // SAFETY: the absent owner path stops before touching maps or MSRs.
        assert!(!unsafe { verify(&mut state, &vmcb) });
        assert_eq!(*vmcb.bytes(), before);
        assert_eq!(state.stopped_info1, 0xf206);
    }

    #[test]
    fn admitted_virtual_io_shares_selector_and_never_uses_a_native_data_cycle() {
        use crate::svm::pci::{
            BusPolicy, ConfigOwner, Error, Function, Interrupt, Region, Transition,
        };
        struct SyntheticOwner;
        impl ConfigOwner for SyntheticOwner {
            fn admit(&mut self, _: BusPolicy, _: &[Region], _: &[Function]) -> Result<(), Error> {
                Ok(())
            }
            fn revalidate(&mut self) -> Result<(), Error> {
                Ok(())
            }
            fn apply(&mut self, _: Transition<'_>) -> Result<(), Error> {
                panic!("no functions in fixture")
            }
            fn dma(&mut self, _: u16, _: u64, _: u64, _: bool) -> Result<(), Error> {
                panic!("no DMA in fixture")
            }
            fn interrupt(&mut self, _: Interrupt, _: bool) -> Result<(), Error> {
                panic!("no interrupts in fixture")
            }
        }
        let route =
            ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 0xe0000021)
                .unwrap();
        let policy = BusPolicy {
            route,
            memory: Region { base: 0x8000_0000, bytes: 0x1000_0000 },
            io: Region { base: 0x1000, bytes: 0xe000 },
        };
        let mut functions = [];
        let mut effects = SyntheticOwner;
        let mut owner = Bus::new(policy, &[], &mut functions, &mut effects).unwrap();
        for (input, port, expected_rax) in
            [(false, 0xcf8, 0x8000_1230), (true, 0xcf8, 0x8000_1230), (true, 0xcfc, 0xffff_ffff)]
        {
            let mut vmcb = io_fixture(input, port, 4);
            vmcb.set_guest_rax(0x8000_1230);
            let mut state = INITIAL_STATE;
            state.configuration = Some(route);
            let mut samples = 0;
            assert!(complete_owned_io(
                &mut state,
                &mut vmcb,
                |index| {
                    assert_eq!(index, [HWCR, SMI_ON_IO_TRAP_CTL_STS][samples]);
                    samples += 1;
                    0
                },
                |_| panic!("virtual access issued native I/O"),
                Some(&mut owner)
            ));
            assert_eq!(samples, 2);
            assert_eq!(vmcb.guest_rip(), 0x4002);
            assert_eq!(vmcb.guest_rax(), expected_rax);
        }
        for (configuration, hwcr, trap, expected) in [
            (None, 0, 0, 0xf206),
            (Some(route), 0, SMI_ON_IO_TRAP_ENABLE, 0xf20a),
            (None, HWCR_IO_CFG_GP_FAULT, SMI_ON_IO_TRAP_ENABLE, 0),
        ] {
            let mut state = INITIAL_STATE;
            state.configuration = configuration;
            let mut vmcb = io_fixture(true, 0xcfc, 4);
            let before = *vmcb.bytes();
            let completed = complete_owned_io(
                &mut state,
                &mut vmcb,
                |index| if index == HWCR { hwcr } else { trap },
                |_| panic!("rejected virtual access issued native I/O"),
                Some(&mut owner),
            );
            assert_eq!(completed, expected == 0);
            assert_eq!(vmcb.guest_rip(), 0x4000);
            if expected == 0 {
                assert!(state.pending_fault);
            } else {
                assert_eq!(state.stopped_info1, expected);
                assert_eq!(*vmcb.bytes(), before);
            }
        }
    }
}
