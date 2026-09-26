use svmvisor_hypervisor::{
    arch::x86_64::{
        capabilities::{CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures},
        msr::{MMIO_CFG_BASE_ADDR, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
        registers::GuestRegisters,
    },
    memory::address::EncryptionState,
    svm::{
        configuration::{
            ConfigurationRoute, LegacySelector, RouteAccessError, RouteError, ScalarError,
            ScalarTarget, handle_route_msr,
        },
        diagnostic_config::{ConfigError, SelectorAccess, prepare_io},
        permission_maps::{Iopm, MsrAccess, Msrpm, Permission},
        vmcb::{InstructionIntercept, Vmcb},
    },
};

const RAW: u64 = 0xe000_0021;

fn route(raw: u64) -> ConfigurationRoute {
    ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, raw).unwrap()
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: exclusively owned inert VMCB fixture, checked in-bounds offsets.
    unsafe {
        core::ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
    }
}

fn stopped(code: u64, info: u64) -> Vmcb {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x070, code),
        (0x078, info),
        (0x080, 0x4002),
        (0x0c8, 0x4002),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x558, 0x8000_0011),
        (0x570, 0x10002),
        (0x578, 0x4000),
        (0x5f8, 0xaabb_ccdd_8001_2abc),
    ] {
        put(&mut vmcb, offset, value);
    }
    vmcb
}

fn io(port: u16, width: u8, input: bool) -> Vmcb {
    stopped(0x7b, (u64::from(port) << 16) | (u64::from(width) << 4) | u64::from(input))
}

fn flags(vmcb: &Vmcb) -> u64 {
    u64::from_le_bytes(vmcb.bytes()[0x570..0x578].try_into().unwrap())
}

fn caps(nrip: bool) -> svmvisor_hypervisor::arch::x86_64::capabilities::ValidatedCapabilities {
    CapabilityEvidence {
        vendor: CpuVendor::Amd,
        svm: EvidenceFlag::Set,
        nested_paging: EvidenceFlag::Set,
        svm_revision: Some(1),
        asid_count: Some(16),
        physical_address_bits: Some(TARGET_PHYSICAL_BITS),
        vm_cr_svmdis: EvidenceFlag::Clear,
        hypervisor_present: EvidenceFlag::Clear,
        encryption: EncryptionState::Unencrypted { encryption_bit: None },
        optional: OptionalFeatures { nrip_save: nrip, ..Default::default() },
    }
    .validate()
    .unwrap()
}

#[test]
fn target_route_validates_all_defined_single_segment_sizes() {
    for exponent in 0..=8 {
        let raw = 0xe000_0001 | (exponent << 2);
        let owner = route(raw);
        let bytes = 1u64 << (20 + exponent);
        assert_eq!(owner.aperture(), (0xe000_0000, bytes));
        assert!(owner.contains(0xe000_0000));
        assert!(owner.contains(0xe000_0000 + bytes - 1));
        assert!(!owner.contains(0xdfff_ffff));
        assert!(!owner.contains(0xe000_0000 + bytes));
        assert_eq!(owner.raw(), raw);
        assert_eq!(owner.verify(raw), Ok(()));
        for bit in 0..64 {
            assert_eq!(owner.verify(raw ^ (1u64 << bit)), Err(RouteError::Drift));
        }
    }
    let last = route(0x0000_ffff_f000_0021);
    assert_eq!(last.aperture(), (0x0000_ffff_f000_0000, 1 << 28));
    assert!(last.contains((1 << 48) - 1));
    assert!(!last.contains(1 << 48));
}

#[test]
fn disabled_reserved_multisegment_and_misaligned_routes_cannot_be_admitted() {
    let admit = |raw| ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, raw);
    assert_eq!(admit(RAW & !1), Err(RouteError::Disabled));
    assert_eq!(admit(1), Err(RouteError::PhysicalAddress));
    assert_eq!(admit(RAW | (1 << 20)), Err(RouteError::ApertureAlignment));
    for bit in (1..2).chain(6..20).chain(48..64) {
        assert_eq!(admit(RAW | (1 << bit)), Err(RouteError::ReservedBits));
    }
    for exponent in 9..=15 {
        assert_eq!(admit(0xe000_0001 | (exponent << 2)), Err(RouteError::UnsupportedSegments));
    }
    assert_eq!(
        ConfigurationRoute::admit_target(TARGET_SIGNATURE ^ 1, TARGET_PHYSICAL_BITS, RAW),
        Err(RouteError::UnsupportedCpu)
    );
    for width in [0, 32, 47, 49, 52, 64, u8::MAX] {
        assert_eq!(
            ConfigurationRoute::admit_target(TARGET_SIGNATURE, width, RAW),
            Err(RouteError::UnsupportedCpu)
        );
    }
}

#[test]
fn scalar_ecam_and_legacy_decode_the_same_bounded_function_and_lane() {
    let owner = route(RAW);
    for bdf in [0u16, 1, 0xff, 0x1234, u16::MAX] {
        for register in 0..=255 {
            for width in [1u8, 2, 4] {
                let selector =
                    LegacySelector::admit((1 << 31) | (u32::from(bdf) << 8) | (register & 0xfc))
                        .unwrap();
                let port = 0xcfc + (register & 3) as u16;
                let ecam = 0xe000_0000 + (u64::from(bdf) << 12) + u64::from(register);
                if (register & 3) + u32::from(width) <= 4 {
                    let expected = ScalarTarget { bdf, register: register as u16, width };
                    assert_eq!(selector.data(port, width), Ok(expected));
                    assert_eq!(owner.ecam_scalar(ecam, width), Ok(expected));
                } else {
                    assert_eq!(selector.data(port, width), Err(ScalarError::DwordCrossing));
                    assert_eq!(owner.ecam_scalar(ecam, width), Err(ScalarError::DwordCrossing));
                }
            }
        }
    }
}

#[test]
fn scalar_targets_never_cross_apertures_dwords_or_legacy_io_links() {
    let owner = route(RAW);
    for width in [0, 3, 8, u8::MAX] {
        assert_eq!(owner.ecam_scalar(0xe000_0000, width), Err(ScalarError::PortOrWidth));
    }
    for address in [0, 0xdfff_ffff, 0xf000_0000, u64::MAX] {
        assert_eq!(owner.ecam_scalar(address, 1), Err(ScalarError::OutsideAperture));
    }
    assert_eq!(
        owner.ecam_scalar(0xefff_ffff, 1),
        Ok(ScalarTarget { bdf: 0xffff, register: 4095, width: 1 })
    );
    assert_eq!(owner.ecam_scalar(0xefff_ffff, 2), Err(ScalarError::DwordCrossing));
    let disabled = LegacySelector::admit(0).unwrap();
    assert_eq!(disabled.data(0xcfc, 4), Err(ScalarError::DisabledLegacy));
    for bit in [0, 1, 28, 29, 30] {
        assert_eq!(LegacySelector::admit(1 << bit), Err(ScalarError::ReservedSelector));
    }
    for bit in 24..=27 {
        assert_eq!(LegacySelector::admit(1 << bit), Err(ScalarError::ExtendedLegacyUnsupported));
    }
    for port in [0, 0xcf8, 0xcf9, 0xcfb, 0xd00, u16::MAX] {
        assert_eq!(disabled.data(port, 1), Err(ScalarError::PortOrWidth));
    }
}

#[test]
fn permanent_intercepts_cover_all_overlap_lanes_without_an_endpoint() {
    let owner = route(RAW);
    let mut io = Iopm::new();
    let mut msrs = Msrpm::native_boot();
    let mut vmcb = Vmcb::new();
    owner.install_native_intercepts(&mut io, &mut msrs, &mut vmcb).unwrap();
    for port in 0..65536 {
        let intercepted = io.bytes()[port / 8] & (1 << (port % 8)) != 0;
        assert_eq!(intercepted, (0xcf8..=0xcff).contains(&port));
    }
    assert_eq!(io.bytes()[8192], 0xff); // Architectural overrun bits remain intercepted.
    assert!(owner.intercepts_installed(&io, &msrs, &vmcb));
    for port in 0xcf8..=0xcff {
        io.set_range(port, 1, Permission::Allow).unwrap();
        assert!(!owner.intercepts_installed(&io, &msrs, &vmcb));
        io.set_range(port, 1, Permission::Intercept).unwrap();
    }
    for access in [MsrAccess::Read, MsrAccess::Write] {
        msrs.set(MMIO_CFG_BASE_ADDR, access, Permission::Allow).unwrap();
        assert!(!owner.intercepts_installed(&io, &msrs, &vmcb));
        msrs.set(MMIO_CFG_BASE_ADDR, access, Permission::Intercept).unwrap();
    }
    for intercept in [InstructionIntercept::Ioio, InstructionIntercept::Msr] {
        vmcb.set_instruction_intercept(intercept, false);
        assert!(!owner.intercepts_installed(&io, &msrs, &vmcb));
        vmcb.set_instruction_intercept(intercept, true);
    }
}

#[test]
fn all_data_reset_and_partial_selector_effects_are_refused_transactionally() {
    for port in 0xcf5..=0xcff {
        for width in [1, 2, 4] {
            for input in [false, true] {
                if u32::from(port) + u32::from(width) <= 0xcf8 {
                    continue;
                }
                let mut vmcb = io(port, width, input);
                let before = *vmcb.bytes();
                let prepared = prepare_io(&mut vmcb).unwrap();
                let admitted = prepared.selector_access();
                if port == 0xcf8 && width == 4 {
                    assert!(admitted.is_ok());
                } else {
                    assert_eq!(admitted, Err(ConfigError::UnsupportedEffect));
                }
                drop(prepared);
                assert_eq!(*vmcb.bytes(), before);
            }
        }
    }
}

#[test]
fn selector_writes_cannot_smuggle_extended_or_reserved_addresses() {
    let mut vmcb = io(0xcf8, 4, false);
    for value in [0x8100_0000, 0x8800_0000, 0x9000_0000, 0x8000_0001, u32::MAX] {
        vmcb.set_guest_rax(u64::from(value));
        let before = *vmcb.bytes();
        let prepared = prepare_io(&mut vmcb).unwrap();
        assert!(matches!(prepared.selector_access(), Err(ConfigError::Selector(_))));
        drop(prepared);
        assert_eq!(*vmcb.bytes(), before);
    }
    vmcb.set_guest_rax(0x1234_5678_80ff_fffc);
    let prepared = prepare_io(&mut vmcb).unwrap();
    assert_eq!(
        prepared.selector_access(),
        Ok(SelectorAccess::Write(LegacySelector::admit(0x80ff_fffc).unwrap()))
    );
}

#[test]
fn hwcr_fault_precedes_effect_refusal_without_completing_cf9() {
    for input in [false, true] {
        let mut vmcb = io(0xcf9, 1, input);
        let old = (vmcb.guest_rip(), vmcb.guest_rax(), flags(&vmcb));
        let prepared = prepare_io(&mut vmcb).unwrap();
        assert_eq!(prepared.selector_access(), Err(ConfigError::UnsupportedEffect));
        prepared.fault_if_disabled().unwrap();
        assert_eq!((vmcb.guest_rip(), vmcb.guest_rax(), flags(&vmcb)), old);
        assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
    }
}

#[test]
fn unchanged_route_writes_and_reads_use_hardware_nrip_without_physical_programming() {
    for write in [false, true] {
        let mut vmcb = stopped(0x7c, u64::from(write));
        vmcb.set_guest_rax(0x1234_5678_0000_0000 | RAW);
        put(&mut vmcb, 0x0c8, 0x4005); // Hardware owns a prefixed instruction's length.
        let mut frame = GuestRegisters { rcx: u64::from(MMIO_CFG_BASE_ADDR), ..Default::default() };
        let before = (vmcb.guest_rax(), frame);
        handle_route_msr(&route(RAW), RAW, &mut vmcb, &mut frame, &caps(true), true).unwrap();
        assert_eq!(vmcb.guest_rip(), 0x4005);
        assert_eq!(flags(&vmcb), 2);
        assert_eq!(vmcb.event_injection(), 0);
        if write {
            assert_eq!((vmcb.guest_rax(), frame), before);
        } else {
            assert_eq!(vmcb.guest_rax(), RAW);
            assert_eq!(frame.rdx, 0);
        }
    }
}

#[test]
fn changed_route_writes_and_backing_drift_never_look_successful() {
    for value in [0, RAW & !1, RAW ^ 4, RAW ^ (1 << 28), RAW | 2, u64::MAX] {
        let mut vmcb = stopped(0x7c, 1);
        vmcb.set_guest_rax(u64::from(value as u32));
        let mut frame = GuestRegisters {
            rcx: u64::from(MMIO_CFG_BASE_ADDR),
            rdx: value >> 32,
            ..Default::default()
        };
        let before = (*vmcb.bytes(), frame);
        assert_eq!(
            handle_route_msr(&route(RAW), RAW, &mut vmcb, &mut frame, &caps(true), true),
            Err(RouteAccessError::RouteChangeUnsupported)
        );
        assert_eq!((*vmcb.bytes(), frame), before);
        assert_eq!(
            handle_route_msr(&route(RAW), value, &mut vmcb, &mut frame, &caps(true), true),
            Err(RouteAccessError::Route(RouteError::Drift))
        );
        assert_eq!((*vmcb.bytes(), frame), before);
    }
}

#[test]
fn route_access_refuses_pending_delivery_bad_mode_and_unproven_continuations() {
    for (offset, value) in [
        (0x070, 0x7b),
        (0x078, 2),
        (0x0a8, 0x8000_0051),
        (0x088, 0x8000_0051),
        (0x060, 1 << 8),
        (0x4c8, 3 << 24),
        (0x570, 0x102),
        (0x548, 1 << 12),
        (0x0c8, 0),
        (0x0c8, 0x4001),
        (0x0c8, 0x4010),
        (0x0c8, 0x8000_0000_0000),
    ] {
        let mut vmcb = stopped(0x7c, 0);
        put(&mut vmcb, offset, value);
        let mut frame = GuestRegisters { rcx: u64::from(MMIO_CFG_BASE_ADDR), ..Default::default() };
        let before = (*vmcb.bytes(), frame);
        assert!(
            handle_route_msr(&route(RAW), RAW, &mut vmcb, &mut frame, &caps(true), true).is_err()
        );
        assert_eq!((*vmcb.bytes(), frame), before);
    }
    let mut vmcb = stopped(0x7c, 0);
    let mut frame = GuestRegisters { rcx: u64::from(MMIO_CFG_BASE_ADDR), ..Default::default() };
    let before = (*vmcb.bytes(), frame);
    assert!(handle_route_msr(&route(RAW), RAW, &mut vmcb, &mut frame, &caps(false), true).is_err());
    assert_eq!((*vmcb.bytes(), frame), before);
}
