//! Stopped-state regressions for MSR owners with the native VNMI profile.
//! These fixtures do not execute MSRs, VMRUN, NMI delivery, or a guest handler.

use core::ptr;

use svmvisor_hypervisor::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        msr::{EFER, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE, TSC_RATIO, TSC_RATIO_UNITY, VM_CR},
        registers::GuestRegisters,
    },
    memory::address::EncryptionState,
    svm::{
        control_msrs::{
            HsaveAddressPolicy, VM_HSAVE_PA, VisibleSvmControls,
            handle_visible_svm_controls_with_nrip,
        },
        dispatch::{NativeEfer, NativeMsrOutcome, handle_native_efer_with_nrip},
        vmcb::{EventIntercept, Vmcb},
        vmcr::{VisibleVmCr, handle_visible_vmcr_with_nrip},
    },
};

const V_NMI: u64 = 1 << 11;
const V_NMI_MASK: u64 = 1 << 12;
const V_NMI_ENABLE: u64 = 1 << 26;
const VNMI_STATES: [u64; 4] = [0, V_NMI, V_NMI_MASK, V_NMI | V_NMI_MASK];

fn capabilities() -> ValidatedCapabilities {
    CapabilityEvidence {
        vendor: CpuVendor::Amd,
        svm: EvidenceFlag::Set,
        nested_paging: EvidenceFlag::Set,
        svm_revision: Some(1),
        asid_count: Some(16),
        physical_address_bits: Some(48),
        vm_cr_svmdis: EvidenceFlag::Clear,
        hypervisor_present: EvidenceFlag::Clear,
        encryption: EncryptionState::Unencrypted { encryption_bit: None },
        optional: OptionalFeatures { nrip_save: true, ..Default::default() },
    }
    .validate()
    .unwrap()
}

fn efer(startup: bool) -> NativeEfer {
    let mut owner = NativeEfer::admit_native_visible_svm(
        0x500,
        1 << 2,
        (1 << 11) | (1 << 20) | (1 << 29),
        1 << 20,
        None,
    )
    .unwrap();
    if startup {
        owner.enable_guest_startup();
    }
    owner
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: exclusively owned inert VMCB fixture, in-bounds qword offsets only.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

fn stopped(index: u32, write: bool, input: u64, nmi: u64, startup: bool) -> (Vmcb, GuestRegisters) {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x060, 6 | if startup { 1 << 24 } else { 0 }),
        (0x070, 0x7c),
        (0x078, u64::from(write)),
        (0x0c8, 0x4002),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x558, 0x8000_0011),
        (0x570, 2),
        (0x578, 0x4000),
        (0x5f8, 0xaaaa_bbbb_0000_0000 | u64::from(input as u32)),
    ] {
        put(&mut vmcb, offset, value);
    }
    vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
    let control = vmcb.virtual_interrupt_control() | nmi;
    put(&mut vmcb, 0x060, control);
    let frame = GuestRegisters {
        rcx: 0xcccc_dddd_0000_0000 | u64::from(index),
        rdx: 0xeeee_ffff_0000_0000 | (input >> 32),
        rbx: 0xabcdef,
        ..GuestRegisters::default()
    };
    (vmcb, frame)
}

fn assert_vnmi(vmcb: &Vmcb, nmi: u64, startup: bool) {
    assert_eq!(
        vmcb.virtual_interrupt_control(),
        6 | V_NMI_ENABLE | nmi | if startup { 1 << 24 } else { 0 }
    );
    assert!(vmcb.event_intercept(EventIntercept::Nmi));
}

fn assert_fault_only(vmcb: &Vmcb, before: &[u8; 4096]) {
    let mut expected = *before;
    expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0du64.to_le_bytes());
    assert_eq!(*vmcb.bytes(), expected);
}

#[test]
fn efer_completion_and_fault_preserve_pending_and_blocked_vnmi() {
    for startup in [false, true] {
        for nmi in VNMI_STATES {
            for (write, input, fault) in
                [(false, 0, false), (true, 0xd00, false), (true, 0x400, true)]
            {
                let mut owner = efer(startup);
                let (mut vmcb, mut frame) = stopped(EFER, write, input, nmi, startup);
                let before = (owner, *vmcb.bytes(), frame);
                let outcome = handle_native_efer_with_nrip(
                    &mut owner,
                    &mut vmcb,
                    &mut frame,
                    &capabilities(),
                );
                assert_vnmi(&vmcb, nmi, startup);
                if fault {
                    assert_eq!(outcome, Ok(NativeMsrOutcome::GeneralProtectionPrepared));
                    assert_fault_only(&vmcb, &before.1);
                    assert_eq!((owner, frame), (before.0, before.2));
                } else {
                    assert_eq!(outcome, Ok(NativeMsrOutcome::Completed));
                    assert_eq!(vmcb.guest_rip(), 0x4002);
                    assert_eq!(vmcb.event_injection(), 0);
                    if write {
                        assert_eq!(owner.logical(), input);
                        assert_eq!(vmcb.guest_efer(), input | 0x1000);
                        assert_eq!(frame, before.2);
                    } else {
                        assert_eq!((vmcb.guest_rax(), frame.rdx), (0x500, 0));
                        let mut expected = before.2;
                        expected.rdx = 0;
                        assert_eq!((owner, frame), (before.0, expected));
                    }
                }
            }
        }
    }
}

#[test]
fn vmcr_read_ignored_write_and_fault_preserve_vnmi_lifecycle() {
    for startup in [false, true] {
        for nmi in VNMI_STATES {
            for (write, input, fault) in
                [(false, 0, false), (true, 8, false), (true, 1 << 63, true)]
            {
                let owner = VisibleVmCr::admit(8).unwrap();
                let (mut vmcb, mut frame) = stopped(VM_CR, write, input, nmi, startup);
                let before = (*vmcb.bytes(), frame);
                let outcome = handle_visible_vmcr_with_nrip(
                    &owner,
                    &efer(startup),
                    &mut vmcb,
                    &mut frame,
                    &capabilities(),
                    startup,
                );
                assert_vnmi(&vmcb, nmi, startup);
                assert_eq!(owner.logical(), 8);
                if fault {
                    assert_eq!(outcome, Ok(NativeMsrOutcome::GeneralProtectionPrepared));
                    assert_fault_only(&vmcb, &before.0);
                    assert_eq!(frame, before.1);
                } else {
                    assert_eq!(outcome, Ok(NativeMsrOutcome::Completed));
                    assert_eq!(vmcb.guest_rip(), 0x4002);
                    assert_eq!(vmcb.event_injection(), 0);
                    let mut expected = before.1;
                    if !write {
                        assert_eq!(vmcb.guest_rax(), 8);
                        expected.rdx = 0;
                    }
                    assert_eq!(frame, expected);
                }
            }
        }
    }
}

#[test]
fn hsave_and_ratio_reads_and_faults_preserve_vnmi_lifecycle() {
    for startup in [false, true] {
        for nmi in VNMI_STATES {
            for (index, value, invalid) in
                [(VM_HSAVE_PA, 0x1234_5000, 1), (TSC_RATIO, TSC_RATIO_UNITY, 1 << 40)]
            {
                for write in [false, true] {
                    let vmcr = VisibleVmCr::admit(8).unwrap();
                    let policy = HsaveAddressPolicy::admit_target(
                        TARGET_SIGNATURE,
                        TARGET_PHYSICAL_BITS,
                        1,
                        0,
                        0,
                    )
                    .unwrap();
                    let mut owner = VisibleSvmControls::admit_firmware_zero_key(
                        0x1234_5000,
                        TSC_RATIO_UNITY,
                        policy,
                        &vmcr,
                    )
                    .unwrap();
                    let (mut vmcb, mut frame) = stopped(index, write, invalid, nmi, startup);
                    let before = (owner, *vmcb.bytes(), frame);
                    let outcome = handle_visible_svm_controls_with_nrip(
                        &mut owner,
                        &vmcr,
                        &efer(startup),
                        &mut vmcb,
                        &mut frame,
                        &capabilities(),
                        startup,
                    );
                    assert_vnmi(&vmcb, nmi, startup);
                    assert_eq!(owner, before.0);
                    if write {
                        assert_eq!(outcome, Ok(NativeMsrOutcome::GeneralProtectionPrepared));
                        assert_fault_only(&vmcb, &before.1);
                        assert_eq!(frame, before.2);
                    } else {
                        assert_eq!(outcome, Ok(NativeMsrOutcome::Completed));
                        assert_eq!(vmcb.guest_rip(), 0x4002);
                        assert_eq!(vmcb.event_injection(), 0);
                        assert_eq!(vmcb.guest_rax(), u64::from(value as u32));
                        let mut expected = before.2;
                        expected.rdx = value >> 32;
                        assert_eq!(frame, expected);
                    }
                }
            }
        }
    }
}

#[test]
fn orphaned_nmi_state_or_missing_interception_still_refuses_without_mutation() {
    for control in [V_NMI, V_NMI_MASK, V_NMI | V_NMI_MASK, V_NMI_ENABLE] {
        let mut owner = efer(false);
        let (mut vmcb, mut frame) = stopped(EFER, false, 0, 0, false);
        put(&mut vmcb, 0x060, control);
        if control & V_NMI_ENABLE != 0 {
            vmcb.set_event_intercept(EventIntercept::Nmi, false);
        }
        let before = (owner, *vmcb.bytes(), frame);
        assert!(
            handle_native_efer_with_nrip(&mut owner, &mut vmcb, &mut frame, &capabilities(),)
                .is_err()
        );
        assert_eq!((owner, *vmcb.bytes(), frame), before);
    }
}
