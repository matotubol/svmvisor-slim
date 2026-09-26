//! Allocator-style initialization without manufacturing enum values from bytes.
use core::{mem::size_of, ptr};
use svmvisor_hypervisor::{
    arch::x86_64::msr::TARGET_SIGNATURE,
    firmware::native::resident::iommu::{
        AcquisitionError, ObservationState, ReadError, ReadOnlyAccess, Scratch,
        retained::{
            CaptureMetadata, HEADER_BYTES, REPORT_OFFSET, RETAINED_ALIGN, RETAINED_BYTES,
            RetainedHeader, RetainedObservation, RetentionError,
        },
    },
    memory::address::{AddressPolicy, EncryptionState},
};

const METADATA: CaptureMetadata = CaptureMetadata {
    configuration_route: 0xe000_0021,
    signature: TARGET_SIGNATURE,
    physical_bits: 48,
    cpu_count: 24,
};

struct Unavailable {
    calls: usize,
}

impl ReadOnlyAccess for Unavailable {
    fn read_firmware(&mut self, _: u64, _: &mut [u8]) -> Result<(), ReadError> {
        self.calls += 1;
        Err(ReadError::Unavailable)
    }
    fn read_acpi(&mut self, _: u64, _: &mut [u8]) -> Result<(), ReadError> {
        panic!("no ACPI after firmware access failed")
    }
    fn read_pci_u32(&mut self, _: u16, _: u16, _: u64) -> Result<u32, ReadError> {
        panic!("no PCI after firmware access failed")
    }
    fn read_mmio_u64(&mut self, _: u64) -> Result<u64, ReadError> {
        panic!("no MMIO after firmware access failed")
    }
}

#[test]
fn static_initializer_captures_in_final_allocation_and_header_can_be_copied_alone() {
    let mut allocation = Box::<RetainedObservation>::new_uninit();
    let base = allocation.as_mut_ptr();
    assert_eq!(base as usize % RETAINED_ALIGN, 0);
    // The allocation is exclusive, aligned and large enough. The source is an
    // initialized static Rust value, disjoint from the destination. In contrast
    // to zeroing or decoding raw firmware bytes this establishes enum validity.
    unsafe { ptr::copy_nonoverlapping(RetainedObservation::empty_template(), base, 1) };
    let mut retained = unsafe { allocation.assume_init() };
    assert_eq!(size_of::<RetainedHeader>(), HEADER_BYTES);
    assert_eq!(RETAINED_BYTES, 24_944);
    let header = unsafe { ptr::read(base.cast::<RetainedHeader>()) };
    assert_eq!(header.validate(METADATA), Err(RetentionError::NotPublished));

    {
        let policy =
            AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
        let mut access = Unavailable { calls: 0 };
        let mut scratch = Scratch::EMPTY;
        retained.capture_once(METADATA, &mut access, policy, 0x10_0000, &mut scratch).unwrap();
        assert_eq!(access.calls, 1);
    }
    assert_eq!((&*retained) as *const RetainedObservation, base);
    let header = unsafe { ptr::read(base.cast::<RetainedHeader>()) };
    assert_eq!(header.validate(METADATA), Ok(0x0200_0020));
    let report = retained.report(METADATA).unwrap();
    assert_eq!(report as *const _ as usize - base as usize, REPORT_OFFSET);
    assert_eq!(report.state, ObservationState::Unavailable);
    assert_eq!(report.failure, Some(AcquisitionError::Read(ReadError::Unavailable)));
    assert!(!report.tables.is_complete());

    // This independently owned integer-only header can still be checked after
    // the typed allocation is gone. It proves no payload or hardware property.
    drop(retained);
    assert_eq!(header.validate(METADATA), Ok(0x0200_0020));
}
