use core::mem::{align_of, size_of};

use svmvisor_hypervisor::svm::permission_maps::{
    IOPM_BYTES, Iopm, MSRPM_BYTES, MsrAccess, Msrpm, Permission, PermissionMapError,
};

#[test]
fn storage_layout_and_default_intercept_every_bit_including_padding() {
    assert_eq!(IOPM_BYTES, 12288);
    assert_eq!(MSRPM_BYTES, 8192);
    assert_eq!(size_of::<Iopm>(), 12288);
    assert_eq!(size_of::<Msrpm>(), 8192);
    assert_eq!(align_of::<Iopm>(), 4096);
    assert_eq!(align_of::<Msrpm>(), 4096);
    assert_eq!(Iopm::default().bytes(), &[0xff; 12288]);
    assert_eq!(Msrpm::default().bytes(), &[0xff; 8192]);
}

#[test]
fn io_ranges_change_only_selected_bits_and_never_clear_overrun_bits() {
    let mut map = Iopm::new();
    map.set_range(0, 1, Permission::Allow).unwrap();
    map.set_range(7, 3, Permission::Allow).unwrap();
    map.set_range(65535, 1, Permission::Allow).unwrap();
    let mut expected = [0xff; 12288];
    expected[0] = 0x7e;
    expected[1] = 0xfc;
    expected[8191] = 0x7f;
    assert_eq!(map.bytes(), &expected);
    map.set_range(8, 1, Permission::Intercept).unwrap();
    expected[1] = 0xfd;
    assert_eq!(map.bytes(), &expected);

    map.set_range(0, 65536, Permission::Allow).unwrap();
    expected[..8192].fill(0);
    assert_eq!(map.bytes(), &expected);
    map.set_range(0, 65536, Permission::Intercept).unwrap();
    assert_eq!(map.bytes(), &[0xff; 12288]);
}

#[test]
fn invalid_io_ranges_leave_existing_permissions_unchanged() {
    let mut map = Iopm::new();
    map.set_range(8, 13, Permission::Allow).unwrap();
    let before = *map.bytes();
    for (port, count, error) in [
        (0, 0, PermissionMapError::EmptyIoRange),
        (65535, 0, PermissionMapError::EmptyIoRange),
        (65535, 2, PermissionMapError::IoRangeOutsidePorts),
        (0, 65537, PermissionMapError::IoRangeOutsidePorts),
        (1, u32::MAX, PermissionMapError::IoRangeOutsidePorts),
    ] {
        for permission in [Permission::Allow, Permission::Intercept] {
            assert_eq!(map.set_range(port, count, permission), Err(error));
            assert_eq!(map.bytes(), &before);
        }
    }
}

#[test]
fn msr_range_endpoints_and_read_write_bits_match_architectural_byte_fixture() {
    let mut map = Msrpm::new();
    // Independent byte/bit fixtures for the three architectural range ends,
    // plus the adjacent MSR sharing a byte with MSR 0.
    for (msr, access) in [
        (0, MsrAccess::Read),
        (1, MsrAccess::Write),
        (0x1fff, MsrAccess::Write),
        (0xc000_0000, MsrAccess::Write),
        (0xc000_1fff, MsrAccess::Read),
        (0xc001_0000, MsrAccess::Read),
        (0xc001_1fff, MsrAccess::Write),
    ] {
        map.set(msr, access, Permission::Allow).unwrap();
    }
    let mut expected = [0xff; 8192];
    expected[0x0000] = 0xf6;
    expected[0x07ff] = 0x7f;
    expected[0x0800] = 0xfd;
    expected[0x0fff] = 0xbf;
    expected[0x1000] = 0xfe;
    expected[0x17ff] = 0x7f;
    assert_eq!(map.bytes(), &expected);
    map.set(0, MsrAccess::Write, Permission::Allow).unwrap();
    expected[0] = 0xf4;
    assert_eq!(map.bytes(), &expected);
    map.set(0, MsrAccess::Read, Permission::Intercept).unwrap();
    expected[0] = 0xf5;
    assert_eq!(map.bytes(), &expected);
}

#[test]
fn msr_interior_slots_match_independent_architectural_byte_fixtures() {
    // APM2 rev3.44 section 15.11/Table 15-8 (24593_3.44_APM_Vol2 p580).
    // Fixed byte/bit fixtures cross 0x3f/0x40 and 0xff/0x100, cover every
    // pair within a byte, and include VM_CR, VM_HSAVE_PA and OSVW offsets.
    for (msr_base, byte_base) in [(0, 0), (0xc000_0000, 0x800), (0xc001_0000, 0x1000)] {
        for (index, byte_offset, read_bit) in [
            (0x03f, 0x0f, 6),
            (0x040, 0x10, 0),
            (0x0ff, 0x3f, 6),
            (0x100, 0x40, 0),
            (0x101, 0x40, 2),
            (0x102, 0x40, 4),
            (0x103, 0x40, 6),
            (0x114, 0x45, 0),
            (0x117, 0x45, 6),
            (0x140, 0x50, 0),
            (0x141, 0x50, 2),
        ] {
            for (access, bit) in [(MsrAccess::Read, read_bit), (MsrAccess::Write, read_bit + 1)] {
                let msr = msr_base + index;
                let mut map = Msrpm::new();
                let mut expected = [0xff; MSRPM_BYTES];
                expected[byte_base + byte_offset] &= !(1 << bit);
                map.set(msr, access, Permission::Allow).unwrap();
                assert_eq!(map.bytes(), &expected, "MSR {msr:08x} {access:?}");
                map.set(msr, access, Permission::Intercept).unwrap();
                assert_eq!(map.bytes(), &[0xff; MSRPM_BYTES], "MSR {msr:08x} {access:?}");
            }
        }
    }
}

#[test]
fn every_architectural_msr_access_changes_only_its_own_bit() {
    // Walk the manual's byte ranges and their four read/write pairs in order,
    // independently of the implementation's MSR-to-absolute-bit arithmetic.
    // This covers all 24,576 MSRs / 49,152 access bits, including range ends.
    let mut map = Msrpm::new();
    let mut expected = [0xff; MSRPM_BYTES];
    for (first_msr, bytes) in
        [(0, 0x0000..0x0800), (0xc000_0000, 0x0800..0x1000), (0xc001_0000, 0x1000..0x1800)]
    {
        let mut msr = first_msr;
        for byte in bytes {
            for read_bit in [0, 2, 4, 6] {
                for (access, bit) in [(MsrAccess::Read, read_bit), (MsrAccess::Write, read_bit + 1)]
                {
                    expected[byte] &= !(1 << bit);
                    map.set(msr, access, Permission::Allow).unwrap();
                    assert_eq!(map.bytes(), &expected, "MSR {msr:08x} {access:?}");
                    expected[byte] = 0xff;
                    map.set(msr, access, Permission::Intercept).unwrap();
                    assert_eq!(map.bytes(), &expected, "MSR {msr:08x} {access:?}");
                }
                msr += 1;
            }
        }
        assert_eq!(msr, first_msr + 0x2000);
    }
}

#[test]
fn native_boot_protects_vmcr_hsave_and_scaling_at_architectural_slots() {
    let map = Msrpm::native_boot();
    // Independent literal locations, including the OSVW exception and both
    // edges of the protected C00101xx block. Each mask covers read AND write.
    for (msr, byte, mask, intercepted) in [
        (0xc000_0080u32, 0x0820, 0x03, true), // EFER
        (0xc000_0081, 0x0820, 0x0c, false),
        (0xc000_0103, 0x0840, 0xc0, false), // TSC_AUX
        (0xc000_0104, 0x0841, 0x03, true),  // TSC_RATIO
        (0xc000_0105, 0x0841, 0x0c, false),
        (0xc001_00ff, 0x103f, 0xc0, false),
        (0xc001_0100, 0x1040, 0x03, true),
        (0xc001_0114, 0x1045, 0x03, true), // VM_CR
        (0xc001_0117, 0x1045, 0xc0, true), // VM_HSAVE_PA
        (0xc001_013f, 0x104f, 0xc0, true),
        (0xc001_0140, 0x1050, 0x03, false), // OSVW_ID_Length
        (0xc001_0141, 0x1050, 0x0c, false), // OSVW_Status
        (0xc001_0142, 0x1050, 0x30, true),
        (0xc001_0143, 0x1050, 0xc0, true),
        (0xc001_01ff, 0x107f, 0xc0, true),
        (0xc001_0200, 0x1080, 0x03, false),
    ] {
        assert_eq!(map.bytes()[byte] & mask, if intercepted { mask } else { 0 }, "MSR {msr:08x}");
    }
}

#[test]
fn native_boot_allows_only_smram_configuration_reads_in_the_protected_block() {
    let map = Msrpm::native_boot();
    // Independent full-map byte fixture: APM2 physical p580, Table 15-8.
    // The protected C00101xx block is FF except OSVW and the three readable
    // SMRAM controls (57896-3.00_PPR physical pp213-215). Byte 1044h covers
    // C0010110..113: clear read bits 2/4/6, retaining every write and 110h.
    let mut expected = [0; MSRPM_BYTES];
    expected[0x1800..].fill(0xff);
    expected[0x1040..0x1080].fill(0xff);
    expected[0x1044] = 0xab;
    expected[0x1050] = 0xf0; // OSVW length/status retain native reads and writes.
    expected[0x0820] = 0x03; // EFER.
    expected[0x0841] = 0x03; // TSC_RATIO.
    expected[0x003f] = 0x30; // MTRR_CAP.
    expected[0x0080..0x0084].fill(0xff); // Variable MTRRs.
    expected[0x0094] = 0x03; // Fixed MTRR 250h.
    expected[0x0096] = 0x0f; // Fixed MTRRs 258h/259h.
    expected[0x009a..0x009c].fill(0xff); // Fixed MTRRs 268h..26Fh.
    expected[0x00bf] = 0xc0; // MTRR_DEF_TYPE.
    expected[0x1004] = 0x03; // SYS_CFG.
    expected[0x1005] = 0xf0; // IORR 16h/17h.
    expected[0x1006] = 0x3f; // IORR 18h/19h and TOP_MEM.
    expected[0x1007] = 0x0c; // TOM2.
    assert_eq!(map.bytes(), &expected);
}

#[test]
fn unsupported_msrs_cannot_alias_a_valid_range_or_reserved_storage() {
    let mut map = Msrpm::new();
    map.set(0x1fff, MsrAccess::Read, Permission::Allow).unwrap();
    let before = *map.bytes();
    for msr in [0x2000, 0xbfff_ffff, 0xc000_2000, 0xc000_ffff, 0xc001_2000, 0xc002_0000, u32::MAX] {
        for access in [MsrAccess::Read, MsrAccess::Write] {
            for permission in [Permission::Allow, Permission::Intercept] {
                assert_eq!(
                    map.set(msr, access, permission),
                    Err(PermissionMapError::UnsupportedMsr)
                );
                assert_eq!(map.bytes(), &before);
            }
        }
    }
}
