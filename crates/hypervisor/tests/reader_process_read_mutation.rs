//! Deterministic callback mutations demonstrate the limits of supplied-image observations.
//! These invented process layouts and byte arrays never access a running process or live memory.

use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{self, ProcessLayoutEvidence, ProcessObservation, ProcessProfile, ProcessRequest},
    read::{self, ReadReport},
};

const HEAD: u64 = 0x0800;
const PROCESS: u64 = 0x2000;
const PID: u64 = PROCESS + 0x028;
const CREATE_TIME: u64 = PROCESS + 0x030;
const ROOT: u64 = PROCESS + 0x040;

struct Image {
    bytes: Vec<u8>,
    calls: usize,
}

impl Image {
    fn new() -> Self {
        let mut image = Self { bytes: vec![0; 0x0001_0000], calls: 0 };
        // Kernel root identity-maps the synthetic list through a 1 GiB leaf.
        for (pa, value) in [
            (0x1000, 0x3001),
            (0x3000, 0x81),
            (HEAD, PROCESS + 0x010),
            (HEAD + 8, PROCESS + 0x010),
            (PROCESS + 0x010, HEAD),
            (PROCESS + 0x018, HEAD),
            (PID, 42),
            (CREATE_TIME, 100),
            (ROOT, 0x4000),
            // Process VA 0x8000 and 0x9000 map to distinct supplied physical pages.
            (0x4000, 0x5001),
            (0x5000, 0x6001),
            (0x6000, 0x7001),
            (0x7040, 0xa001),
            (0x7048, 0xb001),
            // A second root maps the same VA to the second data page.
            (0xc000, 0xd001),
            (0xd000, 0xe001),
            (0xe000, 0xf001),
            (0xf040, 0xb001),
        ] {
            image.word(pa, value);
        }
        image.bytes[0xa000..0xa008].copy_from_slice(b"old data");
        image.bytes[0xb000..0xb008].copy_from_slice(b"new data");
        image
    }

    fn word(&mut self, pa: u64, value: u64) {
        let start = pa as usize;
        self.bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn read(&mut self, pa: u64, bytes: &mut [u8]) -> Result<(), PagingError> {
        self.calls += 1;
        let start = usize::try_from(pa).map_err(|_| PagingError::PhysicalRead)?;
        let end = start.checked_add(bytes.len()).ok_or(PagingError::PhysicalRead)?;
        let source = self.bytes.get(start..end).ok_or(PagingError::PhysicalRead)?;
        bytes.copy_from_slice(source);
        Ok(())
    }
}

fn find(
    pid: u64,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
) -> ProcessObservation {
    let profile = ProcessProfile::new(ProcessLayoutEvidence {
        eprocess_bytes: 0x100,
        active_links_offset: 0x010,
        pid_offset: 0x028,
        create_time_offset: Some(0x030),
        directory_root_offset: 0x040,
        dtb_low_bits_mask: 0,
    })
    .unwrap();
    let request = ProcessRequest { kernel_root_pa: 0x1000, list_head_va: HEAD, pid, max_nodes: 1 };
    process::find(config(), profile, request, read).unwrap().unwrap()
}

fn config() -> PagingConfig {
    PagingConfig::new(48, true, true).unwrap()
}

#[test]
fn field_mutation_can_return_a_process_tuple_that_never_existed_together() {
    let mut image = Image::new();
    let mut changed = false;
    let observed = find(42, &mut |pa, bytes| {
        image.read(pa, bytes)?;
        if pa == PID && !changed {
            // Once PID 42 has been sampled, retire it before publishing the new root/time.
            image.word(PID, 84);
            image.word(ROOT, 0xc000);
            image.word(CREATE_TIME, 200);
            changed = true;
        }
        Ok(())
    });
    assert!(changed);
    assert_eq!(image.calls, 15);
    assert_eq!(
        observed,
        ProcessObservation {
            pid: 42,
            eprocess_va: PROCESS,
            create_time: Some(200),
            kernel_root_pa: 0xc000,
        }
    );
    let mut output = [0xcd; 8];
    let report = read::read_virtual(
        config(),
        observed.kernel_root_pa,
        0x8000,
        &mut output,
        &mut |pa, bytes| image.read(pa, bytes),
    );
    assert_eq!(report, ReadReport { bytes_read: 8, error: None });
    assert_eq!(&output, b"new data");
    assert_eq!(image.calls, 20);
    let current = find(84, &mut |pa, bytes| image.read(pa, bytes));
    assert_eq!(current, ProcessObservation { pid: 84, ..observed });
}

#[test]
fn reusing_pid_object_and_root_does_not_make_an_old_observation_a_handle() {
    let mut image = Image::new();
    let observed = find(42, &mut |pa, bytes| image.read(pa, bytes));
    // Reuse every numerical address and the PID while replacing the identity and mapping.
    image.word(CREATE_TIME, 200);
    image.word(0x7040, 0xb001);
    let current = find(42, &mut |pa, bytes| image.read(pa, bytes));
    assert_eq!(observed.create_time, Some(100));
    assert_eq!(current, ProcessObservation { create_time: Some(200), ..observed });

    let mut output = [0xcd; 8];
    let report = read::read_virtual(
        config(),
        observed.kernel_root_pa,
        0x8000,
        &mut output,
        &mut |pa, bytes| image.read(pa, bytes),
    );
    assert_eq!(report, ReadReport { bytes_read: 8, error: None });
    assert_eq!(&output, b"new data");
    assert_eq!(image.calls, 35);
}

#[test]
fn successful_cross_page_read_can_combine_bytes_from_different_generations() {
    let mut image = Image::new();
    image.bytes[0xaffc..0xb004].copy_from_slice(b"OLD!OLD!");
    let observed = find(42, &mut |pa, bytes| image.read(pa, bytes));
    let mut output = [0xcd; 8];
    let mut changed = false;
    let report = read::read_virtual(
        config(),
        observed.kernel_root_pa,
        0x8ffc,
        &mut output,
        &mut |pa, bytes| {
            image.read(pa, bytes)?;
            if pa == 0xaffc && !changed {
                // Change the first fragment before the second: OLD!NEW! never exists in source.
                image.bytes[0xaffc..0xb000].copy_from_slice(b"NEW!");
                image.bytes[0xb000..0xb004].copy_from_slice(b"NEW!");
                changed = true;
            }
            Ok(())
        },
    );
    assert!(changed);
    assert_eq!(report, ReadReport { bytes_read: 8, error: None });
    assert_eq!(&output, b"OLD!NEW!");
    assert_eq!(&image.bytes[0xaffc..0xb004], b"NEW!NEW!");
    assert_eq!(image.calls, 25);
}
