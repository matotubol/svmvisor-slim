//! A synthetic process list connects discovery to reads through a distinct process root.
//! One layout is invented; the other uses recorded public-symbol offsets. Both images are synthetic.

use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{self, ProcessLayoutEvidence, ProcessProfile, ProcessRequest},
    read,
};

struct Image {
    bytes: Vec<u8>,
}

impl Image {
    fn new(layout: ProcessLayoutEvidence) -> Self {
        let mut image = Self { bytes: vec![0; 0x16000] };
        // Kernel root: identity-map the synthetic list and object fields with a 1 GiB leaf.
        image.word(0x10000, 0x11001);
        image.word(0x11000, 0x81);
        // A separate process root maps VA 0x4000 to PA 0x7000 through four levels.
        image.word(0x12000, 0x13001);
        image.word(0x13000, 0x14001);
        image.word(0x14000, 0x15001);
        image.word(0x15020, 0x7001);
        let first_link = 0x2000 + layout.active_links_offset as usize;
        let second_link = 0x3000 + layout.active_links_offset as usize;
        image.links(0x1000, first_link as u64, second_link as u64);
        image.links(first_link, second_link as u64, 0x1000);
        image.links(second_link, 0x1000, first_link as u64);
        image.word(0x2000 + layout.pid_offset as usize, 4);
        image.word(0x3000 + layout.pid_offset as usize, 4242);
        image.word(0x3000 + layout.create_time_offset.unwrap() as usize, 0x1234_5678_90ab_cdef);
        image.word(0x3000 + layout.directory_root_offset as usize, 0x12000);
        image.bytes[0x7000..0x700c].copy_from_slice(b"known buffer");
        image
    }

    fn links(&mut self, offset: usize, forward: u64, backward: u64) {
        self.word(offset, forward);
        self.word(offset + 8, backward);
    }

    fn word(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn read(&self, pa: u64, bytes: &mut [u8]) -> Result<(), PagingError> {
        let start = usize::try_from(pa).map_err(|_| PagingError::PhysicalRead)?;
        let end = start.checked_add(bytes.len()).ok_or(PagingError::PhysicalRead)?;
        let source = self.bytes.get(start..end).ok_or(PagingError::PhysicalRead)?;
        bytes.copy_from_slice(source);
        Ok(())
    }
}

fn assert_process_read(layout: ProcessLayoutEvidence) {
    let image = Image::new(layout);
    let source = image.bytes.clone();
    let config = PagingConfig::new(48, true, true).unwrap();
    let profile = ProcessProfile::new(layout).unwrap();
    let request =
        ProcessRequest { kernel_root_pa: 0x10000, list_head_va: 0x1000, pid: 4242, max_nodes: 2 };
    let process =
        process::find(config, profile, request, &mut |pa, bytes: &mut [u8]| image.read(pa, bytes))
            .unwrap()
            .unwrap();
    assert_eq!(process.pid, 4242);
    assert_eq!(process.eprocess_va, 0x3000);
    assert_eq!(process.create_time, Some(0x1234_5678_90ab_cdef));
    assert_eq!(process.kernel_root_pa, 0x12000);
    let mut output = [0xcd; 12];
    let report = read::read_virtual(
        config,
        process.kernel_root_pa,
        0x4000,
        &mut output,
        &mut |pa, bytes: &mut [u8]| image.read(pa, bytes),
    );
    assert_eq!(report.bytes_read, 12);
    assert_eq!(report.error, None);
    assert_eq!(&output, b"known buffer");
    assert_eq!(image.bytes, source);
}

#[test]
fn discovered_process_root_reads_known_buffer_from_a_different_address_space() {
    assert_process_read(ProcessLayoutEvidence {
        eprocess_bytes: 0x100,
        active_links_offset: 0x010,
        pid_offset: 0x028,
        create_time_offset: Some(0x030),
        directory_root_offset: 0x040,
        dtb_low_bits_mask: 0,
    });
}

#[test]
fn symbol_verified_layout_reads_a_synthetic_process_buffer() {
    // profiles/ntoskrnl-26100.9457.json: PE/PDB GUID C29EBFB0-6B78-B3C0-20DC-A66D99713F9E,
    // PE/DBI age 1. EPROCESS type 0x1c75, KPROCESS type 0x1b49. This is not capture validation.
    // The fixture writes aligned roots; mask zero is its policy, not a claim about live DTBs.
    assert_process_read(ProcessLayoutEvidence {
        eprocess_bytes: 0x840,
        active_links_offset: 0x1d8,
        pid_offset: 0x1d0,
        create_time_offset: Some(0x1f8),
        directory_root_offset: 0x028,
        dtb_low_bits_mask: 0,
    });
}
