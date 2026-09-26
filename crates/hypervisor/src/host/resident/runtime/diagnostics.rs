//! Private first-fault retention and optional boot diagnostic aliases.
//!
//! Runtime fault details stay in the monitor's retained memory. The resident
//! does not publish progress or register state. After the collective terminal
//! barrier, its sole winner may publish a closed, coarse reason enum using the
//! revalidated boot endpoint. This is best-effort output, never a guest service.

use core::{
    arch::{asm, x86_64::__cpuid_count},
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};

use svmvisor_card_abi::{
    endpoint::{self as card_endpoint, PCI_CLASS_REVISION, PCI_VENDOR_DEVICE, TerminalEndpoint},
    journal::{self, JournalIo},
    stop_status::{self, StopReason},
};

use crate::{
    arch::x86_64::msr::{MMIO_CFG_BASE_ADDR, PAT, TARGET_SIGNATURE},
    host::resident::{
        runtime::{
            ASSIGNED_APIC_ID, PHYSICAL_BITS, POOL, State, TABLES, guest_reader::native_mtrrs,
            image_base, msr::read_msr, startup::mailboxes, stop::terminal_control,
        },
        terminal,
    },
    svm::startup::try_lock_routes,
};

const CONFIG_ALIAS: u64 = 0xfb000;
const BAR_ALIAS: u64 = 0xfc000;

static READY: AtomicU32 = AtomicU32::new(0);
static SEQUENCE: AtomicU32 = AtomicU32::new(0);
static PUBLIC_STOP_ATTEMPTED: AtomicU32 = AtomicU32::new(0);
static FIRST_FAULT: terminal::DeferredFault = terminal::DeferredFault::new();
static mut ENDPOINT: TerminalEndpoint = TerminalEndpoint {
    config_page: 0,
    bar0_host_page: 0,
    fpga_build_id: 0,
    rom_build_id: 0,
    mmio_config_msr: 0,
    bar0_raw: 0,
    segment_bdf: 0,
    boot_id: 0,
    command: 0,
    version: 0,
    reserved: 0,
};

/// Before guest entry, current firmware root and exclusively owned host tables.
/// The caller has installed target config interception in every resident NPT.
pub(super) unsafe fn prepare(endpoint: TerminalEndpoint, slot: usize, count: usize) -> bool {
    let (pool, bytes) = unsafe { POOL };
    if slot >= count || count > 32 || !endpoint.valid() {
        return false;
    }
    let pat = unsafe { read_msr(PAT) };
    let Some(uc) = (0..8).find(|i| (pat >> (i * 8)) & 255 == 0) else {
        return false;
    };
    let Some(mtrrs) = (unsafe { native_mtrrs(__cpuid_count(0x80000008, 0).eax as u8) }) else {
        return false;
    };
    for page in [endpoint.config_page, endpoint.bar0_host_page] {
        if (page < pool + bytes && pool < page + 4096) || !mtrrs.terminal_page_is_uc(page, 0) {
            return false;
        }
    }
    let flags = 3 | (1u64 << 63) | ((uc & 1) << 3) | ((uc & 2) << 3) | ((uc & 4) << 5);
    let base = image_base();
    unsafe {
        for (offset, page) in
            [(CONFIG_ALIAS, endpoint.config_page), (BAR_ALIAS, endpoint.bar0_host_page)]
        {
            let entry = ptr::addr_of_mut!(
                (*ptr::addr_of_mut!(TABLES)).0[3][(((base + offset) >> 12) & 511) as usize]
            );
            if entry.read() != 0 {
                return false;
            }
            entry.write(page | flags);
        }
        ENDPOINT = endpoint;
    }
    READY.store(1, Ordering::Release);
    true
}

/// No STATE, guest-memory or device access: also callable from the private fault
/// IST. Capturing the first fault is bounded and does not wait on an interrupted
/// writer. Ordinary progress events have no output or retained payload.
pub(super) unsafe fn record(event: u8, fault: bool, context: [u64; 6], aux: u32) {
    if !available() || !fault {
        return;
    }
    let mut seq = SEQUENCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if seq == 0 {
        seq = SEQUENCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    }
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc",out("eax")lo,out("edx")hi,options(nostack,preserves_flags));
    }
    FIRST_FAULT.capture(journal::diagnostic_payload(
        seq,
        event,
        true,
        unsafe { ENDPOINT.boot_id },
        unsafe { ASSIGNED_APIC_ID },
        lo as u64 | ((hi as u64) << 32),
        context,
        aux,
    ));
}

pub(super) fn available() -> bool {
    READY.load(Ordering::Acquire) == 1
}

/// Classify private evidence without allowing an arbitrary payload to escape.
/// Unknown/internal reasons intentionally collapse to Other.
fn public_reason(code: u64, reason: u64) -> StopReason {
    match (code, reason) {
        (_, 0xf206) => StopReason::ConfigurationRoute,
        (_, 0xf20a) => StopReason::SmiConfigurationTrap,
        (_, 0xf200..=0xf209) => StopReason::ConfigurationAccess,
        (0x400, _) => StopReason::MemoryPolicy,
        (0x7c, _) => StopReason::ArchitecturalControl,
        _ => StopReason::Other,
    }
}

struct StopJournal(u64);

impl JournalIo for StopJournal {
    type Error = ();

    fn read(&mut self, offset: u64) -> Result<u32, ()> {
        if offset > 0x9c || offset & 3 != 0 {
            return Err(());
        }
        Ok(unsafe { ((self.0 + offset) as *const u32).read_volatile() })
    }

    fn write(&mut self, offset: u64, value: u32) -> Result<(), ()> {
        if !(0x40..=0x60).contains(&offset) || offset & 3 != 0 {
            return Err(());
        }
        unsafe { ((self.0 + offset) as *mut u32).write_volatile(value) };
        Ok(())
    }
}

/// Sole terminal winner, after every admitted CPU has acknowledged its
/// irreversible GIF=0 stop. Parking is NOT DMA drain or ownership evidence.
/// No call from a resumable path or the asynchronous host-fault IST is allowed.
/// Firmware/SMM and unchanged external fabric routing remain prerequisites.
pub(super) unsafe fn publish_stop(state: &State) -> bool {
    if !available() || !state.stopped_valid || __cpuid_count(1, 0).eax != TARGET_SIGNATURE {
        return false;
    }
    let control = unsafe { terminal_control() };
    if !control.all_acknowledged(state.count)
        || control.diagnostic_snapshot()[2] != state.slot as u64 + 1
        || control.diagnostic_revoked()
        || control.configuration_pending()
    {
        return false;
    }
    // One nonblocking attempt. An interrupted route/configuration writer must
    // suppress output, never be waited on or bypassed by the stopped winner.
    let Ok(_route_guard) = try_lock_routes(unsafe { mailboxes(state.count) }) else {
        return false;
    };
    let Some(_diagnostic_guard) = control.diagnostic_lock() else {
        return false;
    };
    if PUBLIC_STOP_ATTEMPTED.swap(1, Ordering::AcqRel) != 0 {
        return false;
    }
    let endpoint = unsafe { ptr::addr_of!(ENDPOINT).read() };
    let Some(route) = state.configuration else { return false };
    if !endpoint.valid()
        || unsafe { read_msr(MMIO_CFG_BASE_ADDR) } != endpoint.mmio_config_msr
        || route.verify(endpoint.mmio_config_msr).is_err()
    {
        return false;
    }
    let Some(mtrrs) = (unsafe { native_mtrrs(PHYSICAL_BITS) }) else { return false };
    if !mtrrs.terminal_page_is_uc(endpoint.config_page, 0)
        || !mtrrs.terminal_page_is_uc(endpoint.bar0_host_page, 0)
    {
        return false;
    }
    // PPR57896 physical pp40-41,210 (text and PNG): UC aligned EAX MOVs.
    let base = image_base();
    let cfg = |offset| unsafe { card_endpoint::read_config_dword(base + CONFIG_ALIAS, offset) };
    if cfg(0) != PCI_VENDOR_DEVICE
        || cfg(8) != PCI_CLASS_REVISION
        || ((cfg(0x0c) >> 16) & 0xff) != 0
        || cfg(4) as u16 != endpoint.command
        || cfg(0x10) != endpoint.bar0_raw
    {
        return false;
    }
    let mut io = StopJournal(base + BAR_ALIAS);
    commit_public_stop(&mut io, endpoint, public_reason(state.stopped, state.stopped_info1))
}

/// Device validation and publication share one caller-held lifetime. This seam
/// is pure with a fake journal; it accepts no private context or arbitrary words.
fn commit_public_stop<I: JournalIo<Error = ()>>(
    io: &mut I,
    endpoint: TerminalEndpoint,
    reason: StopReason,
) -> bool {
    let read64 = |io: &mut I, offset| -> Option<u64> {
        Some(u64::from(io.read(offset).ok()?) | (u64::from(io.read(offset + 4).ok()?) << 32))
    };
    if io.read(0) != Ok(0x4a4d5653)
        || io.read(4) != Ok(0x00030001)
        || read64(io, 8) != Some(endpoint.fpga_build_id)
        || read64(io, 16) != Some(endpoint.rom_build_id)
        || io.read(0x24) != Ok(0)
        || io.read(0x84) != Ok(endpoint.boot_id)
    {
        return false;
    }
    let Ok(previous) = io.read(0x2c) else { return false };
    let Some(sequence) = previous.checked_add(1).filter(|v| *v != 0) else { return false };
    journal::commit_record(io, stop_status::record(sequence, endpoint.boot_id, reason)).is_ok()
}

#[cfg(test)]
mod public_tests {
    use super::*;

    #[test]
    fn operands_and_addresses_cannot_become_public_reasons() {
        for private in [0, 1, 0xdead_beef, 0xffff_8000_1234_5000, u64::MAX] {
            assert_eq!(public_reason(0x400, private), StopReason::MemoryPolicy);
            assert_eq!(public_reason(0x7c, private), StopReason::ArchitecturalControl);
            assert_eq!(public_reason(private, private), StopReason::Other);
        }
        assert_eq!(public_reason(0x7b, 0xf207), StopReason::ConfigurationAccess);
        assert_eq!(public_reason(0x7c, 0xf206), StopReason::ConfigurationRoute);
        assert_eq!(public_reason(0x7b, 0xf20a), StopReason::SmiConfigurationTrap);
    }

    struct Journal {
        words: [u32; 40],
        writes: usize,
        committed: [u32; 8],
        fail_at: Option<u64>,
    }

    impl JournalIo for Journal {
        type Error = ();
        fn read(&mut self, offset: u64) -> Result<u32, ()> {
            if self.fail_at == Some(offset) {
                return Err(());
            }
            Ok(self.words[offset as usize / 4])
        }
        fn write(&mut self, offset: u64, value: u32) -> Result<(), ()> {
            self.writes += 1;
            self.words[offset as usize / 4] = value;
            if offset == 0x60 {
                self.committed.copy_from_slice(&self.words[16..24]);
                self.words[32..40].copy_from_slice(&self.committed);
                self.words[0x2c / 4] = value;
            }
            Ok(())
        }
    }

    fn fixture() -> (TerminalEndpoint, Journal) {
        let endpoint = TerminalEndpoint {
            fpga_build_id: 0x1234_5678_9876_5432,
            rom_build_id: 0x5432_9876_1234_5678,
            boot_id: 31,
            ..TerminalEndpoint::default()
        };
        let mut journal = Journal { words: [0; 40], writes: 0, committed: [0; 8], fail_at: None };
        journal.words[0] = 0x4a4d5653;
        journal.words[1] = 0x00030001;
        journal.words[2] = endpoint.fpga_build_id as u32;
        journal.words[3] = (endpoint.fpga_build_id >> 32) as u32;
        journal.words[4] = endpoint.rom_build_id as u32;
        journal.words[5] = (endpoint.rom_build_id >> 32) as u32;
        journal.words[0x84 / 4] = endpoint.boot_id;
        journal.words[0x2c / 4] = 7;
        (endpoint, journal)
    }

    #[test]
    fn stale_endpoint_or_boot_never_writes_and_success_is_redacted() {
        for offset in [0, 4, 8, 12, 16, 20, 0x24, 0x84] {
            let (endpoint, mut io) = fixture();
            io.words[offset / 4] ^= 1;
            assert!(!commit_public_stop(&mut io, endpoint, StopReason::MemoryPolicy));
            assert_eq!(io.writes, 0);
        }
        for offset in [0, 4, 8, 12, 16, 20, 0x24, 0x84, 0x2c] {
            let (endpoint, mut io) = fixture();
            io.fail_at = Some(offset);
            assert!(!commit_public_stop(&mut io, endpoint, StopReason::MemoryPolicy));
            assert_eq!(io.writes, 0);
        }
        let (endpoint, mut io) = fixture();
        io.words[0x2c / 4] = u32::MAX;
        assert!(!commit_public_stop(&mut io, endpoint, StopReason::MemoryPolicy));
        assert_eq!(io.writes, 0);
        let (endpoint, mut io) = fixture();
        assert!(commit_public_stop(&mut io, endpoint, StopReason::MemoryPolicy));
        assert_eq!(io.committed, [8, 31, 0, 0, 0x501, 0, 0, 0x0008_0015]);
        assert_eq!(io.writes, 9);
    }
}
