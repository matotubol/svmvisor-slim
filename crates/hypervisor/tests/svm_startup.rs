use svmvisor_hypervisor::{
    arch::x86_64::{apic::init_notification_icr, registers::GuestRegisters},
    svm::{
        startup::{
            NativeDestinationMode, NativeIcr, NativeStartupCommand as Command,
            NativeStartupEffect as Effect, NativeStartupMailbox as Mailbox,
            NativeStartupState as State, NativeStartupTarget,
            guest_started_all_application_processors, try_lock_routes,
        },
        vmcb::Vmcb,
    },
};

fn ready(mailboxes: &[Mailbox]) {
    let routes = try_lock_routes(mailboxes).unwrap();
    for slot in 0..mailboxes.len() {
        routes
            .prepare_destination_mode(slot, NativeDestinationMode::X2Apic)
            .unwrap()
            .commit_destination_mode();
        mailboxes[slot].mark_running();
    }
}

#[test]
fn broadcast_startup_preserves_fifo_and_refuses_partial_publication() {
    let mailboxes = [Mailbox::new(0), Mailbox::new(1), Mailbox::new(2)];
    ready(&mailboxes);
    let mut source = NativeIcr::admit(0, &[0, 1, 2]).unwrap();
    for vector in 1..=4 {
        mailboxes[2].publish(Command::Sipi(vector)).unwrap();
    }
    let mut kicked = false;
    assert!(source.route_startup_write(0xc4500, &mailboxes, |_| kicked = true).is_err());
    assert!(!kicked);
    assert_eq!(mailboxes[1].peek(), None);
    for vector in 1..=4 {
        mailboxes[2].complete(Command::Sipi(vector)).unwrap();
    }
    source.route_startup_write(0xc4500, &mailboxes, |_| kicked = true).unwrap();
    source.route_startup_write(0xc0608, &mailboxes, |_| {}).unwrap();
    assert!(kicked);
    assert_eq!(mailboxes[0].peek(), None);
    for target in &mailboxes[1..] {
        assert_eq!(target.peek(), Some(Command::Init));
        target.complete(Command::Init).unwrap();
        assert_eq!(target.peek(), Some(Command::Sipi(8)));
    }
}

#[test]
fn native_cpu_startup_never_enables_interrupt_virtualization() {
    let mut vmcb = Vmcb::new();
    vmcb.configure_native_boot_intercepts().unwrap();
    let mut frame = GuestRegisters::default();
    let mut state = State::Running;
    let mut target = NativeStartupTarget {
        vmcb: &mut vmcb,
        frame: &mut frame,
        state: &mut state,
        signature: 0xb40f40,
    };
    assert_eq!(target.apply(Command::Sipi(8)), Ok(Effect::Ignored));
    assert_eq!(target.apply(Command::Init), Ok(Effect::Init));
    assert_eq!(*target.state, State::AwaitSipi);
    assert_eq!(target.frame.rdx, 0xb40f40);
    assert_eq!(target.vmcb.virtual_interrupt_control(), 0);
    assert_eq!(target.apply(Command::Sipi(8)), Ok(Effect::Started));
    assert_eq!(*target.state, State::Running);
    assert_eq!(target.vmcb.guest_rip(), 0);
    assert_eq!(target.vmcb.virtual_interrupt_control(), 0);
}

#[test]
fn guest_startup_completes_only_when_every_application_processor_is_started() {
    let mailboxes = [Mailbox::new(0), Mailbox::new(1), Mailbox::new(2)];
    ready(&mailboxes);
    // Firmware-parked readiness is not a guest start.
    assert!(!guest_started_all_application_processors(&mailboxes));
    mailboxes[1].mark_started();
    assert!(!guest_started_all_application_processors(&mailboxes));
    mailboxes[2].mark_started();
    // The bootstrap processor (slot 0) is never started by a guest SIPI.
    assert!(guest_started_all_application_processors(&mailboxes));
    // A repeated SIPI is idempotent.
    mailboxes[2].mark_started();
    assert!(guest_started_all_application_processors(&mailboxes));
}

#[test]
fn a_single_cpu_never_completes_guest_startup() {
    let mailboxes = [Mailbox::new(0)];
    assert!(!guest_started_all_application_processors(&mailboxes));
    assert!(!guest_started_all_application_processors(&[]));
}

#[test]
fn startup_notification_retains_selected_physical_destination_and_published_queue() {
    // Firmware ordinals, physical IDs and logical destination bits differ.
    let ids = [0x102, 0, 0x25, 0x27, 0x8abc_0f07];
    for (guest_icr, expected_wake, selected, command) in [
        (0x0000_0000_0000_0500, 0x0000_0000_0000_0500, 0b00010, Command::Init),
        (0x8abc_0f07_0000_0622, 0x8abc_0f07_0000_0500, 0b10000, Command::Sipi(0x22)),
        // Logical cluster 2, bit 5 selects physical ID 25h only.
        (0x0002_0020_0000_0d00, 0x0000_0025_0000_0500, 0b00100, Command::Init),
        // Logical cluster 2, bits 5 and 7 retain a broadcast private wake.
        (0x0002_00a0_0000_0e30, 0x0000_0000_000c_0500, 0b01100, Command::Sipi(0x30)),
        (0x0000_0000_000c_4500, 0x0000_0000_000c_0500, 0b11110, Command::Init),
        (0x0000_0000_000c_0640, 0x0000_0000_000c_0500, 0b11110, Command::Sipi(0x40)),
    ] {
        let mailboxes = ids.map(Mailbox::new);
        ready(&mailboxes);
        let mut source = NativeIcr::admit(ids[0], &ids).unwrap();
        let mut wake = None;
        source
            .route_startup_write(guest_icr, &mailboxes, |destination| {
                // This is the encoder used by the native notification writer.
                wake = Some(init_notification_icr(destination));
                // Notification must follow complete publication and release its lock.
                let _routes = try_lock_routes(&mailboxes).unwrap();
                for (slot, mailbox) in mailboxes.iter().enumerate() {
                    assert_eq!(mailbox.peek(), (selected & (1 << slot) != 0).then_some(command));
                }
            })
            .unwrap();
        assert_eq!(wake, Some(expected_wake), "guest ICR {guest_icr:#x}");
    }
}

#[test]
fn startup_refusals_and_deassert_do_not_emit_a_notification() {
    let ids = [0x25, 0x102];
    for guest_icr in [
        0x0000_0025_0000_0500, // Physical self.
        0x0002_0020_0000_0d00, // Logical self.
        0x0000_0000_0004_0500, // Self shorthand.
        0x0000_0000_0008_0500, // All including self shorthand.
        0xffff_ffff_0000_0500, // Physical all including self.
    ] {
        let mailboxes = ids.map(Mailbox::new);
        ready(&mailboxes);
        let mut source = NativeIcr::admit(ids[0], &ids).unwrap();
        assert!(
            source
                .route_startup_write(guest_icr, &mailboxes, |_| panic!("unexpected wake"))
                .is_err()
        );
        assert!(mailboxes.iter().all(|mailbox| mailbox.peek().is_none()));
    }
    let mailboxes = ids.map(Mailbox::new);
    ready(&mailboxes);
    let mut source = NativeIcr::admit(ids[0], &ids).unwrap();
    source
        .route_startup_write(0x0000_0102_0000_8500, &mailboxes, |_| panic!("deassert wake"))
        .unwrap();
    assert!(mailboxes.iter().all(|mailbox| mailbox.peek().is_none()));
    // Cache and terminal rendezvous retain their exact existing broadcast.
    assert_eq!(init_notification_icr(u32::MAX), 0x000c_0500);
}
