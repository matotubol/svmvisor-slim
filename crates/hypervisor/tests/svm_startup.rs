use svmvisor_hypervisor::{
    arch::x86_64::registers::GuestRegisters,
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
