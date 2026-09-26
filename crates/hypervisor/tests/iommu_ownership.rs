mod ownership_support;
use ownership_support::*;
use svmvisor_hypervisor::{
    firmware::native::resident::iommu::{
        binding::{UnitAssignment, UnitIdentity, bind},
        ownership::{
            AdmissionError, BackendError, BankStorage, CoverageKind, FailureReason, Fence,
            LifecycleEvent, Limits, NativeBlocker, Phase, Plan, PublicationKey, Register, Step,
            Transaction, native_blockers, prepare_banks, require_native_admission,
        },
    },
    host::resident::IOMMU_RESOURCE_BYTES,
};

#[test]
fn complete_two_unit_takeover_orders_global_barriers_and_exact_commands() {
    let fixture = Fixture::new(2);
    let mut backend = fixture.backend();
    let shared = backend.shared.clone();
    let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 9, 0, limits()).unwrap();
    assert_eq!(finish(&mut tx), Step::Complete);
    assert_eq!(tx.phase(), Phase::OwnedQuiesced);
    assert_eq!(tx.retention().new_roots_may_be_published, 3);
    for index in 0..2 {
        assert!(!tx.receipt(index).unwrap().is_mapping_publication());
    }
    let state = shared.borrow();
    let effects = &state.effects;
    let first_write =
        effects.iter().position(|e| matches!(e, Effect::Command(..) | Effect::Write(..))).unwrap();
    for unit in 0..2 {
        assert!(effects[..first_write].contains(&Effect::Quiescence(unit)));
        assert!(effects[..first_write].contains(&Effect::Verify(unit)));
    }
    let first_stop = effects
        .iter()
        .position(
            |e| matches!(e, Effect::Write(_, Register::Control, value) if value & (1 << 12) == 0),
        )
        .unwrap();
    for unit in 0..2 {
        assert!(effects[..first_stop].contains(&Effect::Fence(unit, Fence::AcquireCompletion)));
    }
    let first_install = effects
        .iter()
        .position(|e| matches!(e, Effect::Write(_, Register::DeviceTable, _)))
        .unwrap();
    for unit in 0..2 {
        assert!(effects[..first_install].iter().any(|e| matches!(e, Effect::Write(i, Register::Control, value) if *i == unit && value & (1 << 12) == 0)));
    }
    let commands: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let Effect::Command(unit, address, words) = e {
                Some((*unit, *address, *words))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(commands.len(), 8);
    for pair in commands.chunks_exact(2) {
        assert_eq!(pair[0].2, [8 << 60, 0]);
        assert_eq!(pair[1].2[0] >> 60, 1);
        assert_eq!(pair[1].2[0] & 7, 5, "s=1, f=1, i=0");
        assert!((1..=2).contains(&pair[1].2[1]));
    }
    assert!(
        effects
            .iter()
            .all(|e| !matches!(e, Effect::Write(_, Register::Control, value) if value & 1 == 0)),
        "translation is never disabled"
    );
}

#[test]
fn head_fetch_cannot_complete_or_replace_the_old_owner() {
    let fixture = Fixture::new(2);
    let mut backend = fixture.backend();
    let shared = backend.shared.clone();
    shared.borrow_mut().fetch_only = true;
    let mut tx = Transaction::new(
        &mut backend,
        fixture.plan.clone(),
        1,
        0,
        Limits { max_steps: 70, timeout_ticks: 100 },
    )
    .unwrap();
    assert!(
        matches!(finish(&mut tx), Step::Failed(f) if f.reason == FailureReason::Timeout && f.phase == Phase::AwaitOldDrain)
    );
    assert_eq!(tx.retention().old_queues_may_reference_completion, 3);
    assert_eq!(tx.retention().new_roots_may_be_published, 0);
    assert!(
        shared
            .borrow()
            .effects
            .iter()
            .all(|e| !matches!(e, Effect::Write(_, Register::DeviceTable | Register::Control, _)))
    );
    assert!(tx.receipt(0).is_none());
}

#[test]
fn every_backend_failure_is_terminal_without_rollback_or_release() {
    let fixture = Fixture::new(2);
    let mut successful = fixture.backend();
    let log = successful.shared.clone();
    let mut tx = Transaction::new(&mut successful, fixture.plan.clone(), 1, 0, limits()).unwrap();
    assert_eq!(finish(&mut tx), Step::Complete);
    drop(tx);
    let count = log.borrow().effects.len();
    for fail_at in 0..count {
        let mut backend = fixture.backend();
        let shared = backend.shared.clone();
        shared.borrow_mut().fail_at = Some(fail_at);
        let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 1, 0, limits()).unwrap();
        assert!(
            matches!(finish(&mut tx), Step::Failed(f) if f.reason == FailureReason::Backend(BackendError::Device)),
            "effect {fail_at}"
        );
        let retained = tx.retention();
        assert!(retained.controls_may_be_owned);
        assert!(tx.receipt(0).is_none() && tx.receipt(1).is_none());
        let calls = shared.borrow().effects.len();
        for _ in 0..3 {
            assert!(matches!(tx.step(1), Step::Failed(_)));
        }
        drop(tx);
        assert_eq!(shared.borrow().effects.len(), calls, "no cleanup I/O after failure or Drop");
        for effect in &shared.borrow().effects {
            if let Effect::Write(unit, Register::DeviceTable, _) = effect {
                assert_ne!(retained.new_roots_may_be_published & (1 << unit), 0);
            }
        }
    }
}

#[test]
fn stale_completion_and_snapshot_drift_fail_before_submission() {
    let fixture = Fixture::new(1);
    for stale in [true, false] {
        let mut backend = fixture.backend();
        let shared = backend.shared.clone();
        if stale {
            shared
                .borrow_mut()
                .completions
                .insert(fixture.plan.unit(0).unwrap().completion_base, 1);
        } else {
            shared.borrow_mut().registers[0].command_buffer += 0x1000;
        }
        let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 1, 0, limits()).unwrap();
        assert!(
            matches!(finish(&mut tx), Step::Failed(f) if f.reason == if stale { FailureReason::CompletionStale } else { FailureReason::SnapshotDrift })
        );
        assert!(
            shared
                .borrow()
                .effects
                .iter()
                .all(|effect| !matches!(effect, Effect::Command(..) | Effect::Write(..)))
        );
    }
}

#[test]
fn no_quiescence_or_no_stop_ack_expires_without_unsafe_replacement() {
    let fixture = Fixture::new(1);
    for quiescence in [true, false] {
        let mut backend = fixture.backend();
        let shared = backend.shared.clone();
        if quiescence {
            shared.borrow_mut().quiesced = false;
        } else {
            shared.borrow_mut().stop_pending = true;
        }
        let mut tx = Transaction::new(
            &mut backend,
            fixture.plan.clone(),
            1,
            0,
            Limits { max_steps: 50, timeout_ticks: 100 },
        )
        .unwrap();
        assert!(matches!(finish(&mut tx), Step::Failed(f) if f.reason == FailureReason::Timeout));
        assert_eq!(tx.retention().new_roots_may_be_published, 0);
    }
}

#[test]
fn mapping_receipt_requires_matching_drain_and_rejects_replay_other_unit_and_epoch() {
    let fixture = Fixture::new(2);
    let mut backend = fixture.backend();
    let shared = backend.shared.clone();
    let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 17, 0, limits()).unwrap();
    assert_eq!(finish(&mut tx), Step::Complete);
    let key = PublicationKey {
        unit: fixture.plan.unit(1).unwrap().binding.identity.into(),
        epoch: 17,
        generation: 1,
    };
    tx.begin_publication(key, 1).unwrap();
    assert!(tx.mapping_receipt(key).is_none());
    assert_eq!(finish(&mut tx), Step::Complete);
    let receipt = tx.mapping_receipt(key).unwrap();
    assert!(receipt.is_mapping_publication() && receipt.matches(key));
    assert!(!receipt.matches(PublicationKey { epoch: 18, ..key }));
    assert!(!receipt.matches(PublicationKey {
        unit: fixture.plan.unit(0).unwrap().binding.identity.into(),
        ..key
    }));
    assert_eq!(tx.begin_publication(key, 1), Err(FailureReason::PublicationKey));
    let state = shared.borrow();
    let compose = state.effects.iter().position(|effect| *effect == Effect::Compose(key)).unwrap();
    assert!(
        state.effects[compose + 1..]
            .iter()
            .any(|effect| matches!(effect, Effect::Fence(1, Fence::AcquireCompletion)))
    );
    drop(state);
    let second = PublicationKey { generation: 2, ..key };
    tx.begin_publication(second, 1).unwrap();
    shared.borrow_mut().fetch_only = true;
    assert!(matches!(finish(&mut tx), Step::Failed(_)));
    assert!(tx.mapping_receipt(second).is_none());
    assert_eq!(tx.retention().composition_may_be_published, 2);
}

#[test]
fn reset_power_control_or_tracking_loss_never_resume_the_same_owner() {
    let fixture = Fixture::new(1);
    for event in [
        LifecycleEvent::Reset,
        LifecycleEvent::Suspend,
        LifecycleEvent::PowerLoss,
        LifecycleEvent::ControlLost,
        LifecycleEvent::MemoryIntegrityLost,
        LifecycleEvent::GuestTableTrackingLost,
    ] {
        let mut backend = fixture.backend();
        let shared = backend.shared.clone();
        let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 1, 0, limits()).unwrap();
        assert_eq!(finish(&mut tx), Step::Complete);
        let calls = shared.borrow().effects.len();
        let failure = tx.revoke(event);
        assert_eq!(failure.reason, FailureReason::Lifecycle(event));
        assert_eq!(tx.step(2), Step::Failed(failure));
        assert!(tx.receipt(0).is_none());
        assert_eq!(shared.borrow().effects.len(), calls);
    }
}

#[test]
fn resource_admission_checks_whole_memory_control_and_each_generation() {
    let fixture = Fixture::new(2);
    let ram = [range(0x1000_0000, 0x2400_0000)];
    let controls = [range(0xe000_0000, 0x2000_0000)];
    let short_ram = [range(0x1000_0000, IOMMU_RESOURCE_BYTES - 4096)];
    let mut cov = coverage(&ram, &controls);
    cov.dma_denied = &short_ram;
    assert!(matches!(
        Plan::prepare(policy(), &fixture.binding, cov, &fixture.publications),
        Err(AdmissionError::Coverage { kind: CoverageKind::DmaDenied, .. })
    ));
    let short_controls = [range(0xe010_0000, 0x2000)];
    assert!(matches!(
        Plan::prepare(
            policy(),
            &fixture.binding,
            coverage(&ram, &short_controls),
            &fixture.publications
        ),
        Err(AdmissionError::Coverage { kind: CoverageKind::ControlDenied, .. })
    ));
    let mut overlapping = fixture.publications.clone();
    overlapping[1].generations[0] = overlapping[0].generations[1];
    assert!(matches!(
        Plan::prepare(policy(), &fixture.binding, coverage(&ram, &controls), &overlapping),
        Err(AdmissionError::Overlap)
    ));
    overlapping = fixture.publications.clone();
    overlapping[1].generations[0] = range(old_base(0), 0x10000);
    assert!(matches!(
        Plan::prepare(policy(), &fixture.binding, coverage(&ram, &controls), &overlapping),
        Err(AdmissionError::Overlap)
    ));
    overlapping = fixture.publications.clone();
    overlapping[1].required_bytes += 4096;
    assert!(matches!(
        Plan::prepare(policy(), &fixture.binding, coverage(&ram, &controls), &overlapping),
        Err(AdmissionError::PublicationCapacity)
    ));
}

#[test]
fn old_cross_unit_alias_is_refused_even_when_original_binding_only_checked_pool() {
    let mut fixture = Fixture::new(2);
    fixture.report.hardware[1].registers.as_mut().unwrap().command_buffer =
        fixture.report.hardware[0].registers.unwrap().command_buffer;
    let assignments: Vec<_> = fixture
        .banks
        .iter()
        .enumerate()
        .map(|(index, storage)| UnitAssignment {
            identity: UnitIdentity::from_unit(fixture.report.tables.ivrs.units()[index]),
            extent: range(bank_base(index), IOMMU_RESOURCE_BYTES),
            storage,
        })
        .collect();
    let binding = bind(policy(), &fixture.report, pool(), &assignments).unwrap();
    let ram = [range(0x1000_0000, 0x2400_0000)];
    let controls = [range(0xe000_0000, 0x2000_0000)];
    assert!(matches!(
        Plan::prepare(policy(), &binding, coverage(&ram, &controls), &fixture.publications),
        Err(AdmissionError::Overlap)
    ));
}

#[test]
fn multibank_preflight_preserves_every_bank_on_missing_or_duplicate_assignment() {
    let report = report(2);
    let mut first = empty_bank();
    let mut second = empty_bank();
    let mut banks = [
        BankStorage {
            identity: UnitIdentity::from_unit(report.tables.ivrs.units()[0]),
            extent: range(bank_base(0), IOMMU_RESOURCE_BYTES),
            storage: &mut first,
        },
        BankStorage {
            identity: UnitIdentity::from_unit(report.tables.ivrs.units()[0]),
            extent: range(bank_base(1), IOMMU_RESOURCE_BYTES),
            storage: &mut second,
        },
    ];
    assert!(prepare_banks(policy(), &report, pool(), &mut banks).is_err());
    assert!(banks[0].storage.preflight_prepare(policy(), bank_base(0)).is_ok());
    assert!(banks[1].storage.preflight_prepare(policy(), bank_base(1)).is_ok());
    assert!(prepare_banks(policy(), &report, pool(), &mut banks[..1]).is_err());
}

#[test]
fn clock_and_step_limits_are_independent_and_native_facts_remain_unresolved() {
    let fixture = Fixture::new(1);
    let mut backend = fixture.backend();
    let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 1, 0, limits()).unwrap();
    assert_eq!(tx.step(3), Step::Progress);
    assert!(matches!(tx.step(2), Step::Failed(f) if f.reason == FailureReason::ClockRegression));
    assert!(native_blockers().contains(&NativeBlocker::CurrentRequesterRoutingA0A5AndAliasRange));
    assert!(native_blockers().contains(&NativeBlocker::CompleteFabricB8BcControlMap));
    assert!(native_blockers().contains(&NativeBlocker::GuestTableCpuAndDmaWriteTracking));
    assert_eq!(require_native_admission(), Err(native_blockers()));
}

#[test]
fn inactive_image_slot_reuse_requires_preceding_drain_and_fresh_quiescence() {
    let fixture = Fixture::new(1);
    let mut backend = fixture.backend();
    let shared = backend.shared.clone();
    let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 4, 0, limits()).unwrap();
    assert_eq!(finish(&mut tx), Step::Complete);
    let key = PublicationKey {
        unit: fixture.plan.unit(0).unwrap().binding.identity.into(),
        epoch: 4,
        generation: 1,
    };
    for generation in 1..=3 {
        tx.begin_publication(PublicationKey { generation, ..key }, 1).unwrap();
        assert_eq!(finish(&mut tx), Step::Complete);
    }
    {
        let state = shared.borrow();
        assert_eq!(state.slots[0].destination(), state.slots[2].destination());
        assert_ne!(state.slots[0].destination(), state.slots[1].destination());
        assert!(state.slots[0].previous().is_none() && state.slots[0].reuse_after().is_none());
        assert!(state.slots[1].reuse_after().is_none());
        assert_eq!(state.slots[2].previous(), Some(state.slots[1].destination()));
        assert!(
            state.slots[2].reuse_after().unwrap().matches(PublicationKey { generation: 2, ..key })
        );
    }
    tx.begin_publication(PublicationKey { generation: 4, ..key }, 1).unwrap();
    shared.borrow_mut().quiesced = false;
    assert!(
        matches!(finish(&mut tx), Step::Failed(f) if f.phase == Phase::RevalidateMappingQuiescence)
    );
    assert_eq!(shared.borrow().slots.len(), 3, "no slot reuse while source silence is lost");
}

#[test]
fn completion_cells_never_recycle_and_exhaustion_has_no_publication_effect() {
    let fixture = Fixture::new(1);
    let mut backend = fixture.backend();
    let shared = backend.shared.clone();
    let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 4, 0, limits()).unwrap();
    assert_eq!(finish(&mut tx), Step::Complete);
    let key = PublicationKey {
        unit: fixture.plan.unit(0).unwrap().binding.identity.into(),
        epoch: 4,
        generation: 1,
    };
    for generation in 1..=510 {
        tx.begin_publication(PublicationKey { generation, ..key }, 1).unwrap();
        assert_eq!(finish(&mut tx), Step::Complete);
    }
    let effects = shared.borrow().effects.len();
    assert_eq!(
        tx.begin_publication(PublicationKey { generation: 511, ..key }, 1),
        Err(FailureReason::CompletionExhausted)
    );
    assert_eq!(shared.borrow().effects.len(), effects);
    assert_eq!(shared.borrow().completions.len(), 512);
}

#[test]
fn matching_cell_with_lost_control_or_wrong_nonzero_value_cannot_mint_receipt() {
    let fixture = Fixture::new(1);
    for lost_control in [false, true] {
        let mut backend = fixture.backend();
        let shared = backend.shared.clone();
        let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 1, 0, limits()).unwrap();
        advance_to(&mut tx, Phase::AwaitOldDrain);
        if lost_control {
            shared.borrow_mut().epoch_lost = true;
        } else {
            shared
                .borrow_mut()
                .completions
                .insert(fixture.plan.unit(0).unwrap().completion_base, 2);
        }
        assert!(matches!(finish(&mut tx), Step::Failed(_)));
        assert!(tx.receipt(0).is_none());
        assert_eq!(tx.retention().new_roots_may_be_published, 0);
    }
}

#[test]
fn old_queue_wrap_reserves_empty_slot_and_full_queue_times_out_without_store() {
    for full in [false, true] {
        let mut fixture = Fixture::new(1);
        let registers = fixture.report.hardware[0].registers.as_mut().unwrap();
        registers.command_head = if full { 0 } else { 4080 };
        registers.command_tail = 4080;
        fixture.rebind();
        let mut backend = fixture.backend();
        let shared = backend.shared.clone();
        let mut tx = Transaction::new(
            &mut backend,
            fixture.plan.clone(),
            1,
            0,
            Limits { max_steps: 80, timeout_ticks: 100 },
        )
        .unwrap();
        let result = finish(&mut tx);
        if full {
            assert!(
                matches!(result, Step::Failed(f) if f.phase == Phase::PublishOldDrain && f.reason == FailureReason::Timeout)
            );
            assert!(shared.borrow().commands.is_empty());
        } else {
            assert_eq!(result, Step::Complete);
            let state = shared.borrow();
            let old = old_base(0) + 0x200000;
            assert_eq!(state.commands[&(old + 4080)], [8 << 60, 0]);
            assert_eq!(state.commands[&old][0] >> 60, 1);
            assert!(state.effects.contains(&Effect::Write(0, Register::CommandTail, 16)));
        }
    }
}

#[test]
fn new_engine_start_is_polled_and_readonly_control_bits_are_never_written_back() {
    let fixture = Fixture::new(1);
    let mut backend = fixture.backend();
    let shared = backend.shared.clone();
    let ignored = (15 << 18) | (1 << 49) | (1 << 57);
    shared.borrow_mut().readonly_control = ignored;
    shared.borrow_mut().start_pending = true;
    let mut tx = Transaction::new(&mut backend, fixture.plan.clone(), 1, 0, limits()).unwrap();
    advance_to(&mut tx, Phase::AwaitNewStart);
    assert_eq!(tx.step(1), Step::Pending);
    shared.borrow_mut().registers[0].status = (1 << 3) | (1 << 4);
    assert_eq!(finish(&mut tx), Step::Complete);
    assert!(shared.borrow().effects.iter().all(|effect| !matches!(effect, Effect::Write(_, Register::Control, value) if value & ignored != 0)));
}
