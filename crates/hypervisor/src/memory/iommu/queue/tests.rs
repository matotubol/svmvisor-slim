use super::*;
use crate::memory::address::EncryptionState;
use crate::memory::iommu::commands::CompletionOrdering;

const BASE: u64 = 0x12_3000;
const COMPLETION: u64 = BASE + 0x4000;

fn policy() -> AddressPolicy {
    AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn protected() -> PhysicalRange {
    policy().validate(BASE, 0x8000, 4096).unwrap()
}

fn prepare<'a>(
    pages: &'a mut [CommandPage],
    completion: &'a mut CompletionPage,
) -> CommandBuffer<'a> {
    CommandBuffer::prepare(policy(), protected(), BASE, pages, COMPLETION, completion).unwrap()
}

fn wait(cell: usize, value: u64) -> HostCommand {
    wait_at(COMPLETION + cell as u64 * 8, value)
}

fn wait_at(address: u64, value: u64) -> HostCommand {
    HostCommand::completion_wait(policy(), address, value, CompletionOrdering::WaitBeforeSubsequent)
        .unwrap()
}

fn dirty_pages<const N: usize>() -> [CommandPage; N] {
    core::array::from_fn(|index| CommandPage { bytes: [0xa0 | index as u8; PAGE_BYTES] })
}

fn dirty_completion() -> CompletionPage {
    CompletionPage { values: [0xa1a2_a3a4_a5a6_a7a8; COMPLETION_CELLS] }
}

fn unchanged_preparation(
    address_policy: AddressPolicy,
    extent: PhysicalRange,
    command_base: u64,
    completion_base: u64,
    error: QueueError,
) {
    let mut pages = dirty_pages::<2>();
    let mut completion = dirty_completion();
    let before_pages = pages.clone();
    let before_completion = completion.clone();
    assert_eq!(
        CommandBuffer::prepare(
            address_policy,
            extent,
            command_base,
            &mut pages,
            completion_base,
            &mut completion,
        )
        .err(),
        Some(error)
    );
    assert_eq!(pages, before_pages);
    assert_eq!(completion, before_completion);
}

fn unchanged_enqueue(queue: &mut CommandBuffer<'_>, commands: &[HostCommand], error: QueueError) {
    // Independent snapshots include every byte and every piece of mutable
    // producer state, including completion metadata hidden from public callers.
    let mut before_pages = dirty_pages::<2>();
    let count = queue.pages.len();
    assert!(count <= before_pages.len());
    before_pages[..count].clone_from_slice(queue.pages);
    let before_completion = queue.completion.clone();
    let before_expected = queue.expected;
    let before_head = queue.head_offset;
    let before_tail = queue.tail_offset;
    let before_value = queue.last_completion_value;
    assert_eq!(queue.enqueue(commands), Err(error));
    assert_eq!(queue.pages, &before_pages[..count]);
    assert_eq!(*queue.completion, before_completion);
    assert_eq!(queue.expected, before_expected);
    assert_eq!(queue.head_offset, before_head);
    assert_eq!(queue.tail_offset, before_tail);
    assert_eq!(queue.last_completion_value, before_value);
}

#[test]
fn storage_layout_and_entire_initial_memory_are_explicit() {
    assert_eq!(core::mem::size_of::<CommandPage>(), 4096);
    assert_eq!(core::mem::align_of::<CommandPage>(), 4096);
    assert_eq!(core::mem::size_of::<CompletionPage>(), 4096);
    assert_eq!(core::mem::align_of::<CompletionPage>(), 4096);
    let mut pages = dirty_pages::<2>();
    let mut completion = dirty_completion();
    let queue = prepare(&mut pages, &mut completion);
    assert_eq!(queue.geometry().backing().base(), BASE);
    assert_eq!(queue.geometry().backing().len(), 8192);
    assert_eq!(queue.completion_backing().base(), COMPLETION);
    assert_eq!(queue.completion_backing().len(), 4096);
    assert!(queue.pages().iter().all(|page| page.bytes().iter().all(|byte| *byte == 0)));
    assert!(queue.completion_page().values().iter().all(|value| *value == 0));
    assert_eq!((queue.head_offset(), queue.tail_offset(), queue.available_entries()), (0, 0, 511));
}

#[test]
fn geometry_matches_manual_base_register_and_pointer_units_for_all_sizes() {
    // Independent p215 encodings, not calculated from the implementation mask.
    for (pages, entries, register) in [
        (1, 256, 0x0800_0000_0012_3000),
        (2, 512, 0x0900_0000_0012_3000),
        (4, 1024, 0x0a00_0000_0012_3000),
        (8, 2048, 0x0b00_0000_0012_3000),
        (16, 4096, 0x0c00_0000_0012_3000),
        (32, 8192, 0x0d00_0000_0012_3000),
        (64, 16384, 0x0e00_0000_0012_3000),
        (128, 32768, 0x0f00_0000_0012_3000),
    ] {
        let geometry = CommandRingGeometry::new(policy(), BASE, pages).unwrap();
        assert_eq!(geometry.entry_count(), entries);
        assert_eq!(geometry.usable_entries(), entries - 1);
        assert_eq!(geometry.base_register_value(), register);
        assert_eq!(geometry.validate_offset(0), Ok(0));
        assert_eq!(
            geometry.validate_offset((entries as u64 - 1) * 16),
            Ok((entries as u32 - 1) * 16)
        );
        assert_eq!(geometry.byte_len(), (entries * 16) as u32);
    }
}

#[test]
fn only_supported_power_of_two_command_lengths_are_accepted() {
    for pages in [0, 3, 5, 127, 129, 256, usize::MAX] {
        assert_eq!(
            CommandRingGeometry::new(policy(), BASE, pages),
            Err(QueueError::InvalidCommandPageCount(pages))
        );
    }
    let mut pages = dirty_pages::<3>();
    let before = pages.clone();
    let mut completion = dirty_completion();
    let before_completion = completion.clone();
    assert_eq!(
        CommandBuffer::prepare(
            policy(),
            protected(),
            BASE,
            &mut pages,
            COMPLETION,
            &mut completion
        )
        .err(),
        Some(QueueError::InvalidCommandPageCount(3))
    );
    assert_eq!(pages, before);
    assert_eq!(completion, before_completion);
}

#[test]
fn geometry_checks_all_backing_bytes_for_width_alignment_overflow_and_encryption() {
    let narrow =
        AddressPolicy::new(32, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
    for (base, count, error) in [
        (BASE + 1, 1, AddressError::Misaligned),
        (0xffff_f000, 2, AddressError::OutsidePhysicalWidth),
        (0x1_0000_0000, 1, AddressError::OutsidePhysicalWidth),
        (u64::MAX - 4095, 2, AddressError::Overflow),
    ] {
        assert_eq!(
            CommandRingGeometry::new(narrow, base, count),
            Err(QueueError::Address { backing: Backing::Commands, error })
        );
    }
    let no_bit =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(13) }).unwrap();
    assert_eq!(
        CommandRingGeometry::new(no_bit, 0, 8),
        Err(QueueError::Address {
            backing: Backing::Commands,
            error: AddressError::EncryptionBitEncoded
        })
    );
    assert!(CommandRingGeometry::new(narrow, 0xffff_f000, 1).is_ok());
}

#[test]
fn preparation_revalidates_protected_extent_and_preserves_dirty_memory_on_error() {
    let narrow =
        AddressPolicy::new(32, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
    unchanged_preparation(
        narrow,
        policy().validate(0, 0x1_0000_1000, 4096).unwrap(),
        BASE,
        COMPLETION,
        QueueError::Address {
            backing: Backing::ProtectedExtent,
            error: AddressError::OutsidePhysicalWidth,
        },
    );
    unchanged_preparation(
        policy(),
        policy().validate(BASE, 0x7fff, 1).unwrap(),
        BASE,
        COMPLETION,
        QueueError::ProtectedLengthNotPageAligned,
    );
    unchanged_preparation(
        policy(),
        policy().validate(BASE + 1, 0x8000, 1).unwrap(),
        BASE,
        COMPLETION,
        QueueError::Address { backing: Backing::ProtectedExtent, error: AddressError::Misaligned },
    );
    unchanged_preparation(
        policy(),
        protected(),
        BASE,
        COMPLETION + 8,
        QueueError::Address { backing: Backing::Completion, error: AddressError::Misaligned },
    );
}

#[test]
fn both_entire_storage_spans_must_be_confined_and_numerically_disjoint() {
    unchanged_preparation(
        policy(),
        protected(),
        BASE - 4096,
        COMPLETION,
        QueueError::OutsideProtectedExtent(Backing::Commands),
    );
    unchanged_preparation(
        policy(),
        protected(),
        BASE + 0x7000,
        COMPLETION,
        QueueError::OutsideProtectedExtent(Backing::Commands),
    );
    unchanged_preparation(
        policy(),
        protected(),
        BASE,
        BASE + 0x8000,
        QueueError::OutsideProtectedExtent(Backing::Completion),
    );
    // Distinct Rust objects with overlapping numeric assignments still conflict.
    unchanged_preparation(policy(), protected(), BASE, BASE + 4096, QueueError::OverlappingBacking);
}

#[test]
fn raw_pointer_reserved_bits_and_out_of_range_offsets_are_never_masked() {
    let geometry = CommandRingGeometry::new(policy(), BASE, 1).unwrap();
    for bit in (0..4).chain(19..64) {
        let raw = 16 | (1u64 << bit);
        assert_eq!(geometry.validate_offset(raw), Err(QueueError::InvalidPointerBits(raw)));
    }
    for raw in [4096, 8192, 0x7fff0] {
        assert_eq!(geometry.validate_offset(raw), Err(QueueError::PointerOutsideRing(raw)));
    }
    assert_eq!(geometry.validate_offset(16), Ok(16));
}

#[test]
fn serialized_bytes_match_independent_command_literals() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    let batch = queue
        .enqueue(&[
            HostCommand::invalidate_device_entry(0x1234),
            HostCommand::invalidate_domain(0xabcd),
            wait(511, 0x0807_0605_0403_0201),
        ])
        .unwrap();
    assert_eq!(batch, PreparedBatch { start_offset: 0, tail_offset: 48, command_count: 3 });
    assert_eq!(
        &queue.pages()[0].bytes()[..48],
        &[
            0x34, 0x12, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcd, 0xab, 0,
            0x30, 3, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xfd, 0x7f, 0x12, 0, 0, 0, 0, 0x10,
            1, 2, 3, 4, 5, 6, 7, 8,
        ]
    );
    assert!(queue.pages()[0].bytes()[48..].iter().all(|byte| *byte == 0));
    assert!(queue.completion_page().values().iter().all(|value| *value == 0));
}

#[test]
fn full_ring_retains_one_empty_slot_and_failed_enqueue_changes_nothing() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    let command = HostCommand::invalidate_device_entry(7);
    let batch = queue.enqueue(&[command; 255]).unwrap();
    assert_eq!(batch.tail_offset, 4080);
    assert_eq!(queue.available_entries(), 0);
    assert!(queue.pages()[0].bytes()[4080..].iter().all(|byte| *byte == 0));
    unchanged_enqueue(
        &mut queue,
        &[command],
        QueueError::InsufficientCapacity { requested: 1, available: 0 },
    );
    assert_eq!(queue.observe_head(16).unwrap().fetched_commands, 1);
    assert_eq!(queue.enqueue(&[command]).unwrap().tail_offset, 0);
    assert_eq!(queue.available_entries(), 0);
    unchanged_enqueue(
        &mut queue,
        &[command],
        QueueError::InsufficientCapacity { requested: 1, available: 0 },
    );
}

#[test]
fn wrap_emission_preserves_unfetched_commands_and_reuses_only_available_slots() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    queue.enqueue(&[HostCommand::invalidate_device_entry(1); 250]).unwrap();
    queue.observe_head(160).unwrap();
    let before = queue.pages()[0].clone();
    let commands: [HostCommand; 10] =
        core::array::from_fn(|index| HostCommand::invalidate_device_entry(100 + index as u16));
    assert_eq!(queue.enqueue(&commands).unwrap().tail_offset, 64);
    // Slots 4..249 include both old consumed slots and all unfetched commands.
    assert_eq!(&queue.pages()[0].bytes()[64..4000], &before.bytes()[64..4000]);
    for (index, expected_id) in [(250, 100u16), (255, 105), (0, 106), (3, 109)] {
        let bytes = &queue.pages()[0].bytes()[index * 16..index * 16 + 16];
        assert_eq!(u16::from_le_bytes(bytes[..2].try_into().unwrap()), expected_id);
        assert_eq!(bytes[7], 0x20);
    }
    assert_eq!(queue.available_entries(), 5);
    assert_eq!(queue.observe_head(64).unwrap().fetched_commands, 250);
    assert_eq!(queue.available_entries(), 255);
}

#[test]
fn emission_crosses_page_boundary_with_byte_offsets_not_word_indices() {
    let mut pages = dirty_pages::<2>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    queue.enqueue(&[HostCommand::invalidate_device_entry(0x4321); 257]).unwrap();
    assert_eq!(queue.tail_offset(), 4112);
    assert_eq!(&queue.pages()[0].bytes()[4080..4096], &queue.pages()[1].bytes()[..16]);
    assert_eq!(&queue.pages()[1].bytes()[..8], &[0x21, 0x43, 0, 0, 0, 0, 0, 0x20]);
    assert!(queue.pages()[1].bytes()[16..].iter().all(|byte| *byte == 0));
}

#[test]
fn invalid_regressing_or_beyond_tail_heads_leave_everything_unchanged() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    queue.enqueue(&[HostCommand::invalidate_device_entry(1); 10]).unwrap();
    queue.observe_head(80).unwrap();
    let before = queue.pages()[0].clone();
    for raw in [0, 64, 176, 4080] {
        assert_eq!(
            queue.observe_head(raw),
            Err(QueueError::HeadBeyondPreparedTail {
                previous: 80,
                observed: raw as u32,
                prepared_tail: 160
            })
        );
        assert_eq!(queue.head_offset(), 80);
        assert_eq!(queue.tail_offset(), 160);
        assert_eq!(queue.pages()[0], before);
    }
    for raw in [1, 1 << 19, u64::MAX] {
        assert_eq!(queue.observe_head(raw), Err(QueueError::InvalidPointerBits(raw)));
        assert_eq!(queue.head_offset(), 80);
    }
    assert_eq!(queue.observe_head(4096), Err(QueueError::PointerOutsideRing(4096)));
    assert_eq!(queue.observe_head(160).unwrap().fetched_commands, 5);
    assert_eq!(queue.observe_head(160).unwrap().fetched_commands, 0);
}

#[test]
fn empty_and_oversized_batches_do_not_mutate_storage_or_state() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    unchanged_enqueue(&mut queue, &[], QueueError::EmptyBatch);
    unchanged_enqueue(
        &mut queue,
        &[HostCommand::invalidate_domain(9); 256],
        QueueError::InsufficientCapacity { requested: 256, available: 255 },
    );
}

#[test]
fn late_completion_failure_is_transactional_including_prior_valid_commands() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    let commands = [HostCommand::invalidate_domain(1), wait(0, 12), wait_at(BASE, 13)];
    unchanged_enqueue(
        &mut queue,
        &commands,
        QueueError::CompletionOutsideBacking { index: 2, store_address: BASE },
    );
    // The successful prefix's marker and cell were not spent by failed preflight.
    queue.enqueue(&[wait(0, 12)]).unwrap();
    assert_eq!(queue.compare_completion(0, 12).unwrap().expected_value, 12);
}

#[test]
fn completions_are_confined_to_the_entire_separate_borrowed_page() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    // Even otherwise protected command/unused/event-like pages are forbidden.
    for address in [0, BASE, BASE + 0x2000, COMPLETION - 8, COMPLETION + 4096, (1u64 << 52) - 8] {
        unchanged_enqueue(
            &mut queue,
            &[wait_at(address, 1)],
            QueueError::CompletionOutsideBacking { index: 0, store_address: address },
        );
    }
    queue.enqueue(&[wait(0, 1), wait(511, 2)]).unwrap();
    assert_eq!(queue.completion_cell_address(0), Ok(COMPLETION));
    assert_eq!(queue.completion_cell_address(511), Ok(COMPLETION + 4088));
    assert_eq!(queue.completion_cell_address(512), Err(QueueError::InvalidCompletionCell(512)));
    assert_eq!(
        queue.completion_cell_address(usize::MAX),
        Err(QueueError::InvalidCompletionCell(usize::MAX))
    );
}

#[test]
fn a_command_built_under_a_wider_policy_is_revalidated_before_emission() {
    let narrow =
        AddressPolicy::new(32, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue =
        CommandBuffer::prepare(narrow, protected(), BASE, &mut pages, COMPLETION, &mut completion)
            .unwrap();
    unchanged_enqueue(
        &mut queue,
        &[wait_at(1 << 40, 1)],
        QueueError::Command {
            index: 0,
            error: CommandError::StoreAddress(AddressError::OutsidePhysicalWidth),
        },
    );
}

#[test]
fn zero_repeated_and_decreasing_markers_are_rejected_across_cells_and_batches() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    unchanged_enqueue(
        &mut queue,
        &[wait(0, 0)],
        QueueError::CompletionValueNotIncreasing { index: 0, previous: 0, requested: 0 },
    );
    queue.enqueue(&[wait(0, 10)]).unwrap();
    for value in [0, 1, 9, 10] {
        unchanged_enqueue(
            &mut queue,
            &[wait(1, value)],
            QueueError::CompletionValueNotIncreasing { index: 0, previous: 10, requested: value },
        );
    }
    unchanged_enqueue(
        &mut queue,
        &[wait(1, 12), wait(2, 12)],
        QueueError::CompletionValueNotIncreasing { index: 1, previous: 12, requested: 12 },
    );
    unchanged_enqueue(
        &mut queue,
        &[wait(1, 12), wait(2, 11)],
        QueueError::CompletionValueNotIncreasing { index: 1, previous: 12, requested: 11 },
    );
    queue.enqueue(&[wait(1, 11), wait(2, 12)]).unwrap();
}

#[test]
fn the_same_completion_cell_cannot_be_retargeted_within_a_batch() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    unchanged_enqueue(
        &mut queue,
        &[wait(7, 1), wait(7, 2)],
        QueueError::CompletionCellAlreadyUsed { index: 1, cell: 7 },
    );
    queue.enqueue(&[wait(7, 1)]).unwrap();
}

#[test]
fn head_progress_and_equal_numeric_sample_never_release_a_completion_cell() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    queue.enqueue(&[HostCommand::invalidate_domain(9), wait(5, 41)]).unwrap();
    assert_eq!(queue.observe_head(32).unwrap().fetched_commands, 2);
    assert_eq!(queue.available_entries(), 255);
    assert!(!queue.compare_completion(5, 0).unwrap().equal());
    assert!(!queue.compare_completion(5, 40).unwrap().equal());
    assert!(queue.compare_completion(5, 41).unwrap().equal());
    // Comparison does not manufacture an actual store into the borrowed page.
    assert_eq!(queue.completion_page().values()[5], 0);
    unchanged_enqueue(
        &mut queue,
        &[wait(5, 42)],
        QueueError::CompletionCellAlreadyUsed { index: 0, cell: 5 },
    );
    queue.enqueue(&[wait(6, 42)]).unwrap();
    assert!(!queue.compare_completion(6, 41).unwrap().equal());
}

#[test]
fn sequence_exhaustion_refuses_wrap_and_does_not_block_plain_invalidations() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    queue.enqueue(&[wait(0, u64::MAX)]).unwrap();
    for value in [0, 1, u64::MAX] {
        unchanged_enqueue(
            &mut queue,
            &[wait(1, value)],
            QueueError::CompletionValueNotIncreasing {
                index: 0,
                previous: u64::MAX,
                requested: value,
            },
        );
    }
    queue.enqueue(&[HostCommand::invalidate_device_entry(7)]).unwrap();
}

#[test]
fn every_completion_cell_can_be_used_once_across_many_ring_wraps() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    for cell in 0..512 {
        queue.enqueue(&[wait(cell, cell as u64 + 1)]).unwrap();
        queue.observe_head(u64::from(queue.tail_offset())).unwrap();
    }
    assert_eq!((queue.head_offset(), queue.tail_offset()), (0, 0));
    for cell in 0..512 {
        assert!(queue.compare_completion(cell, cell as u64 + 1).unwrap().equal());
    }
    unchanged_enqueue(
        &mut queue,
        &[wait(511, 513)],
        QueueError::CompletionCellAlreadyUsed { index: 0, cell: 511 },
    );
}

#[test]
fn comparison_refuses_unissued_cells_and_does_not_alter_any_state() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    assert_eq!(queue.compare_completion(0, 1), Err(QueueError::UnusedCompletionCell(0)));
    assert_eq!(queue.compare_completion(512, 1), Err(QueueError::InvalidCompletionCell(512)));
    queue.enqueue(&[wait(3, 50)]).unwrap();
    let before = queue.expected;
    for sample in [0, 49, 50, 51, u64::MAX] {
        let comparison = queue.compare_completion(3, sample).unwrap();
        assert_eq!(
            comparison,
            CompletionComparison {
                address: COMPLETION + 24,
                expected_value: 50,
                observed_value: sample
            }
        );
    }
    assert_eq!(queue.expected, before);
    assert_eq!(queue.last_completion_value, 50);
    assert_eq!(queue.tail_offset(), 16);
    assert_eq!(queue.head_offset(), 0);
}

#[test]
fn a_value_already_present_in_the_completion_cell_cannot_be_emitted() {
    let mut pages = dirty_pages::<1>();
    let mut completion = dirty_completion();
    let mut queue = prepare(&mut pages, &mut completion);
    // Inject an offline stale memory condition directly within this unit test.
    // Production callers receive no mutable completion-page accessor.
    queue.completion.values[17] = 99;
    unchanged_enqueue(
        &mut queue,
        &[HostCommand::invalidate_domain(3), wait(17, 99)],
        QueueError::CompletionValueAlreadyPresent { index: 1, cell: 17 },
    );
}
