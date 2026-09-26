//! Independent offline producer checks over allocated, caller-owned storage.
//! No hardware MMIO, DMA, readiness or completion authority is involved.
use std::collections::VecDeque;

use svmvisor_hypervisor::memory::{
    address::{AddressPolicy, EncryptionState},
    iommu::{
        commands::{CompletionOrdering, HostCommand},
        queue::{CommandBuffer, CommandPage, CompletionPage, QueueError},
    },
};

fn policy() -> AddressPolicy {
    AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn read_words(pages: &[CommandPage], slot: usize) -> [u64; 2] {
    let page = slot / 256;
    let offset = (slot % 256) * 16;
    let bytes = &pages[page].bytes()[offset..offset + 16];
    [
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..].try_into().unwrap()),
    ]
}

#[test]
fn producer_matches_an_independent_fifo_through_many_full_and_wrapping_batches() {
    // A VecDeque models entry occupancy independently of the byte-offset
    // arithmetic. Use the smallest and largest supported physical geometries.
    for page_count in [1usize, 2, 128] {
        let mut pages = vec![CommandPage::ZERO; page_count];
        let mut completion = Box::new(CompletionPage::ZERO);
        let command_base = 0x1234_0000;
        let completion_base = command_base + page_count as u64 * 4096;
        let extent = policy().validate(command_base, (page_count as u64 + 1) * 4096, 4096).unwrap();
        let mut queue = CommandBuffer::prepare(
            policy(),
            extent,
            command_base,
            &mut pages,
            completion_base,
            &mut completion,
        )
        .unwrap();
        let capacity = page_count * 256 - 1;
        let initial: Vec<_> =
            (0..capacity).map(|index| HostCommand::invalidate_device_entry(index as u16)).collect();
        queue.enqueue(&initial).unwrap();
        let mut fifo: VecDeque<[u64; 2]> =
            (0..capacity).map(|index| [0x2000_0000_0000_0000 | (index as u16) as u64, 0]).collect();
        let mut head_slot = 0;
        let mut tail_slot = capacity;
        let mut random = 0x0bd6_887d_fe54_9911u64;
        let mut emitted = capacity;
        assert_eq!(
            queue.enqueue(&[HostCommand::invalidate_device_entry(0)]),
            Err(QueueError::InsufficientCapacity { requested: 1, available: 0 }),
        );
        let mut rejected = 1;
        for turn in 0..4096 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            if turn % 3 == 0 && !fifo.is_empty() {
                let consumed = 1 + (random as usize % fifo.len());
                for _ in 0..consumed {
                    assert_eq!(read_words(queue.pages(), head_slot), fifo.pop_front().unwrap());
                    head_slot = (head_slot + 1) % (capacity + 1);
                }
                let progress = queue.observe_head((head_slot * 16) as u64).unwrap();
                assert_eq!(progress.fetched_commands, consumed);
            } else {
                let count = 1 + (random as usize % (capacity.min(1024) + 1));
                let commands: Vec<_> = (0..count)
                    .map(|index| HostCommand::invalidate_device_entry((emitted + index) as u16))
                    .collect();
                let available = capacity - fifo.len();
                let before_tail = queue.tail_offset();
                match queue.enqueue(&commands) {
                    Ok(batch) => {
                        assert!(count <= available);
                        assert_eq!(batch.start_offset as usize, tail_slot * 16);
                        for index in 0..count {
                            let identifier = ((emitted + index) as u16) as u64;
                            // Literal command expectation independent of words().
                            let words = [0x2000_0000_0000_0000 | identifier, 0];
                            assert_eq!(read_words(queue.pages(), tail_slot), words);
                            fifo.push_back(words);
                            tail_slot = (tail_slot + 1) % (capacity + 1);
                        }
                        emitted += count;
                        assert_eq!(batch.tail_offset as usize, tail_slot * 16);
                    }
                    Err(error) => {
                        assert_eq!(
                            error,
                            QueueError::InsufficientCapacity { requested: count, available }
                        );
                        assert_eq!(queue.tail_offset(), before_tail);
                        rejected += 1;
                    }
                }
            }
            assert_eq!(queue.available_entries(), capacity - fifo.len());
            assert_eq!(queue.head_offset() as usize, head_slot * 16);
            assert_eq!(queue.tail_offset() as usize, tail_slot * 16);
            for (index, expected) in fifo.iter().enumerate() {
                assert_eq!(
                    read_words(queue.pages(), (head_slot + index) % (capacity + 1)),
                    *expected
                );
            }
        }
        assert!(emitted > 4 * (capacity + 1), "must exercise multiple wraps");
        assert!(rejected > 0, "must exercise actual full refusals");
    }
}

#[test]
fn public_api_constrains_store_destinations_and_never_recycles_an_observed_cell() {
    let mut pages = vec![CommandPage::ZERO; 1];
    let mut completion = Box::new(CompletionPage::ZERO);
    let extent = policy().validate(0x100000, 0x10000, 4096).unwrap();
    let mut queue =
        CommandBuffer::prepare(policy(), extent, 0x100000, &mut pages, 0x108000, &mut completion)
            .unwrap();
    let wait = |address, value| {
        HostCommand::completion_wait(
            policy(),
            address,
            value,
            CompletionOrdering::WaitBeforeSubsequent,
        )
        .unwrap()
    };
    let cell = queue.completion_cell_address(511).unwrap();
    assert_eq!(cell, 0x108ff8);
    let before = queue.pages()[0].clone();
    assert_eq!(
        queue.enqueue(&[HostCommand::invalidate_domain(1), wait(0x101000, 1)]),
        Err(QueueError::CompletionOutsideBacking { index: 1, store_address: 0x101000 }),
    );
    assert_eq!(queue.pages()[0], before);
    queue.enqueue(&[HostCommand::invalidate_domain(1), wait(cell, 1)]).unwrap();
    assert_eq!(read_words(queue.pages(), 1), [0x1000_0000_0010_8ffd, 1]);
    queue.observe_head(32).unwrap();
    assert!(queue.compare_completion(511, 1).unwrap().equal());
    assert_eq!(queue.completion_page().values()[511], 0);
    assert_eq!(
        queue.enqueue(&[wait(cell, 2)]),
        Err(QueueError::CompletionCellAlreadyUsed { index: 0, cell: 511 })
    );
}
