//! Split reads of any count and length into resident requests of at most eight ranges and
//! 4096 bytes. Each request is one identity-checked observation.

use svmvisor_card_abi::batch::{BatchRange, MAX_DATA_BYTES, MAX_RANGES};
use svmvisor_hypervisor::memory::address::is_canonical_48;

/// Bytes `range` of a request belong at `offset` in read number `read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Piece {
    pub read: usize,
    pub offset: usize,
    pub range: BatchRange,
}

/// Wire ranges and the caller buffers receiving their bytes, in the same byte order.
#[derive(Debug, Default)]
pub(crate) struct Request {
    pub ranges: Vec<BatchRange>,
    pub pieces: Vec<Piece>,
}

/// Checks every read, then packs them in order. Exactly adjacent reads share a wire range;
/// gaps, overlaps and duplicates retain separate observations. Empty reads need no request.
pub(crate) fn plan(reads: &[(u64, usize)]) -> Result<Vec<Request>, String> {
    for &(address, length) in reads {
        if length != 0
            && (!is_canonical_48(address)
                || address.checked_add(length as u64 - 1).is_none_or(|last| !is_canonical_48(last)))
        {
            return Err(format!(
                "read of {length} bytes at {address:#x} is not a canonical, nonwrapping range"
            ));
        }
    }
    let mut requests = Vec::new();
    let mut current = Request::default();
    let mut total = 0;
    for (read, &(address, length)) in reads.iter().enumerate() {
        let mut offset = 0;
        while offset < length {
            let address = address + offset as u64;
            let adjacent = current.ranges.last().is_some_and(|range| {
                range.address.checked_add(u64::from(range.length)) == Some(address)
            });
            if (!adjacent && current.ranges.len() == MAX_RANGES) || total == MAX_DATA_BYTES {
                requests.push(std::mem::take(&mut current));
                total = 0;
            }
            let count = (length - offset).min(MAX_DATA_BYTES - total);
            let range = BatchRange { address, length: count as u32 };
            if adjacent && !current.ranges.is_empty() {
                current.ranges.last_mut().unwrap().length += range.length;
            } else {
                current.ranges.push(range);
            }
            current.pieces.push(Piece { read, offset, range });
            total += count;
            offset += count;
        }
    }
    if !current.ranges.is_empty() {
        requests.push(current);
    }
    Ok(requests)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(requests: &[Request]) -> Vec<Vec<(usize, usize, u64, u32)>> {
        requests
            .iter()
            .map(|request| {
                request
                    .pieces
                    .iter()
                    .map(|piece| {
                        (piece.read, piece.offset, piece.range.address, piece.range.length)
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn small_reads_share_requests_of_at_most_eight_ranges() {
        let reads: Vec<_> = (0..10).map(|index| (0x1000 + index * 0x100, 8)).collect();
        let requests = plan(&reads).unwrap();
        assert_eq!(requests.iter().map(|request| request.ranges.len()).collect::<Vec<_>>(), [8, 2]);
        assert_eq!(shape(&requests)[1], [(8, 0, 0x1800, 8), (9, 0, 0x1900, 8)]);
    }

    #[test]
    fn long_reads_split_at_the_request_byte_limit_and_keep_their_offsets() {
        let requests = plan(&[(0x1000, 100), (0x9000, 10_000), (0x20000, 4)]).unwrap();
        assert_eq!(
            shape(&requests),
            [
                vec![(0, 0, 0x1000, 100), (1, 0, 0x9000, 3996)],
                vec![(1, 3996, 0x9000 + 3996, 4096)],
                vec![(1, 8092, 0x9000 + 8092, 1908), (2, 0, 0x20000, 4)],
            ]
        );
        for request in &requests {
            let bytes: u32 = request.ranges.iter().map(|range| range.length).sum();
            assert!(bytes as usize <= MAX_DATA_BYTES && request.ranges.len() <= MAX_RANGES);
        }
    }

    #[test]
    fn empty_reads_need_no_request_and_bad_ranges_send_nothing() {
        assert!(plan(&[]).unwrap().is_empty());
        assert!(plan(&[(0, 0), (u64::MAX, 0)]).unwrap().is_empty());
        for read in [(0x7fff_ffff_fff0, 0x20), (u64::MAX, 2), (0x8000_0000_0000, 1)] {
            assert!(plan(&[(0x1000, 8), read]).is_err(), "{read:x?}");
        }
    }

    #[test]
    fn adjacent_reads_share_one_range_and_preserve_every_output_piece() {
        let reads: Vec<_> = (0..32).map(|index| (0x1000 + index * 8, 8)).collect();
        let requests = plan(&reads).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].ranges, [BatchRange { address: 0x1000, length: 256 }]);
        assert_eq!(requests[0].pieces.len(), 32);
        for (index, piece) in requests[0].pieces.iter().enumerate() {
            assert_eq!(piece.read, index);
            assert_eq!(piece.offset, 0);
            assert_eq!(piece.range, BatchRange { address: 0x1000 + index as u64 * 8, length: 8 });
        }
    }

    #[test]
    fn adjacency_can_extend_the_eighth_range_but_never_the_byte_limit() {
        let mut reads: Vec<_> = (0..8).map(|index| (0x1000 + index * 0x1000, 8)).collect();
        reads.push((0x8008, 4096));
        let requests = plan(&reads).unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].ranges.len(), 8);
        assert_eq!(requests[0].ranges[7], BatchRange { address: 0x8000, length: 4040 });
        assert_eq!(requests[1].ranges, [BatchRange { address: 0x8fc8, length: 64 }]);
        assert_eq!(requests[1].pieces[0].read, 8);
        assert_eq!(requests[1].pieces[0].offset, 4032);
    }

    #[test]
    fn gaps_overlaps_duplicates_and_input_order_are_preserved() {
        let reads = [(0x1000, 8), (0x1010, 8), (0x1014, 8), (0x1014, 8), (0x1008, 8)];
        let requests = plan(&reads).unwrap();
        assert_eq!(requests.len(), 1);
        let ranges: Vec<_> = reads
            .iter()
            .map(|&(address, length)| BatchRange { address, length: length as u32 })
            .collect();
        assert_eq!(requests[0].ranges, ranges);
    }
}
