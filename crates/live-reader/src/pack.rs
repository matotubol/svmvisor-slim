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

/// Checks every `(address, length)` read, then packs them in order. Empty reads need no request.
pub(crate) fn plan(reads: &[(u64, usize)]) -> Result<Vec<Vec<Piece>>, String> {
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
    let mut current: Vec<Piece> = Vec::new();
    let mut total = 0;
    for (read, &(address, length)) in reads.iter().enumerate() {
        let mut offset = 0;
        while offset < length {
            if current.len() == MAX_RANGES || total == MAX_DATA_BYTES {
                requests.push(std::mem::take(&mut current));
                total = 0;
            }
            let count = (length - offset).min(MAX_DATA_BYTES - total);
            current.push(Piece {
                read,
                offset,
                range: BatchRange { address: address + offset as u64, length: count as u32 },
            });
            total += count;
            offset += count;
        }
    }
    if !current.is_empty() {
        requests.push(current);
    }
    Ok(requests)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(requests: &[Vec<Piece>]) -> Vec<Vec<(usize, usize, u64, u32)>> {
        requests
            .iter()
            .map(|request| {
                request
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
        assert_eq!(requests.iter().map(Vec::len).collect::<Vec<_>>(), [8, 2]);
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
            let bytes: u32 = request.iter().map(|piece| piece.range.length).sum();
            assert!(bytes as usize <= MAX_DATA_BYTES && request.len() <= MAX_RANGES);
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
}
