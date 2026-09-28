//! Bounded observations with explicit unreadable spans. Captures never retry or page memory in.
//! Each readable span is an identity-checked observation, not part of an atomic snapshot.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use svmvisor_hypervisor::memory::address::{PAGE_BYTES, is_canonical_48};

use crate::{Error, ErrorKind, ProcessHandle, Result, Svm};

/// Hard allocation and work ceilings, even when a caller supplies larger limits.
pub const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CAPTURE_SPANS: usize = 16_384;
pub const MAX_CAPTURE_TIMEOUT: Duration = Duration::from_secs(300);

/// The requested ranges, successful bytes, missing spans, and provenance of one capture.
#[derive(Clone, Debug)]
pub struct CaptureObservation {
    pub pid: u32,
    /// Kernel process creation time, in 100 ns units since 1601, as bound by this handle.
    pub created: u64,
    pub started_unix_ms: u64,
    pub elapsed: Duration,
    /// Logical reader requests issued during this capture, including unreadable requests.
    pub calls: u64,
    /// Actual VMMCALL count, or `None` when the transport cannot measure it.
    pub hypercalls: Option<u64>,
    pub regions: Vec<CaptureRegion>,
    pub spans: Vec<CaptureSpan>,
}

/// One requested range. Separate regions remain separate observations, even if they overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureRegion {
    pub address: u64,
    pub length: usize,
}

/// Work bounds checked for the complete request before allocation or reader calls.
#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub max_bytes: usize,
    pub max_spans: usize,
    pub timeout: Duration,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self { max_bytes: 16 * 1024 * 1024, max_spans: 8192, timeout: Duration::from_secs(30) }
    }
}

/// One page-bounded observation. An unreadable span has no fabricated byte contents.
#[derive(Clone, Debug)]
pub struct CaptureSpan {
    pub region: usize,
    pub offset: usize,
    pub address: u64,
    pub length: usize,
    /// Time from capture start to this request, measured by the monotonic clock.
    pub started: Duration,
    pub elapsed: Duration,
    pub data: CaptureData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureData {
    Bytes {
        bytes: Vec<u8>,
        sha256: [u8; 32],
    },
    /// The runtime refused this range. It does not distinguish absent and paged-out memory.
    Unreadable,
}

struct SvmCapture<'a> {
    svm: &'a mut Svm,
    handle: ProcessHandle,
}

impl CaptureSource for SvmCapture<'_> {
    fn identity(&mut self) -> Result<(u32, u64)> {
        Ok((self.handle.pid(), self.svm.process_created(self.handle)?))
    }

    fn counters(&self) -> (u64, Option<u64>) {
        (self.svm.calls(), self.svm.hypercalls())
    }

    fn read(&mut self, address: u64, bytes: &mut [u8], timeout: Duration) -> Result<()> {
        self.svm.read_process_memory_bounded(self.handle, address, bytes, timeout)
    }
}

trait CaptureSource {
    fn identity(&mut self) -> Result<(u32, u64)>;
    fn counters(&self) -> (u64, Option<u64>);
    fn read(&mut self, address: u64, bytes: &mut [u8], timeout: Duration) -> Result<()>;
}

/// Copies each requested range once, splitting at page boundaries and preserving read holes.
/// Only `Unreadable` becomes a missing span. Any other error discards the entire observation;
/// process identity changes therefore never publish a capture assembled from different processes.
/// Existing strict read methods keep their all-or-nothing contract.
pub fn read(
    svm: &mut Svm,
    handle: ProcessHandle,
    regions: &[CaptureRegion],
    limits: CaptureLimits,
) -> Result<CaptureObservation> {
    read_from(&mut SvmCapture { svm, handle }, regions, limits, Instant::now)
}

fn read_from(
    source: &mut impl CaptureSource,
    regions: &[CaptureRegion],
    limits: CaptureLimits,
    mut now: impl FnMut() -> Instant,
) -> Result<CaptureObservation> {
    let span_count = validate(regions, limits)?;
    let started = now();
    let deadline = started.checked_add(limits.timeout).ok_or_else(limit_reached)?;
    let started_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| invalid("system clock is outside the capture timestamp range"))?;
    let (pid, created) = source.identity()?;
    let (calls, hypercalls) = source.counters();
    let mut spans = Vec::with_capacity(span_count);

    for (region, range) in regions.iter().enumerate() {
        let mut offset = 0;
        while offset < range.length {
            let read_started = now();
            let remaining = deadline
                .checked_duration_since(read_started)
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(limit_reached)?;
            let address = range.address + offset as u64;
            let length = (range.length - offset).min(PAGE_BYTES - address as usize % PAGE_BYTES);
            let mut bytes = vec![0; length];
            let result = source.read(address, &mut bytes, remaining);
            let completed = now();
            let data = match result {
                Ok(()) => {
                    let sha256 = Sha256::digest(&bytes).into();
                    CaptureData::Bytes { bytes, sha256 }
                }
                Err(error) if error.kind() == ErrorKind::Unreadable => CaptureData::Unreadable,
                Err(error) => return Err(error),
            };
            if completed >= deadline {
                return Err(limit_reached());
            }
            spans.push(CaptureSpan {
                region,
                offset,
                address,
                length,
                started: read_started.duration_since(started),
                elapsed: completed.duration_since(read_started),
                data,
            });
            offset += length;
        }
    }
    let completed = now();
    if completed >= deadline {
        return Err(limit_reached());
    }
    let (last_calls, last_hypercalls) = source.counters();
    Ok(CaptureObservation {
        pid,
        created,
        started_unix_ms,
        elapsed: completed.duration_since(started),
        calls: last_calls.saturating_sub(calls),
        hypercalls: hypercalls.zip(last_hypercalls).map(|(first, last)| last.saturating_sub(first)),
        regions: regions.to_vec(),
        spans,
    })
}

fn validate(regions: &[CaptureRegion], limits: CaptureLimits) -> Result<usize> {
    if limits.max_bytes == 0
        || limits.max_bytes > MAX_CAPTURE_BYTES
        || limits.max_spans == 0
        || limits.max_spans > MAX_CAPTURE_SPANS
        || limits.timeout.is_zero()
        || limits.timeout > MAX_CAPTURE_TIMEOUT
    {
        return Err(invalid("capture limits exceed the supported byte, span, or time bounds"));
    }
    if regions.is_empty() || regions.len() > limits.max_spans {
        return Err(invalid("capture needs at least one region and at most max_spans regions"));
    }
    let mut total = 0usize;
    let mut spans = 0usize;
    for range in regions {
        let last = range.length.checked_sub(1).and_then(|length| {
            u64::try_from(length).ok().and_then(|length| range.address.checked_add(length))
        });
        if !is_canonical_48(range.address)
            || last
                .is_none_or(|last| !is_canonical_48(last) || (range.address >> 47) != (last >> 47))
        {
            return Err(invalid("capture regions must be nonempty, canonical, nonwrapping ranges"));
        }
        total = total
            .checked_add(range.length)
            .filter(|&total| total <= limits.max_bytes)
            .ok_or_else(|| invalid("capture exceeds max_bytes"))?;
        let pages = (range.length + range.address as usize % PAGE_BYTES).div_ceil(PAGE_BYTES);
        spans = spans
            .checked_add(pages)
            .filter(|&spans| spans <= limits.max_spans)
            .ok_or_else(|| invalid("capture exceeds max_spans"))?;
    }
    Ok(spans)
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidArgument, message)
}

fn limit_reached() -> Error {
    Error::new(ErrorKind::LimitReached, "capture deadline reached; no observation published")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Source {
        reads: Vec<(u64, usize, Duration)>,
        failure: Option<(u64, ErrorKind)>,
        identities: usize,
    }

    impl CaptureSource for Source {
        fn identity(&mut self) -> Result<(u32, u64)> {
            self.identities += 1;
            Ok((42, 1234))
        }

        fn counters(&self) -> (u64, Option<u64>) {
            (self.reads.len() as u64, Some(self.reads.len() as u64 * 3))
        }

        fn read(&mut self, address: u64, bytes: &mut [u8], timeout: Duration) -> Result<()> {
            self.reads.push((address, bytes.len(), timeout));
            if let Some((failed, kind)) = self.failure {
                if failed == address {
                    bytes.fill(0xff);
                    return Err(Error::new(kind, "injected read failure"));
                }
            }
            bytes.fill(0);
            Ok(())
        }
    }

    #[test]
    fn page_boundary_holes_preserve_offsets_and_distinguish_missing_from_zero() {
        let mut source =
            Source { failure: Some((0x2000, ErrorKind::Unreadable)), ..Source::default() };
        let ranges = [CaptureRegion { address: 0x1ffe, length: 4100 }];
        let result =
            read_from(&mut source, &ranges, CaptureLimits::default(), Instant::now).unwrap();
        assert_eq!(
            source.reads.iter().map(|&(va, length, _)| (va, length)).collect::<Vec<_>>(),
            [(0x1ffe, 2), (0x2000, 4096), (0x3000, 2)]
        );
        assert_eq!(result.spans.iter().map(|span| span.offset).collect::<Vec<_>>(), [0, 2, 4098]);
        assert_eq!(result.spans[1].data, CaptureData::Unreadable);
        let expected: [u8; 32] = Sha256::digest([0, 0]).into();
        assert_eq!(
            result.spans[2].data,
            CaptureData::Bytes { bytes: vec![0, 0], sha256: expected }
        );
        assert_eq!(
            (result.pid, result.created, result.calls, result.hypercalls),
            (42, 1234, 3, Some(9))
        );
    }

    #[test]
    fn fatal_failure_discards_the_capture_and_stops_before_the_next_page() {
        for kind in [ErrorKind::ProcessGone, ErrorKind::SessionEnded, ErrorKind::InvalidHandle] {
            let mut source = Source { failure: Some((0x2000, kind)), ..Source::default() };
            let ranges = [CaptureRegion { address: 0x1000, length: 3 * PAGE_BYTES }];
            let error = read_from(&mut source, &ranges, CaptureLimits::default(), Instant::now)
                .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(source.reads.len(), 2);
        }
    }

    #[test]
    fn invalid_or_excessive_ranges_do_no_reader_work() {
        let limits = CaptureLimits { max_bytes: 16, max_spans: 2, ..CaptureLimits::default() };
        for ranges in [
            vec![],
            vec![CaptureRegion { address: 0x1000, length: 0 }],
            vec![CaptureRegion { address: u64::MAX, length: 2 }],
            vec![CaptureRegion { address: 0x7fff_ffff_ffff, length: 2 }],
            vec![CaptureRegion { address: 0x1000, length: 17 }],
            vec![CaptureRegion { address: 0x1fff, length: 2 }; 2],
        ] {
            let mut source = Source::default();
            assert_eq!(
                read_from(&mut source, &ranges, limits, Instant::now).unwrap_err().kind(),
                ErrorKind::InvalidArgument
            );
            assert!(source.reads.is_empty());
            assert_eq!(source.identities, 0);
        }
    }

    #[test]
    fn deadline_stops_work_and_passes_only_remaining_time_to_reads() {
        let mut source = Source::default();
        let ranges = [CaptureRegion { address: 0x1000, length: 3 * PAGE_BYTES }];
        let limits =
            CaptureLimits { timeout: Duration::from_millis(4), ..CaptureLimits::default() };
        let start = Instant::now();
        let mut ticks = 0;
        let error = read_from(&mut source, &ranges, limits, || {
            let now = start + Duration::from_millis(ticks);
            ticks += 1;
            now
        })
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitReached);
        assert_eq!(source.reads.len(), 2);
        assert_eq!(source.reads[0].2, Duration::from_millis(3));
        assert_eq!(source.reads[1].2, Duration::from_millis(1));
    }

    #[test]
    fn hard_limits_are_checked_even_for_a_small_request() {
        let ranges = [CaptureRegion { address: 0x1000, length: 1 }];
        for limits in [
            CaptureLimits { max_bytes: MAX_CAPTURE_BYTES + 1, ..CaptureLimits::default() },
            CaptureLimits { max_spans: MAX_CAPTURE_SPANS + 1, ..CaptureLimits::default() },
            CaptureLimits { timeout: Duration::ZERO, ..CaptureLimits::default() },
            CaptureLimits {
                timeout: MAX_CAPTURE_TIMEOUT + Duration::from_secs(1),
                ..CaptureLimits::default()
            },
        ] {
            let mut source = Source::default();
            assert!(read_from(&mut source, &ranges, limits, Instant::now).is_err());
            assert!(source.reads.is_empty());
            assert_eq!(source.identities, 0);
        }
    }
}
