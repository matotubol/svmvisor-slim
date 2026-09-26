use super::*;
use crate::memory::iommu::{MAX_ACPI_DEVICES, MAX_REQUESTER_SCOPES, MAX_SPECIAL_DEVICES};

/// Each numeric scope contributes at most two actual and two source endpoints;
/// each auxiliary device contributes two. No 65,536-element expansion is used.
pub const MAX_INTERVALS: usize =
    1 + 4 * MAX_REQUESTER_SCOPES + 2 * MAX_SPECIAL_DEVICES + 2 * MAX_ACPI_DEVICES;

#[derive(Clone, Copy, Debug)]
pub struct ResolutionInterval<'a> {
    /// Inclusive interval starting at the exact requested DeviceID.
    pub range: RequesterRange,
    /// Resolution at `range.first`; use source_id() for another member.
    pub first: Resolution<'a>,
}

impl ResolutionInterval<'_> {
    pub fn source_id(&self, requester: u16) -> Option<u16> {
        if !self.range.contains(requester) {
            return None;
        }
        Some(match self.first.source_mapping() {
            SourceMapping::Identity => requester,
            SourceMapping::Alias(source) => source,
        })
    }
}

/// Work performed for a numeric range; no global inventory or ownership claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeSummary {
    pub segment: u16,
    pub range: RequesterRange,
    pub intervals: usize,
}

impl<'a> Resolver<'a> {
    /// Resolve a suffix up to the next relevant endpoint. Splitting at every
    /// actual/source endpoint also catches source settings and identity changes
    /// hidden inside an otherwise uniform broad numeric declaration.
    pub fn resolve_interval(&self, query: Query) -> Result<ResolutionInterval<'a>, ResolveError> {
        let first = self.resolve(query)?;
        let mut end = 0x1_0000u32;
        let mut boundary = |range: RequesterRange| {
            for candidate in [u32::from(range.first), u32::from(range.last) + 1] {
                if candidate > u32::from(query.requester) && candidate < end {
                    end = candidate;
                }
            }
        };
        for scope in self.ivrs.requester_scopes() {
            if self.segment(scope.form_index) == query.segment {
                boundary(scope.range);
                boundary(scope.source_range());
            }
        }
        for device in self.ivrs.special_devices() {
            if self.segment(device.form_index) == query.segment {
                boundary(RequesterRange { first: device.source_id, last: device.source_id });
            }
        }
        for device in self.ivrs.acpi_devices() {
            if self.segment(device.form_index) == query.segment {
                boundary(RequesterRange { first: device.source_id, last: device.source_id });
            }
        }
        Ok(ResolutionInterval {
            range: RequesterRange { first: query.requester, last: (end - 1) as u16 },
            first,
        })
    }

    /// Validate every numeric ID with at most MAX_INTERVALS endpoint queries.
    /// Returns the first failing interval's starting requester with its witness.
    /// No caller storage or inventory is changed, including on late failure.
    pub fn validate_range(
        &self,
        segment: u16,
        range: RequesterRange,
    ) -> Result<RangeSummary, ResolveError> {
        let mut query = Query { segment, requester: range.first };
        if range.first > range.last {
            return Err(failure(query, range.first, ResolveErrorKind::InvalidRange, None, None));
        }
        let mut intervals = 0;
        loop {
            let interval = self.resolve_interval(query)?;
            intervals += 1;
            if interval.range.last >= range.last {
                return Ok(RangeSummary { segment, range, intervals });
            }
            // Last is strictly less than range.last, so this cannot overflow.
            query.requester = interval.range.last + 1;
        }
    }
}
