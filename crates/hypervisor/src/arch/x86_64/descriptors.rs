//! Expanded SVM segment state and shared descriptor table dimensions.
//! AMD APM volume 2 Appendix B defines the expanded VMCB segment fields.

pub(crate) const CODE_SELECTOR: u16 = 8;
pub(crate) const GDT_BYTES: usize = 40;
pub(crate) const TSS_BYTES: usize = 104;

/// Expanded segment representation, not itself an unchecked VMCB input token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentState {
    pub selector: u16,
    pub attributes: u16,
    pub limit: u32,
    pub base: u64,
}
