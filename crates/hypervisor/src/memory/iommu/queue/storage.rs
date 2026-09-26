use crate::memory::address::PAGE_BYTES;

/// One real command-buffer page. Its Rust address is not its assigned physical
/// address. This ordinary storage must remain disconnected from hardware.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C, align(4096))]
pub struct CommandPage {
    pub(super) bytes: [u8; PAGE_BYTES],
}

impl CommandPage {
    pub const ZERO: Self = Self { bytes: [0; PAGE_BYTES] };

    /// Serialized little-endian command bytes, including currently unused slots.
    pub const fn bytes(&self) -> &[u8; PAGE_BYTES] {
        &self.bytes
    }
}

/// One assigned completion page, containing 512 aligned 64-bit store cells.
/// The unused cells are part of the protected backing too. This is ordinary
/// disconnected storage, not a coherent or volatile hardware observation API.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C, align(4096))]
pub struct CompletionPage {
    pub(super) values: [u64; super::COMPLETION_CELLS],
}

impl CompletionPage {
    pub const ZERO: Self = Self { values: [0; super::COMPLETION_CELLS] };

    pub const fn values(&self) -> &[u64; super::COMPLETION_CELLS] {
        &self.values
    }
}

const _: () = {
    assert!(core::mem::size_of::<CommandPage>() == PAGE_BYTES);
    assert!(core::mem::align_of::<CommandPage>() == PAGE_BYTES);
    assert!(core::mem::offset_of!(CommandPage, bytes) == 0);
    assert!(core::mem::size_of::<CompletionPage>() == PAGE_BYTES);
    assert!(core::mem::align_of::<CompletionPage>() == PAGE_BYTES);
    assert!(core::mem::offset_of!(CompletionPage, values) == 0);
};
