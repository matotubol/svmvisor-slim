//! In-memory transport boundary for the retained reader logic. No native transport exists.

use std::time::Instant;

use svmvisor_card_abi::batch::REQUEST_BYTES;

pub(crate) trait Exchange {
    fn exchange(
        &mut self,
        request: &[u8; REQUEST_BYTES],
        deadline: Instant,
    ) -> Result<Vec<u8>, String>;

    fn context(&mut self, _: u64, _: Instant) -> Result<Vec<u8>, String> {
        Err("automatic context is unsupported by this transport".into())
    }
}

#[cfg(test)]
pub(crate) mod testing;
