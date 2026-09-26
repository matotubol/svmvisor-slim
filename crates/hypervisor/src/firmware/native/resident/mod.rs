//! Native resident preparation: allocation, launch admission, MP
//! inventory and the inert ReadyToBoot callback continuation.

pub use crate::firmware::native::resident::callback::{
    CallbackError, CallbackPrepared, CallbackRequest, CallbackSites, GuestStackSpan,
    prepare_callback,
};

pub mod allocation;
pub mod bootstrap_paging;
mod callback;
pub mod launch;
pub mod memory;
pub mod processors;
