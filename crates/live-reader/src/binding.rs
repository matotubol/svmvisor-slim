//! Discover once on the client; resident tokens own subsequent process revalidation.

use svmvisor_card_abi::batch::BindingEvidence;
use svmvisor_hypervisor::reader::{
    paging::PagingConfig,
    process::{self, ProcessRequest},
};

use crate::{
    bridge::ReadBridge,
    process::{Details, memory},
    profile::KernelProfile,
};

/// A process bound resident-side, with the EPROCESS fields read while finding it.
pub(crate) struct Bound {
    pub token: u64,
    /// The creation time the resident compares on each sample.
    pub created: u64,
    pub details: Details,
}

/// Walk the kernel process list for `request.pid` and bind it resident-side. `Ok(None)` means
/// the list was walked completely and the PID is absent.
pub(crate) fn discover(
    config: PagingConfig,
    profile: &KernelProfile,
    request: ProcessRequest,
    bridge: &mut ReadBridge,
) -> Result<Option<Bound>, String> {
    let mut backend_error = None;
    let found =
        process::find(config, profile.process(), request, &mut memory(bridge, &mut backend_error));
    let identity = found.map_err(|error| {
        format!("process discovery failed: {error:?}; backend={backend_error:?}")
    })?;
    let Some(identity) = identity else {
        return Ok(None);
    };
    let details = Details::read(
        config,
        profile,
        request.kernel_root_pa,
        identity.eprocess_va,
        &mut memory(bridge, &mut backend_error),
    );
    let details = details.map_err(|error| format!("{error}; backend={backend_error:?}"))?;

    let created = identity.create_time.ok_or("binding requires process creation time")?;
    let layout = profile.process().layout();
    let token = bridge.bind(BindingEvidence {
        kernel_root: request.kernel_root_pa,
        target_root: identity.kernel_root_pa,
        pid: identity.pid,
        object: identity.eprocess_va,
        creation: created,
        object_bytes: layout.eprocess_bytes,
        links_offset: layout.active_links_offset,
        pid_offset: layout.pid_offset,
        root_offset: layout.directory_root_offset,
        creation_offset: layout
            .create_time_offset
            .ok_or("profile requires creation-time offset")?,
        root_mask: layout.dtb_low_bits_mask,
    })?;
    Ok(Some(Bound { token, created, details }))
}
