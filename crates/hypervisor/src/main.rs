//! UEFI firmware entry for the minimal Windows-booting hypervisor.
#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "uefi")]
#[path = "firmware/native/resident/activation/mod.rs"]
mod resident_activation;

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
/// # Safety
/// Firmware supplies a live image handle and system table at TPL_APPLICATION.
pub unsafe extern "efiapi" fn efi_main(
    image: uefi_raw::Handle,
    table: *const uefi_raw::table::system::SystemTable,
) -> uefi_raw::Status {
    unsafe { resident_activation::install(image, table.cast_mut()) }
}

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

#[cfg(not(target_os = "uefi"))]
fn main() {
    eprintln!("svmvisor-hypervisor is a UEFI firmware image; build with cargo xtask resident");
}
