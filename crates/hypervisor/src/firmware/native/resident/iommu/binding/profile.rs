//! 48882-3.11 physical pp206,209-210,217-228,250-251,254-256 (text/PNGs).
//! Optional support alone is not an enabled mode. Reserved read bits are ignored.

use super::{PciObservation, RegisterObservation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    PciFunction,
    CapabilityIdentity,
    FeaturePresence,
    VirtualAddressWidth(u8),
    PhysicalAddressWidth(u8),
    HostTranslationLevels,
    InterruptRemapSupport,
    Control { bits: u64 },
    Status { bits: u64 },
    InvalidationTimeout,
    ExclusionEnabled,
}

pub(super) struct Details {
    pub capability_bytes: usize,
    pub aperture_bytes: u64,
    pub physical_bits: u8,
    pub zero_control_mask: u64,
}

pub(super) fn validate(
    pci: PciObservation,
    registers: RegisterObservation,
) -> Result<Details, ProfileError> {
    if matches!(pci.vendor_device & 0xffff, 0 | 0xffff)
        || pci.class_revision >> 8 != 0x080600
        || pci.command_status & (1 << 20) == 0
    {
        return Err(ProfileError::PciFunction);
    }
    let header = pci.capability_header;
    if header & 0xff != 0x0f || (header >> 16) & 7 != 3 || (header >> 19) & 31 != 1 {
        return Err(ProfileError::CapabilityIdentity);
    }
    let efr_supported = header & (1 << 27) != 0;
    let cap_ext = header & (1 << 28) != 0;
    if registers.extended_features.is_some() != efr_supported
        || registers.extended_features2.is_some() != efr_supported
        || pci.miscellaneous1.is_some() != cap_ext
    {
        return Err(ProfileError::FeaturePresence);
    }
    let virtual_bits = ((pci.miscellaneous0 >> 15) & 127) as u8;
    let physical_bits = ((pci.miscellaneous0 >> 8) & 127) as u8;
    if !matches!(virtual_bits, 48 | 64) {
        return Err(ProfileError::VirtualAddressWidth(virtual_bits));
    }
    if !matches!(physical_bits, 40 | 48 | 52) {
        return Err(ProfileError::PhysicalAddressWidth(physical_bits));
    }
    // EFRSup=0 means these features are unsupported, not an unread zero register.
    let features = registers.extended_features.unwrap_or(0);
    let features2 = registers.extended_features2.unwrap_or(0);
    if features >> 10 & 3 == 3 {
        return Err(ProfileError::HostTranslationLevels);
    }
    if features2 >> 8 & 3 > 1 {
        return Err(ProfileError::InterruptRemapSupport);
    }
    let (zero_control_mask, zero_status_mask) = profile_masks(features, features2);
    let forbidden = registers.control & zero_control_mask;
    if forbidden != 0 {
        return Err(ProfileError::Control { bits: forbidden });
    }
    let residue = registers.status & zero_status_mask;
    if residue != 0 {
        return Err(ProfileError::Status { bits: residue });
    }
    if registers.control >> 5 & 7 == 7 {
        return Err(ProfileError::InvalidationTimeout);
    }
    if registers.exclusion_base & 1 != 0 {
        return Err(ProfileError::ExclusionEnabled);
    }
    Ok(Details {
        capability_bytes: if cap_ext { 24 } else { 20 },
        aperture_bytes: if features & (1 << 9) != 0 { 0x80000 } else { 0x4000 },
        physical_bits,
        zero_control_mask,
    })
}

fn profile_masks(features: u64, features2: u64) -> (u64, u64) {
    // Basic control has no HT tunnel, host A/D mode, alternate root/buffer
    // interpretation or IRTE-cache policy. These defined bits are conservative
    // profile restrictions even where the candidate deny DTE would not use them.
    // CRW[21:18], reserved[49,57] and all other reserved read bits are ignored.
    // GAPPIEn is conservatively excluded with the GA mode whenever GASup=1;
    // GAPPISup=0 does not receive an invented reserved-read/ignore guarantee.
    let mut control = (1 << 1) | (3 << 46) | (0x3f << 58);
    let mut status = 0;
    for (supported, control_bits, status_bits) in [
        (features & (1 << 1) != 0, 7 << 13, 7 << 5), // PPR
        (features & (1 << 4) != 0, (1 << 16) | (1 << 48) | (1 << 54), 0),
        (features & (1 << 7) != 0, (1 << 17) | (31 << 25) | (1 << 55), 7 << 8),
        (features >> 16 & 3 != 0, (1 << 22) | (1 << 24), 0), // SMI filter
        (features >> 24 & 3 != 0, 3 << 30, 3 << 11),         // dual PPR log
        (features >> 28 & 3 != 0, 3 << 32, 3 << 15),         // dual event log
        (features >> 38 & 3 != 0, 7 << 34, 0),               // device-table segmentation
        (features & (1 << 37) != 0, 3 << 37, 0),             // guest privilege policy
        (features & (1 << 41) != 0, (1 << 39) | (1 << 42), 0), // PPR auto response
        (features >> 42 & 3 != 0, 1 << 40, 0),               // MARC
        (features & (1 << 50) != 0, 1 << 45, 0),             // enhanced PPR
        (features & (1 << 2) != 0, 3 << 50, 0),              // x2APIC controls
        (features & (1 << 55) != 0, 3 << 52, 0),             // vIOMMU/virtual commands
        (features2 & (1 << 2) != 0, 1 << 56, 0),             // tiered memory
        (features2 >> 8 & 3 != 0, 3 << 43, 0),               // larger interrupt remap format
        (features & (1 << 40) != 0, 0, 3 << 17),             // PPR overflow threshold state
    ] {
        if supported {
            control |= control_bits;
            status |= status_bits;
        }
    }
    // SlfWBdis and BlkStopMrkEn do not enable additional tables/logs. Basic
    // enable/run/interrupt bits stay observable and supply no quiescence proof.
    (control, status)
}
