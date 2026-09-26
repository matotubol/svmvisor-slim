//! Same-CPU capture: CPUID/MSR admission, MTRRs and paging controls.
use core::arch::{asm, x86_64::__cpuid_count};

use svmvisor_hypervisor::firmware::native::resident::launch::{Mtrrs, native_paging_config};
use svmvisor_hypervisor::{
    arch::x86_64::{
        apic,
        msr::{
            EFER, HWCR, MTRR_CAP, SEV_STATUS, SYS_CFG, SYS_CFG_DEFINED, SYS_CFG_ENCRYPTION,
            TARGET_PHYSICAL_BITS, TARGET_SIGNATURE, TOM2, TSC_RATIO, TSC_RATIO_DEFINED, VM_CR,
            VM_CR_LOCK, VM_CR_R_INIT,
        },
    },
    host::paging::PagingConfig,
    svm::{
        control_msrs::{
            HsaveAddressPolicy, SMM_ADDR, SMM_MASK, SvmControlAdmissionError, VM_HSAVE_PA,
            VisibleSvmControls,
        },
        vmcr::VisibleVmCr,
    },
};

use super::physical_boot;
use super::{Cpu, physical_boot::admission_hint};

// CPUID-gated MSRs only. AMD APM2 15.4 VM_CR.SVMDIS and feature leaves.
pub(super) unsafe fn cpu() -> Result<Cpu, u64> {
    let basic = __cpuid_count(0, 0);
    let extended = __cpuid_count(0x80000000, 0);
    if basic.eax < 1
        || basic.ebx != 0x68747541
        || basic.edx != 0x69746e65
        || basic.ecx != 0x444d4163
        || extended.eax < 0x8000000a
    {
        let (item, observed, expected): (u64, u32, u32) = if basic.eax < 1 {
            (0, basic.eax, 1)
        } else if basic.ebx != 0x68747541 {
            (1, basic.ebx, 0x68747541)
        } else if basic.edx != 0x69746e65 {
            (2, basic.edx, 0x69746e65)
        } else if basic.ecx != 0x444d4163 {
            (3, basic.ecx, 0x444d4163)
        } else {
            (4, extended.eax, 0x8000000a)
        };
        admission_hint(101, item, observed as u64, expected as u64);
        return Err(1);
    }
    let one = __cpuid_count(1, 0);

    physical_boot::admission_cpu_id(one.ebx >> 24);
    let ext = __cpuid_count(0x80000001, 0);
    let svm = __cpuid_count(0x8000000a, 0);
    if one.ecx & (1 << 21) == 0 {
        admission_hint(157, 1, one.ecx as u64, 1 << 21);
        return Err(2);
    }
    // Preserve the loader-selected interface; never silently promote xAPIC
    // after the loader has chosen its register access method (APM2 16.10).
    let apic_base = unsafe { rdmsr(apic::APIC_BASE) };
    if apic_base & apic::APIC_BASE_X2APIC != apic::APIC_BASE_X2APIC {
        admission_hint(158, apic::APIC_BASE as u64, apic_base, apic::APIC_BASE_X2APIC);
        return Err(2);
    }
    if one.ecx & (1 << 31) != 0
        || one.edx & 0x07011020 != 0x07011020
        || ext.ecx & 4 == 0
        || ext.edx & 0x24100000 != 0x24100000
        || svm.edx & ((1 << 4) | 1) != ((1 << 4) | 1)
        || svm.ebx < 2
        || svm.eax != 1
    {
        let (item, observed, expected) = if one.ecx & (1 << 31) != 0 {
            (0, one.ecx, 0)
        } else if one.edx & 0x07011020 != 0x07011020 {
            (1, one.edx, 0x07011020)
        } else if ext.ecx & 4 == 0 {
            (2, ext.ecx, 4)
        } else if ext.edx & 0x24100000 != 0x24100000 {
            (3, ext.edx, 0x24100000)
        } else if svm.edx & ((1 << 4) | 1) != ((1 << 4) | 1) {
            (4, svm.edx, (1 << 4) | 1)
        } else if svm.ebx < 2 {
            (5, svm.ebx, 2)
        } else {
            (6, svm.eax, 1)
        };
        admission_hint(102, item, observed as u64, expected as u64);
        return Err(2);
    }
    let width = __cpuid_count(0x80000008, 0).eax as u8;
    let leaf = (extended.eax >= 0x8000001f).then(|| {
        let enc = __cpuid_count(0x8000001f, 0);
        [enc.eax, enc.ebx, enc.ecx, enc.edx]
    });
    let plan = svmvisor_hypervisor::arch::x86_64::encryption::NativeEncryptionPlan::new(
        one.eax, width, leaf,
    )
    .map_err(|_| {
        if !(32..=52).contains(&width) {
            admission_hint(104, 0x80000008, width as u64, 32 | (52u64 << 32));
        } else if one.eax == TARGET_SIGNATURE
            && width != TARGET_PHYSICAL_BITS
            && leaf.is_some_and(|v| v.iter().any(|&x| x != 0))
        {
            admission_hint(156, 0x80000008, width as u64, TARGET_PHYSICAL_BITS as u64);
        } else {
            let values = leaf.unwrap_or([0; 4]);
            admission_hint(
                103,
                one.eax as u64,
                values[0] as u64 | ((values[1] as u64) << 32),
                values[2] as u64 | ((values[3] as u64) << 32),
            );
        }
        3u64
    })?;
    let sys_cfg = plan.sys_cfg_msr().map(|msr| unsafe { rdmsr(msr) });
    let sev_status = plan.sev_status_msr().map(|msr| unsafe { rdmsr(msr) });
    let encryption = plan.validate(sys_cfg, sev_status).map_err(|_| {
        let allowed = SYS_CFG_DEFINED & !SYS_CFG_ENCRYPTION;
        if sys_cfg.is_some_and(|v| v & !allowed != 0) {
            admission_hint(153, SYS_CFG as u64, sys_cfg.unwrap(), allowed);
        } else {
            admission_hint(154, SEV_STATUS as u64, sev_status.unwrap_or(0), 0);
        }
        3u64
    })?;
    if !(32..=52).contains(&width) {
        admission_hint(104, 0x80000008, width as u64, 32 | (52u64 << 32));
        return Err(4);
    }
    // Refuse before INIT what the runtime's visible VM_CR owner refuses at arm
    // (SVMDIS, reserved bits); R_INIT keeps its own preparation/observer checks.
    let vm_cr = unsafe { rdmsr(VM_CR) };
    let Ok(vmcr_owner) = VisibleVmCr::admit(vm_cr & !VM_CR_R_INIT) else {
        admission_hint(151, VM_CR as u64, vm_cr, !(VM_CR_LOCK | VM_CR_R_INIT));
        return Err(4);
    };
    let efer = unsafe { rdmsr(EFER) };
    if efer & (1 << 12) != 0 {
        admission_hint(152, EFER as u64, efer, 1 << 12);
        return Err(4);
    }
    // Match the resident's exact-target register policy before destructive AP
    // startup, and before reading any target-specific SMRAM register.
    if one.eax != TARGET_SIGNATURE || width != TARGET_PHYSICAL_BITS {
        admission_hint(159, one.eax as u64, width as u64, TARGET_SIGNATURE as u64);
        return Err(4);
    }
    let hsave = unsafe { rdmsr(VM_HSAVE_PA) };
    // The CPUID admission above includes TscRateMsr. Sample before runtime entry
    // fixes physical scaling at unity; arm captures each CPU's guest value again.
    let tsc_ratio = unsafe { rdmsr(TSC_RATIO) };
    let policy = HsaveAddressPolicy::admit_target(
        one.eax,
        width,
        unsafe { rdmsr(HWCR) },
        unsafe { rdmsr(SMM_ADDR) },
        unsafe { rdmsr(SMM_MASK) },
    );
    if let Err(error) = policy.and_then(|policy| {
        VisibleSvmControls::admit_firmware_zero_key(hsave, tsc_ratio, policy, &vmcr_owner)
    }) {
        if error == SvmControlAdmissionError::InvalidInitialTscRatio {
            admission_hint(161, TSC_RATIO as u64, tsc_ratio, TSC_RATIO_DEFINED);
        } else {
            admission_hint(160, VM_HSAVE_PA as u64, hsave, 0);
        }
        return Err(4);
    }
    Ok(Cpu { physical_bits: width, apic_id: one.ebx >> 24, encryption })
}

/// CPU/encryption admission precedes this capture. Other admitted profiles
/// retain architectural default behavior.
pub(super) unsafe fn mtrrs(physical_bits: u8) -> Result<Mtrrs, u64> {
    use svmvisor_hypervisor::memory::mtrrs::{MAX_VARIABLE, MtrrReadError};
    Mtrrs::read(physical_bits, __cpuid_count(1, 0).eax, |index| unsafe { rdmsr(index) }).map_err(
        |error| {
            match error {
                MtrrReadError::VariableCount { capability } => {
                    admission_hint(105, MTRR_CAP as u64, capability, MAX_VARIABLE as u64)
                }
                MtrrReadError::Tom2 { error: _, sys_cfg, tom2 } => {
                    admission_hint(155, TOM2 as u64, tom2, sys_cfg);
                }
            }
            5
        },
    )
}

pub(super) unsafe fn config(cpu: Cpu) -> Result<PagingConfig, u64> {
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    native_paging_config(cr0, cr3, cr4, cpu.physical_bits, unsafe { rdmsr(EFER) } & (1 << 11) != 0)
        .ok_or_else(|| {
            let (item, observed, expected) = if cr0 & 0x80000011 != 0x80000011 {
                (0, cr0, 0x80000011)
            } else if cr0 & 0x60000000 != 0 {
                (0, cr0, 0)
            } else if !svmvisor_hypervisor::guest::continuation::native_cr4_supported(cr4) {
                (4, cr4, 0)
            } else {
                (3, cr3, 0)
            };
            admission_hint(106, item, observed, expected);
            6
        })
}

pub(super) unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    }
    (u64::from(high) << 32) | u64::from(low)
}

pub(super) unsafe fn wrmsr(msr: u32, value: u64) {
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nostack, preserves_flags));
    }
}
