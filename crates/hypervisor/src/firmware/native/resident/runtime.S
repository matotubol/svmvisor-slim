/* Resident one-CPU native continuation world switch.
 * AMD APM2 rev3.44 15.5.1/15.5.2/15.7/15.13.1; BridgeContext in bridge.rs.
 * Windows x64 ABI: RCX=context; dispatched function RCX=context, AL=resume.
 * Link this complete object and dispatcher into retained private monitor code.
 * No absolute symbol/data references and no calls into the original DXE image.
 * The incoming guest auxiliary state is already in its VMCB. Host and guest
 * stacks/roots differ. No host x87/MMX/SIMD, xstate/XCR0 changes or migration;
 * extended state and DR0-3 remain live and guest-owned throughout the loop.
 * Only a successful target-owned guest INIT clears live DR0-3 in the audited
 * core helper; VMCB DR6/7 reset separately. Private INIT/#SX never resets them.
 * Entry is nonreturning. The startup profile opens STGI with IF=0 only in
 * its private INIT-to-SX acknowledgment window; no recovery after VMRUN.
 */
.text
.p2align 4
.globl svmvisor_resident_enter
svmvisor_resident_enter:
    cli
    clgi
    mov %rcx, %r10
    /* Native-to-resident commit. Arm admitted LbrVirt and a 16-entry stack.
     * The caller proved this entire arena identity-mapped and writable under
     * the current root. Preserve original controls before freezing recording;
     * neither a branch nor a call intervenes before both recording bits clear.
     * Preserve every other DebugCtl bit. Afterward host recording stays off,
     * while VMRUN/VMEXIT exchange the guest controls and records automatically
     * (APM2 physical pp602,807-808; target PPR pp124-125,190,234-235).
     * No fallible return follows this point; this capture is at commit, not at
     * the earlier EFI callback boundary. R10 remains the host context. */
.globl svmvisor_resident_lbr_capture
svmvisor_resident_lbr_capture:
    mov 16(%r10), %r11
    mov $0x1d9, %ecx
    rdmsr
    mov %eax, 0x670(%r11)
    mov %edx, 0x674(%r11)
    and $-2, %eax
    wrmsr
    mov $0xc000010f, %ecx
    rdmsr
    mov %eax, 0x698(%r11)
    mov %edx, 0x69c(%r11)
    and $-65, %eax
    wrmsr
    mov $0x1db, %ecx
    rdmsr
    mov %eax, 0x678(%r11)
    mov %edx, 0x67c(%r11)
    inc %ecx
    rdmsr
    mov %eax, 0x680(%r11)
    mov %edx, 0x684(%r11)
    inc %ecx
    rdmsr
    mov %eax, 0x688(%r11)
    mov %edx, 0x68c(%r11)
    inc %ecx
    rdmsr
    mov %eax, 0x690(%r11)
    mov %edx, 0x694(%r11)
    mov $0xc000010e, %ecx
    rdmsr
    mov %eax, 0xb70(%r11)
    mov %edx, 0xb74(%r11)
    lea 0xa70(%r11), %rdi
    mov $0xc0010300, %ecx
.globl svmvisor_resident_lbr_stack_capture
svmvisor_resident_lbr_stack_capture:
    rdmsr
    mov %eax, (%rdi)
    mov %edx, 4(%rdi)
    add $8, %rdi
    inc %ecx
    cmp $0xc0010320, %ecx
    jb svmvisor_resident_lbr_stack_capture
.globl svmvisor_resident_lbr_capture_end
svmvisor_resident_lbr_capture_end:
    /* Commit point: guest original EFER/CR0 are already in its VMCB. Host
     * private NX/WP permissions require these host-only enablements before
     * using the private paging root. APM2 3.1/5.3 and 15.5/15.6. */
    mov $0xc0000080, %ecx
    rdmsr
    or $0x800, %eax
    wrmsr
    /* MOV CR3 alone retains firmware global translations, which may still
     * grant RWX access to host guards/data. Clear host PGE before switching
     * roots and leave it clear: our private tables have no global leaves.
     * Keeping PGE clear also prevents speculative global refills under the
     * old root. Guest CR4 is already captured in the VMCB and stays unchanged;
     * PCIDE and all other inherited controls are preserved here.
     * APM2 rev3.44 physical pp109,220-222,564; NPT host PGE ignored at p615. */
.globl svmvisor_resident_host_paging
svmvisor_resident_host_paging:
    mov %cr4, %rax
    and $-129, %rax
    mov %rax, %cr4
    mov 8(%r10), %rax
    mov %rax, %cr3
.globl svmvisor_resident_host_paging_end
svmvisor_resident_host_paging_end:
    mov %cr0, %rax
    or $0x10000, %rax
    mov %rax, %cr0
    mov 0(%r10), %rsp
    sub $16, %rsp
    mov %r10, (%rsp) /* Host-only context, preserved by VMRUN's host RSP. */
    mov 56(%r10), %rax
    lgdt (%rax)
    pushq 88(%r10)
    lea .Lresident_cs(%rip), %rax
    push %rax
    lretq
.Lresident_cs:
    mov 80(%r10), %ax
    mov %ax, %ss
    mov %ax, %ds
    mov %ax, %es
    xor %eax, %eax
    mov %ax, %fs
    mov %ax, %gs
    lldt %ax
    mov 72(%r10), %ax
    ltr %ax
    /* Terminal gates select private IST1: its TSS must already be loaded. */
    mov 64(%r10), %rax
    lidt (%rax)
    /* Host CR4.MCE=1 now that the resident IDT with the #MC gate (vector 18,
     * IST1) and NMI gate (vector 2, IST2) is loaded. Without it a host machine
     * check shuts the processor down; with it a host #MC traps to vector 18
     * (APM2 rev3.44 15.12.18 p522, Table 15-10 p530). PPR57896 p101
     * HOST_MCE_OVERRIDE (Fixed,1): with host CR4.MCE=1 a guest #MC with guest
     * CR4.MCE=0 is intercepted, not a shutdown. This entry is shared, so BSP
     * and AP hosts are consistent (the AP trampoline left CR4=0x620, MCE=0).
     * VMRUN saves this host CR4 and #VMEXIT restores it (15.5.1). */
    mov %cr4, %rax
    or $0x40, %rax
    mov %rax, %cr4
    /* A private host has no firmware/guest TLS. Guest bases are already in the
     * immutable native capture and mutable guest VMCB, before these writes. */
    xor %eax, %eax
    xor %edx, %edx
    mov $0xc0000100, %ecx
    wrmsr
    inc %ecx
    wrmsr
    inc %ecx
    wrmsr
    mov 48(%r10), %rax
    mov %rax, %rdx
    shr $32, %rdx
    mov $0xc0010117, %ecx
    wrmsr
    /* The exact CPU profile was admitted without changing PMU hardware.
     * Capture selectors now, at the nonreturning commit, and apply logical
     * EFER filtering. Counter values and global PMU state remain live. The
     * private root, stack, descriptors and terminal gates are already active. */
.globl svmvisor_resident_pmu_commit
svmvisor_resident_pmu_commit:
    cld
    mov (%rsp), %rcx
    sub $32, %rsp
    call svmvisor_resident_pmu_initialize
    add $32, %rsp
    test %al, %al
    jz svmvisor_resident_terminal
    mov (%rsp), %r10
    /* Arm captured this CPU's original TSC_RATIO and required CPUID.TscRateMsr.
     * The logical guest runs as a native host, whose own clock is not scaled by
     * its ratio MSR (APM2 physical p647; PPR57896 p189). Keep the physical
     * multiplier at 1.0; intercepted guest writes update software state only. */
.globl svmvisor_resident_tsc_ratio_init
svmvisor_resident_tsc_ratio_init:
    mov $0xc0000104, %ecx
    xor %eax, %eax
    mov $1, %edx
    wrmsr
    mov 32(%r10), %rax
    vmsave %rax
.Lresident_resume:
    mov (%rsp), %r10
    /* Host IF/GIF remain clear. Native guest IF/TPR and physical LAPIC state
     * own ordinary IRQ delivery; never overwrite the guest-live CR8 here. */
    mov 16(%r10), %rax
    /* Host-private entry provenance before guest GPRs become live. Offsets
     * are pinned by RawVmexitCapture's compile-time assertions in runtime.rs. */
.globl svmvisor_resident_entry_capture
svmvisor_resident_entry_capture:
    lea svmvisor_resident_raw_vmexit(%rip), %r11
    addq $1, 0(%r11)
    jnz .Lentry_sequence_ready
    addq $1, 0(%r11)
.Lentry_sequence_ready:
    mov %rax, 16(%r11)
    mov 0x578(%rax), %rdx
    mov %rdx, 24(%r11)
    mov 0x558(%rax), %rdx
    mov %rdx, 136(%r11)
    vmload %rax
    mov 40(%r10), %rsi
    mov 0(%rsi), %rcx
    mov 8(%rsi), %rdx
    mov 16(%rsi), %rbx
    mov 24(%rsi), %rbp
    mov 40(%rsi), %rdi
    mov 48(%rsi), %r8
    mov 56(%rsi), %r9
    mov 64(%rsi), %r10
    mov 72(%rsi), %r11
    mov 80(%rsi), %r12
    mov 88(%rsi), %r13
    mov 96(%rsi), %r14
    mov 104(%rsi), %r15
    mov 32(%rsi), %rsi
.globl svmvisor_resident_vmrun
svmvisor_resident_vmrun:
    /* GIF remains clear, so physical IRQs cannot run on the captured guest
     * register frame. VMRUN loads guest RFLAGS; with V_INTR_MASKING=0 that
     * guest IF controls IRQ delivery. VMEXIT clears GIF before restoring IF. */
    sti
    vmrun %rax
.globl svmvisor_resident_vmexit
svmvisor_resident_vmexit:
    cli
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11
    push %r10
    push %r9
    push %r8
    push %rdi
    push %rsi
    push %rbp
    push %rbx
    push %rdx
    push %rcx
    mov 112(%rsp), %r10
    /* All 14 guest GPRs are now on the host stack. RAX is the restored
     * VMRUN physical operand, not guest RAX (which is at VMCB+5f8).
     * Capture precedes VMSAVE, host VMLOAD and every Rust/INIT mutation.
     * No calls, guest stores, FP/SIMD, or guest-stack accesses occur here. */
.globl svmvisor_resident_exit_capture
svmvisor_resident_exit_capture:
    lea svmvisor_resident_raw_vmexit(%rip), %rdi
    movq $0, 8(%rdi)
    mov %rax, 32(%rdi)
    mov 16(%r10), %r11
    mov %r11, 144(%rdi)
    mov 0x578(%rax), %r11
    mov %r11, 40(%rdi)
    mov 0x0c8(%rax), %r11
    mov %r11, 48(%rdi)
    mov 0x070(%rax), %r11
    mov %r11, 56(%rdi)
    mov 0x558(%rax), %r11
    mov %r11, 64(%rdi)
    mov 0x550(%rax), %r11
    mov %r11, 72(%rdi)
    mov 0x5f8(%rax), %r11
    mov %r11, 80(%rdi)
    mov 8(%rsp), %r11
    mov %r11, 88(%rdi)
    mov (%rsp), %r11
    mov %r11, 128(%rdi)
    mov %cr0, %r11
    mov %r11, 112(%rdi)
    movq $-1, 96(%rdi)
    movq $-1, 104(%rdi)
    movq $-1, 120(%rdi)
    movq $0, 152(%rdi)
.globl svmvisor_resident_msr_capture
svmvisor_resident_msr_capture:
    cmpq $0x7c, 56(%rdi)
    jne svmvisor_resident_raw_capture_commit
    cmpl $0xc0010010, 128(%rdi)
    jne svmvisor_resident_raw_capture_commit
    /* Only SYS_CFG diagnostics consume physical CPU/cache evidence. Select
     * that boundary before serializing with CPUID on the native host. The
     * guest GPRs are already saved; ordinary MSR exits skip this entire sample. */
    mov $1, %eax
    xor %ecx, %ecx
    cpuid
    shr $24, %ebx
    mov %rbx, 120(%rdi)
    cmp $0x00b40f40, %eax
    jne svmvisor_resident_raw_capture_commit
    mov $0x2ff, %ecx
    rdmsr
    shl $32, %rdx
    or %rdx, %rax
    mov %rax, 96(%rdi)
    mov $0xc0010010, %ecx
    rdmsr
    shl $32, %rdx
    or %rdx, %rax
    mov %rax, 104(%rdi)
    movq $1, 152(%rdi)
.globl svmvisor_resident_raw_capture_commit
svmvisor_resident_raw_capture_commit:
    mov 0(%rdi), %r11
    mov %r11, 8(%rdi) /* Commit the tuple last; no writer until next entry. */
.globl svmvisor_resident_exit_capture_end
svmvisor_resident_exit_capture_end:
    mov 16(%r10), %rax
    vmsave %rax
    mov 32(%r10), %rax
    vmload %rax
    cld
    mov %rsp, %rsi
    mov 40(%r10), %rdi
    mov $14, %ecx
    rep movsq
    add $112, %rsp
    mov (%rsp), %rcx
    sub $32, %rsp /* Required shadow space; stack remains call-aligned. */
    call *96(%rcx)
    add $32, %rsp
    test %al, %al
    jnz .Lresident_resume
.globl svmvisor_resident_terminal
svmvisor_resident_terminal:
    cli
    hlt
    jmp svmvisor_resident_terminal
/* Private redirected-INIT gate. APM2 rev3.44 15.21.8/Table15-12,15.28:
 * vector30 pushes error1 and consumes INIT without architectural CPU/APIC
 * reset. IF stays clear; CLGI closes the window before touching host state.
 * No GPR is changed. Fault-class saved RIP is resumed unchanged. IRETQ
 * restores saved host flags after removing exactly the error-code qword.
 * Neither this gate nor its caller acknowledges any maskable APIC source.
 * Any other error code is a terminal host #SX. Host IF stays clear, so no
 * physical maskable interrupt can enter this exception gate. */
.globl svmvisor_resident_sx
svmvisor_resident_sx:
    clgi
    cmpq $1, (%rsp)
    jne svmvisor_resident_fault_30
    lock incq svmvisor_resident_init_acks(%rip)
    add $8, %rsp
    iretq
.globl svmvisor_resident_runtime_end
svmvisor_resident_runtime_end:
