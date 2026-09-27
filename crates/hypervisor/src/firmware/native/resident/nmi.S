/* Acknowledge a physical NMI in an IF-clear host GIF window, including the
 * still-pending source of #VMEXIT(NMI). The dispatcher transfers the pending
 * bit into V_NMI; hardware owns guest masking until IRET. No GPR is changed,
 * and IRET restores the flags modified by the acknowledgment increment. */
.text
.p2align 4
.globl svmvisor_resident_nmi
svmvisor_resident_nmi:
    clgi
    movl $1, svmvisor_resident_nmi_pending(%rip)
    incq svmvisor_resident_nmi_acks(%rip)
    iretq
