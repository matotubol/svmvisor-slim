/* Host NMI during a redirected-INIT GIF window. Physical guest NMIs are
 * delivered natively. This gate records a host-window NMI for delivery when
 * the stopped guest can accept it. IF remains clear and no GPR is changed. */
.text
.p2align 4
.globl svmvisor_resident_nmi
svmvisor_resident_nmi:
    clgi
    movl $1, svmvisor_resident_nmi_pending(%rip)
    iretq
