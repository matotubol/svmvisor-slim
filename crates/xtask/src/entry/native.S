.text
.p2align 12
.globl svmvisor_trial_client
.def svmvisor_trial_client; .scl 2; .type 32; .endef
.seh_proc svmvisor_trial_client
svmvisor_trial_client:
    push rbx
    .seh_pushreg rbx
    push rsi
    .seh_pushreg rsi
    push rdi
    .seh_pushreg rdi
    push r12
    .seh_pushreg r12
    sub rsp, 40
    .seh_stackalloc 40
    .seh_endprologue
    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    mov [rbx + 88], rsp
    test r9, r9
    jnz 2f
    // Warm the resolved syscall and identical frame before arming.
    mov qword ptr [rsp + 32], 0
    call rdi
    jmp 5f
2:
    mov rax, {magic}
    mov ecx, {arm}
    mov rdx, rsi
    mov r8d, {version}
.if {mock}
    mov rax, rsi
    sub rax, 1
    mov edx, 2
.else
    vmmcall
.endif
    mov [rbx], rax
    mov [rbx + 8], rdx
    test rax, rax
    jnz 3f
    call rdi
    mov eax, eax
    mov [rbx + 16], rax
    mov qword ptr [rbx + 24], 1
3:
    mov rax, {magic}
    mov ecx, {query}
    mov rdx, rsi
    mov r8d, {version}
.if {mock}
    xor eax, eax
    mov edx, 3
    mov r8d, 0x400
    mov r9d, 0x1234
    mov r10, 0x100000011
    mov r11d, 0x5678
    mov r12d, 9
.else
    vmmcall
.endif
    // RBX holds the result pointer: R8-R12 are all QUERY outputs.
    mov [rbx + 32], rax
    mov [rbx + 40], rdx
    mov [rbx + 48], r8
    mov [rbx + 56], r9
    mov [rbx + 64], r10
    mov [rbx + 72], r11
    mov [rbx + 80], r12
5:
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
.seh_endproc
.globl svmvisor_trial_client_end
svmvisor_trial_client_end:
