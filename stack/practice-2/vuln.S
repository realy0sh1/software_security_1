.intel_syntax noprefix
.section .text
.global _start

mov_rdi_rax_ret:
    mov rdi, rax
    ret

pop_rdi_ret:
    pop rdi
    ret

do_syscall:
    syscall
    ret

pop_rax_ret:
    pop rax
    ret

pop_rsi_ret:
    pop rsi
    ret

pop_rdx_ret:
    pop rdx
    ret

_start:
    call read_input
    mov rax, 0x3c // sys_exit
    xor rdi, rdi
    syscall

read_input:
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    
    mov rax, 0
    mov rdi, 0
    lea rsi, [rbp-0x40] // 0x40 bytes = 64 bytes input buffer, where input is written to
    mov rdx, 0xFFFF     // we are allowed to write up to 65535 chars => 
    syscall
    
    leave // mov RSP, RBP and Pop RBP
    ret

.section .data

flag_file:
    .asciz "/flag"
    
.align 8
flag_buffer:
    .space 64
