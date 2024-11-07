.intel_syntax noprefix

.macro define_string name value
    .local \name
    \name: .asciz "\value"
.endm

.section .rodata
define_string prompt, "What is your name?"
define_string welcome, "Welcome, "
define_string encouragement, "Try running /bin/sh"
define_string newline, "\n"

.text
.global _start
.type _start, STT_FUNC
_start:
    sub rsp, 8
    # int result = main()
    call main
    # exit_group(result)
    mov edi, eax
    mov eax, 0xe7
    syscall
    hlt # This syscall should never return.

.global strlen
.type strlen, STT_FUNC
strlen:
    # rdi: the string to measure
    # Will return the length in rax, and clobber rcx and rdi on the way.
    xor eax, eax
    xor ecx, ecx
    dec rcx
    repne scasb
    not rcx
    sub rcx, 1
    mov rax, rcx
    ret

.global print
.type print, STT_FUNC
print:
    # rdi: the string to print.
    mov rsi, rdi
    call strlen # We know this will preserve everything except rdi, rcx, and rax (see above)
    mov rdx, rax
    mov edi, 1
    mov eax, 1
    syscall
    ret

.global puts
.type puts, STT_FUNC
puts:
    # rdi: the string to print (with a newline).
    call print
    lea rdi, [newline]
    jmp print

.global main
.type main, STT_FUNC
main:
    push r8
    sub rsp, 200

    # puts(prompt)
    lea rdi, [prompt]
    call puts

    # bytes = read(STDIN_FILENO, buffer, buffer_len)
    mov edi, 0
    mov rsi, rsp
    mov edx, 0x200
    mov eax, 0
    syscall
    cmp rax, 0
    cmovs rax, rdi # rax = 0 on error.
    mov byte ptr [rsi + rax], 0 # Write a null byte after the end of the string.
    mov r8, rax

    # print(welcome)
    lea rdi, [welcome]
    call print

    # puts(buffer)
    mov rdi, rsp
    call puts

    # puts(encouragement)
    lea rdi, [encouragement]
    call puts

    # return 0
    xor eax, eax
    add rsp, 200
    pop r8
    ret
