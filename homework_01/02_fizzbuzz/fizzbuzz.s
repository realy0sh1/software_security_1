.intel_syntax noprefix
.globl do_fizzbuzz

do_fizzbuzz:
	push rbp
	push rbx
	push rdx
	xor rcx, rcx
	
	loop:
		xor r10, r10
		mov r10b, 3
		
		lea rbx, [rdi + 4*rcx]
		mov eax, [rbx]
		
		xor rdx, rdx 
		xor r11, r11
		mov r11b, 3
		div r11d
		
		xor rax, rax
		cmp edx, eax
		cmove r10d, eax
		
		mov eax, [rbx]
		
		xor rdx, rdx 
		xor r11, r11
		mov r11b, 5
		div r11d
		
		xor rax, rax
		cmp edx, eax
		mov al, 1
		cmove r10d, eax
		
		mov eax, [rbx]
		
		xor rdx, rdx 
		xor r11, r11
		mov r11b, 15
		div r11d
		
		xor rax, rax
		cmp edx, eax
		mov al, 2
		cmove r10d, eax
		
		mov [rbx], r10d
		
		inc rcx
		xor rax, rax
		mov al, 1
		shl rax, 11
		cmp rcx, rax
	jl loop
	pop rdx
	pop rbx
	pop rbp
	xor rax, rax
	
	ret
