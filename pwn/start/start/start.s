global _start

section .text 
_start :
	push esp
	push _exit
	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	push 0x3a465443
	push 0x20656874
	push 0x20747261
	push 0x74732073
	push 0x2774654c
	mov ecx,esp
	mov dl,20
	mov bl,1
	mov al,4
	int 0x80
	
	xor ebx,ebx
	mov dl,60
	mov al,3
	int 0x80

	add esp,20
	ret

_exit :
	pop esp
	xor eax,eax
	inc eax
	int 0x80
	
