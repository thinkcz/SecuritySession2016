title "HOOK"
	
	include ksamd64.inc


	subttl "InstHookProc"

	
	EXTERN InstrumentationHook:PROC
		
	NESTED_ENTRY InstHookProc, TEXT
	.ENDPROLOG
	;mov r11, rax
	
	push rax
	push r10
	push rdx
	push rcx
	;GENERATE_EXCEPTION_FRAME Rbp

	mov rdx, rax
	mov rcx, r10


	sub rsp, 16h
	call InstrumentationHook
	add rsp, 16h


		
	;RESTORE_EXCEPTION_STATE Rbp

	;mov rax,r11
	
	pop rcx
	pop rdx
	pop r10
	pop rax
	

	jmp r10	

	NESTED_END InstHookProc, TEXT


	

	end