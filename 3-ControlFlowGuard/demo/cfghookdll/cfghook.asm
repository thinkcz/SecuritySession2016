title "HOOK"

include ksamd64.inc

	EXTERN CfgHook:PROC

	
	NESTED_ENTRY CfgHookProc, TEXT
	.ENDPROLOG
	
	;GENERATE_EXCEPTION_FRAME Rbp
	



	call CfgHook
		
	;RESTORE_EXCEPTION_STATE Rbp


	
	ret

	NESTED_END CfgHookProc, TEXT

	end