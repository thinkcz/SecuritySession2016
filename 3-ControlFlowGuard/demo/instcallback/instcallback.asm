title "HOOK"

include ksamd64.inc

	EXTERN InstrumentationHook:PROC

	
	NESTED_ENTRY InstHookProc, TEXT
		
	GENERATE_EXCEPTION_FRAME Rbp
	
	call InstrumentationHook
		
	RESTORE_EXCEPTION_STATE Rbp
	
	ret

	NESTED_END InstHookProc, TEXT

	end