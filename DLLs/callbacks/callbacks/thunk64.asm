

EXTERN CallbackRoutine:proc
EXTERN __imp_RtlCaptureContext:dq

.code

InstrCallbackEntry PROC

    mov gs:[2e0h], rsp ; Win10 TEB InstrumentationCallbackPreviousSp
    mov gs:[2d8h], r10 ; Win10 TEB InstrumentationCallbackPreviousPc
	
	mov r10, rcx ; save rcx
	sub rsp, 4d0h ; CONTEXT structure size
	and rsp, -10h ; align rsp
	mov rcx, rsp ; parameters are fun
	call __imp_RtlCaptureContext ; capture the thread's context
	
	sub rsp, 20h ; shadow stack space
	call CallbackRoutine ; call our callback which will restore context and go back to where we want
	
	int 3 ; we should not be here.

InstrCallbackEntry ENDP

END