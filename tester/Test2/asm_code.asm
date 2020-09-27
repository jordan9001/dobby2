
.CONST
PUBLIC ROSTR
ROSTR:
	DB "THIS IS READ ONLY", 0

.CODE

cc_asm_ii PROC PUBLIC FRAME
.ENDPROLOG
	ud2
	ret
cc_asm_ii ENDP

cc_asm_ss PROC PUBLIC FRAME
.ENDPROLOG
	DB 0F1h
	ret
cc_asm_ss ENDP

END