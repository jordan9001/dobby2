.intel_syntax noprefix
.global test_asm

dat_1:
.quad 0x4141414141414141, 0, 0, 0x4040404040404040

test_asm:
    lea rcx, [dat_1]
    mov rdx, 2
    mov rax, [rcx + (rdx * 8) + 8]

    mov rax, dat_1

    ret
