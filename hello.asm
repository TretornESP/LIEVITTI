;Hello World test by Tretorn
;The encryption algorithm for the PoC is linear!!
;It encrypts everything until the first 0xcc (int3 here)
;when execution reaches the 0xcc, it encrypts what it had run previously
;and decrypts ONLY the next chunk (in this example from line 15 to line 27)
;if you did a jmp to, as an example, GOBACK, it would execute data not yet
;decrypted and would crash.

;A following more advanced version would catch the crash, calculated the section
;and decrypted it just in time. But whatever.

;Please be linear programming this or face the consequences.

global _start

section .text

_start:
    jmp MESSAGE

MESSAGE:
    int3 ; This codes define the chunks for the encryption algorithm!
    call GOBACK       
                    
M:    db "Hello, World!", 0dh, 0ah

GOBACK:
    mov rax, 0x1
    mov rdi, 0x1

    pop rsi          
                   
    mov rdx, 0xF
    syscall
    int3
    mov rax, 0x3C
    mov rdi, 0x0
    syscall



section .data