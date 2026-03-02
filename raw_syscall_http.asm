; raw_syscall_http.asm — x86-64 Linux
; HTTP GET via direct syscall instructions. No libc. No external tools.
; Syscalls used: socket(41), connect(42), write(1), read(0), close(3), exit(60)
;
; Assemble: nasm -f elf64 raw_syscall_http.asm -o raw_syscall_http.o
; Link:     ld raw_syscall_http.o -o raw_syscall_http
; Run:      ./raw_syscall_http

section .data

; HTTP/1.0 request — explicit CRLF line endings per RFC
request:
    db "GET / HTTP/1.0", 13, 10
    db "Host: ifconfig.me", 13, 10
    db "User-Agent: x86_64-asm/syscall", 13, 10
    db 13, 10
request_len equ $ - request

; struct sockaddr_in { sa_family(2), sin_port(2), sin_addr(4), pad(8) }
; IP: 34.160.111.145  Port: 80
sockaddr:
    dw  2                       ; AF_INET = 2
    dw  0x5000                  ; port 80 big-endian: 0x0050 -> stored LE as 0x5000
    db  34, 160, 111, 145       ; sin_addr in network byte order (big-endian)
    times 8 db 0                ; padding to 16 bytes

section .bss
    buf resb 65536

section .text
global _start

_start:
    ;------------------------------------------------------------------
    ; sockfd = socket(AF_INET=2, SOCK_STREAM=1, 0)
    ;------------------------------------------------------------------
    mov rax, 41         ; SYS_socket
    mov rdi, 2          ; AF_INET
    mov rsi, 1          ; SOCK_STREAM
    mov rdx, 0
    syscall
    mov r12, rax        ; save sockfd

    ;------------------------------------------------------------------
    ; connect(sockfd, &sockaddr, 16)
    ;------------------------------------------------------------------
    mov rax, 42         ; SYS_connect
    mov rdi, r12
    lea rsi, [rel sockaddr]
    mov rdx, 16         ; sizeof(sockaddr_in)
    syscall

    ;------------------------------------------------------------------
    ; write(sockfd, request, request_len)
    ;------------------------------------------------------------------
    mov rax, 1          ; SYS_write
    mov rdi, r12
    lea rsi, [rel request]
    mov rdx, request_len
    syscall

    ;------------------------------------------------------------------
    ; read loop: read(sockfd, buf, 65536) then write(stdout, buf, n)
    ;------------------------------------------------------------------
.read_loop:
    mov rax, 0          ; SYS_read
    mov rdi, r12
    lea rsi, [rel buf]
    mov rdx, 65536
    syscall
    test rax, rax
    jle  .done

    mov rdx, rax        ; bytes read
    mov rax, 1          ; SYS_write
    mov rdi, 1          ; stdout
    lea rsi, [rel buf]
    syscall
    jmp  .read_loop

    ;------------------------------------------------------------------
    ; close(sockfd)
    ;------------------------------------------------------------------
.done:
    mov rax, 3          ; SYS_close
    mov rdi, r12
    syscall

    ;------------------------------------------------------------------
    ; exit(0)
    ;------------------------------------------------------------------
    mov rax, 60         ; SYS_exit
    mov rdi, 0
    syscall
