from pwn import *

CHALL_PATH = "./chall"
CHALL = ELF(CHALL_PATH)

COMMANDS="""
c
"""


if args.REMOTE:
    c = remote("pkm.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, gdbscript=COMMANDS)
    else:
        c = process(CHALL_PATH)

c.interactive()