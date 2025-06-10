from libdebug import debugger
import string

def provolino(t, bp):
    pass

# Wait for the output until the program prompts for password
def force_fail(t, hs):
    t.syscall_number = 0
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0
    t.syscall_arg2 = 0
    t.syscall_arg3 = 0

# Initialize the debugger with the target binary
d = debugger("./slow_provola")

# Flag to be sent to the program
flag = b"$" * 68
res=''

for i in range(68):
    for c in string.printable:
        new_flag = flag[:i]+c.encode()+flag[i+1:]

        r=d.run()

        # Set a breakpoint for the for loop
        if i==51:
            num=d.bp(0x3BCD, file="provola2", callback=provolino)
        elif i>51:
            num=d.bp(0x3BCD + 153*(i-51), file="provola2", callback=provolino)
        else:
            num=d.bp(0x1A5E + 168*i, file="provola2", callback=provolino) 
        
        # Set a breakpoint for the sleep
        bp = d.bp(0x7ffff7cea570, callback=force_fail)
       
        d.cont() #we have to continue after the breakpoint

        r.recvuntil(b'password.')
        r.sendline(new_flag)

        d.wait()
        d.kill()
       
        if num.hit_count == 32:
            flag=new_flag
            res = res+c
            break
    print(res)
    print(hex(0x1a5e+168*i))



