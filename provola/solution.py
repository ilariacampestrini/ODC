from libdebug import debugger
import string

def provolino(t, bp):
    pass

d = debugger("./provola", continue_to_binary_entrypoint = False)

flag=b"$"*37
max_counter=0
res=''

for i in range(37):
    for c in string.printable:
        new_flag = flag[:i]+c.encode()+flag[i+1:]
        
        r=d.run()
        
        bp=d.breakpoint(0x1A0F, file="provola", callback=provolino) #it is an offset

        d.cont() #we have to continue after the breakpoint
        r.recvuntil(b'password.')
        data=r.sendline(new_flag)

        d.wait()
        d.kill()

        if bp.hit_count > max_counter:
            max_counter = bp.hit_count
            flag = new_flag
            res = res+c
            break
print(res)
    
