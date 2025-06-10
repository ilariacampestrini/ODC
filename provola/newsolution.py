from libdebug import debugger
import string

def provolino(t, bp):
    pass

d = debugger("./provola")

flag=b"$"*37
max_counter=0
res=''

for i in range(37):
    for c in string.printable:
        new_flag = flag[:i]+c.encode()+flag[i+1:]

        r=d.run()

        bp=d.bp(0x1A0F, file="provola", callback=provolino) #it is an offset

        d.cont() #we have to continue after the breakpoint
        d.cont()
        print(c)
        r.recvuntil(b'.')
        data=r.sendline(new_flag)
        print(data)

        d.wait()
        d.kill()

        print(new_flag)

        if bp.hit_count > max_counter:
            max_counter = bp.hit_count
            flag = new_flag
            res = res+c
            print(res)
            break
    
