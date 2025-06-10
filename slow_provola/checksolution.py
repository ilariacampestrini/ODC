from libdebug import debugger

import string




def provolino(t, bp):

   print(t.memory[t.regs.rbp-0x14d])

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




flag =b"flag{pr0v0l4_1s_th3_f4v0r1p3_che3s3_0f_th3_1t4l1an_h4ck3r_c0meun1py}" 

f_s = "flag{pr0v0l4_1s_th3_f4v0r1p3_che3s3_0f_th3_1t4l1an_h4ck3r_c0meun1py}"




for i in range(68):

   r=d.run()

   print(f_s[i])

   if i==51:
       num=d.bp(0x3BCD, file="slow_provola", callback=provolino)
   elif i>51:

       num=d.bp(0x3BCD + 153*(i-51), file="slow_provola", callback=provolino)
   else:
       num=d.bp(0x1A5E + 168*i, file="slow_provola", callback=provolino) 

   # Set a breakpoint for the sleep
   bp = d.bp(0x7ffff7d0ec20, callback=force_fail)

   

   d.cont() #we have to continue after the breakpoint

   r.recvuntil(b'password.')

   r.sendline(flag)

   
d.wait()

d.kill()

      







#flag{pr0v0l4_1s_th3_f4v0r1t3_che3s3_0f_th3_1t4l1an_h4ck3r_c0mmun1ty} 