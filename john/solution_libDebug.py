from libdebug import debugger
import string

flagset = string.ascii_letters + string.digits + "_.-%&@!"
flaglen = 27

flag_init = "flag{"
# check 4
# after the breakpoint, in eax there will be the value of the correct character (used for the comparison) 
# we can just check if the value is the same as the one we are trying to guess
found = ""
for i in range(6):
    for c in flagset:
        flag = flag_init + found + c + "A"*(flaglen-len(found)-1) + "}"
        d = debugger(["./john_patched", flag], continue_to_binary_entrypoint = False)
        #d.arch="amd64"
        d.run()
        d.bp(0x080496EA)
        #d.cont()
        #for _ in range(i+1):
         #   d.cont()
        if(d.regs.eax == ord(c)):
            print(flag)
            found += c
            d.kill()
            break
        d.kill()

flag_until_4 = flag_init+found
flaglen = 33 - len(flag_until_4) - 1 

#check 5
# 2 if statements:
# 1. for ALL characters, check if they are correct (in case are not it return 0 and programs exita). BP at 0x08049658, check
#    if the result of the comparison in eax is 1 (char is correct)
# 2. checks if the 7th character is even ALWAYS. So, the place holder "A" is okay for all the character before but then, when
#    trying to guess the 7th, if we place a even character, the program will exit after the check of the first character of the 
#    flag (even if it is correct) --> so the lopp of d.cont() will crash. For this reason, when brute forcing the 7th 
#    character, we need to skip the even characters.
found = ""
for i in range(10):
    for c in flagset:
        if(i==6 and ord(c)%2==0): 
            continue
        flag = flag_until_4 + found + c + "A"*(flaglen-len(found)-1) + "}"
        d = debugger(["./john_patched", flag], continue_to_binary_entrypoint = False)
        #d.arch="amd64"
        d.run()
        d.bp(0x08049658)
        for _ in range(i+1):
            d.cont()  
        if(d.regs.eax == 0x1):
            print(flag)
            found += c
            d.kill()
            break
        d.kill()

flag_until_5 = flag_until_4+found
flaglen = 33 - len(flag_until_5) - 1 

#check 6
# recursive check. As in check 4, at the breakpoint, in eax there will be the value of the correct character 
# (used for the comparison). We can just check if the value is the same as the one we are trying to guess
found = ""
for i in range(11):
    for c in flagset:
        flag = flag_until_5 + found + c + "A"*(flaglen-len(found)-1) + "}"
        d = debugger(["./john_patched", flag], continue_to_binary_entrypoint = False)
        d.run()
        d.bp(0x80495AA)
        for _ in range(i+1):
            d.cont()  
        if(d.regs.eax == ord(c)):
            print(flag)
            found += c
            d.kill()
            break
        d.kill()