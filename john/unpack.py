#challenge with 32 bits and no pie, we find the absolute precise address on ida
from pwn import xor #we use that because xor is only between integers in python

#we read data directly from file instead of copying memory data here
f = open("./john", "rb")
content = f.read()

base = 0x8048000
address_check = 0x0804970E
address_1 = 0x080492A0
address_2 = 0x080492E5
address_3 = 0x08049329
address_4 = 0x080496AB
address_5 = 0x080495E4
address_6 = 0x08049546
address_7 = 0x0804951F

keys = [
    b"\x01\x02\x03\x04",
    b"\x10\x20\x30\x40",
    b"B00B",
    b"DEAD",
    b"\xff\xff\xff\xff"
]

def unpack(address, size, key): #unpack a function
    unpacked = b''
    offset = address - base
    for i in range(0, size*4, 4):
        unpacked += xor(content[offset+i:offset+i+4],key)
    return unpacked

key_check = keys[address_check%5]
unpacked_check = unpack (address_check, 83, key_check)
#we printed the unpacked binary, we have to use ghidra to interpret it because it is raw file
#we can substitute in the binary the unpacked code
with open("john_unpacked", "wb") as f:
    new_content = content[:address_check - base] + unpacked_check + content[address_check - base + len(unpacked_check):]
    f.write(new_content)



#we have to repeat unpacking many times

# CHECK 1
with open("john_unpacked", "rb") as f:
    content_1 = f.read()

key = keys[address_1%5]
unpacked_1 = unpack(address_1, 17, key)
#we printed the unpacked binary, we have to use ghidra to interpret it because it is raw file
#we can substitute in the binary the unpacked code
with open("john_unpacked", "wb") as f:
    new_content_1 = content_1[:address_1 - base] + unpacked_1 + content_1[address_1 - base + len(unpacked_1):]
    f.write(new_content_1)

# CHECK 2
with open("john_unpacked", "rb") as f:
    content_2 = f.read()

key = keys[address_2%5]
unpacked_2 = unpack(address_2, 17, key)
with open("john_unpacked", "wb") as f:
    new_content_2 = content_2[:address_2 - base] + unpacked_2 + content_2[address_2 - base + len(unpacked_2):]
    f.write(new_content_2)

# CHECK 3
with open("john_unpacked", "rb") as f:
    content_3 = f.read()

key = keys[address_3%5]
unpacked_3 = unpack(address_3, 23, key)
with open("john_unpacked", "wb") as f:
    new_content_3 = content_3[:address_3 - base] + unpacked_3 + content_3[address_3 - base + len(unpacked_3):]
    f.write(new_content_3)

# CHECK 4
with open("john_unpacked", "rb") as f:
    content_4 = f.read()

key = keys[address_4%5]
unpacked_4 = unpack(address_4, 24, key)
with open("john_unpacked", "wb") as f:
    new_content_4 = content_4[:address_4 - base] + unpacked_4 + content_4[address_4 - base + len(unpacked_4):]
    f.write(new_content_4)

# CHECK 5
with open("john_unpacked", "rb") as f:
    content_5 = f.read()

key = keys[address_5%5]
unpacked_5 = unpack(address_5, 49, key)
with open("john_unpacked", "wb") as f:
    new_content_5 = content_5[:address_5 - base] + unpacked_5 + content_5[address_5 - base + len(unpacked_5):]
    f.write(new_content_5)

# CHECK 6
with open("john_unpacked", "rb") as f:
    content_6 = f.read()

key = keys[address_6%5]
unpacked_6 = unpack(address_6, 39, key)
with open("john_unpacked", "wb") as f:
    new_content_6 = content_6[:address_6 - base] + unpacked_6 + content_6[address_6 - base + len(unpacked_6):]
    f.write(new_content_6)

# CHECK 7
with open("john_unpacked", "rb") as f:
    content_7 = f.read()

key = keys[address_7%5]
unpacked_7 = unpack(address_7, 9, key)
with open("john_unpacked", "wb") as f:
    new_content_7 = content_7[:address_7 - base] + unpacked_7 + content_7[address_7 - base + len(unpacked_7):]
    f.write(new_content_7)







# otherwise I can modify the code in order to nullify the packing and unpacking routines
# create a copy of the program, open with ida, spot the xor which changes the code, go the hexadecimal view and modify it with 90 90
# then option: apply patches to input file
# than it is just a reversing challenge
# 
# 
# watchpoint in read mode:rwatch, watchpoint in read+write mode:awatch
