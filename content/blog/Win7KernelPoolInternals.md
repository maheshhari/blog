---
title:  Windows 7 Kernel Pool Internals
date: 2020-02-08 00:00:00
categories:
  - Windows
  - heap
tags:
  - Windows
  - Kernel
thumbnailImagePosition: right
---

Notes on Windows 7 Kernel Pool Internals that I learned from this [paper](https://media.blackhat.com/bh-dc-11/Mandt/BlackHat_DC_2011_Mandt_kernelpool-wp.pdf?source=post_page---------------------------)
<!-- more -->

### NUMA (Non-uniform Memory Architecture)
* Dedicate different memory bank for different processors
* Quicker access to local memory
* Processors and memory are maintained in units called nodes via the `KNODE` structure in kernel.
```c
0: kd> dt nt!_KNODE
   +0x000 PagedPoolSListHead : _SLIST_HEADER
   +0x010 NonPagedPoolSListHead : [3] _SLIST_HEADER
   +0x040 Affinity         : _GROUP_AFFINITY
   +0x050 ProximityId      : Uint4B
   +0x054 NodeNumber       : Uint2B
   +0x056 PrimaryNodeNumber : Uint2B
   +0x058 MaximumProcessors : UChar
   +0x059 Color            : UChar
   +0x05a Flags            : _flags
   +0x05b NodePad0         : UChar
   +0x05c Seed             : Uint4B
   +0x060 MmShiftedColor   : Uint4B
   +0x068 FreeCount        : [2] Uint8B
   +0x078 Right            : Uint4B
   +0x07c Left             : Uint4B
   +0x080 CachedKernelStacks : _CACHED_KSTACK_LIST
   +0x0a0 ParkLock         : Int4B
   +0x0a4 NodePad1         : Uint4B
```

* Multi-node system; nt!KeNumberNodes > 1
* KNODE->Color is an array index used by allocation and free algorithms to associate nodes with pool
* KNODE has 4 singly linked lookaside list of free pool pages for each node 

### System Memory Pools
Memory pools are dynamically created at system initialization based on the number of system nodes. Each pool is defined by a pool descriptor.

### Two types of pool memory:
#### Paged
* Can be accessed from any processor
* IRQL < Dispatch\_Level(2)
* Number of paged pool: `nt!ExpNumberOfPagedPools`
* Uniprocessor - 4 paged pools (index 1-4)
* Multiprocessor - 1 per node (index 1)
* Extra pool descriptor in each for prototype pools / full page allocations (index 0)
* All pool descriptors are maintained in `nt!ExpPagedPoolDescriptor` array.

#### Non-paged
* Present in Physical memory always
* For threads at IRQL >= Dispatch\_level(2) no page faults = speed
* Number of non-paged pool: `nt!ExpNumberOfNonPagedPools`
* Uniprocessor - 1st index in `nt!PoolVector` points to non-paged pool descriptor
* Multiprocessor - each node has one non-paged pool, descriptors stored in `nt!ExpNonPagedPoolDescriptor` array

#### Session pool
* Used by win32K
* Unique to each session
* Paged and non-paged session pool
* Non-paged session memory uses global non-paged pool descriptor
* Paged session memory has unique descriptor in `nt!MM_SESSION_SPACE`
* Session pool descriptor obtained from `nt!EPROCESS` 

### Pool Descriptor
* `nt!POOL_DESCRIPTOR`
* Kernel pool managed by pool descriptor
* It tracks:
	* Running allocations
	* Pages in use
	* Free chunks

```c
0: kd> dt nt!_pool_descriptor
   +0x000 PoolType         : _POOL_TYPE
   +0x008 PagedLock        : _KGUARDED_MUTEX
   +0x008 NonPagedLock     : Uint8B
   +0x040 RunningAllocs    : Int4B
   +0x044 RunningDeAllocs  : Int4B
   +0x048 TotalBigPages    : Int4B
   +0x04c ThreadsProcessingDeferrals : Int4B
   +0x050 TotalBytes       : Uint8B
   +0x080 PoolIndex        : Uint4B
   +0x0c0 TotalPages       : Int4B
   +0x100 PendingFrees     : Ptr64 Ptr64 Void
   +0x108 PendingFreeDepth : Int4B
   +0x140 ListHeads        : [256] _LIST_ENTRY
```

* PendingFrees - singly-linked list of chunks waiting to be freed
* ListHeads - doubly-linked list of free chunks of the same size

#### ListHeads Lists (AMD64)
* Chunk size less than a page
* Granularity  - 0x10 bytes
* Blocksize = (NumberOfBytes + 0x1F) >> 4
* Size of block = Blocksize * Granularity

```python
>>> (0+0x1f)>>4
1
>>> (0x10+0x1f)>>4
2
>>> (0x11+0x1f)>>4
3
>>> (0x21+0x1f)>>4
4
```
##### nt!pool\_header metadata header for all pool chunks

```c
0: kd> dt nt!_pool_header
   +0x000 PreviousSize     : Pos 0, 8 Bits
   +0x000 PoolIndex        : Pos 8, 8 Bits
   +0x000 BlockSize        : Pos 16, 8 Bits
   +0x000 PoolType         : Pos 24, 8 Bits
   +0x000 Ulong1           : Uint4B
   +0x004 PoolTag          : Uint4B
   +0x008 ProcessBilled    : Ptr64 _EPROCESS
   +0x008 AllocatorBackTraceIndex : Uint2B
   +0x00a PoolTagHash      : Uint2B
   +0x00c Padding[0x4]       : Uint1B
```

* **PreviousSize** - BlockSize of preceding pool chunk
	* Used to locate previous chunk's pool header for merging to reduce fragmentation
	* If PreviousSize if 0, then chunk at beginning of pool
* **PoolIndex** - index into pool descriptor array `nt!ExpPagedPoolDescirptor` or `nt!ExpNonPagedPoolDescriptor` to get corresponding `nt!pool_descriptor`
* Chunk is freed into `Pool_Descriptor->ListHeads[BlockSize]`
* **PoolType**
	* PoolType is 0 if the chunk is free
	* If Busy, PoolType is (enum POOL\_TYPE | pool\_in\_use)

```c
0: kd> dt nt!_pool_type
   NonPagedPool = 0n0
   PagedPool = 0n1
   NonPagedPoolMustSucceed = 0n2
   DontUseThisType = 0n3
   NonPagedPoolCacheAligned = 0n4
   PagedPoolCacheAligned = 0n5
   NonPagedPoolCacheAlignedMustS = 0n6
   MaxPoolType = 0n7
   NonPagedPoolSession = 0n32
   PagedPoolSession = 0n33
   NonPagedPoolMustSucceedSession = 0n34
   DontUseThisTypeSession = 0n35
   NonPagedPoolCacheAlignedSession = 0n36
   PagedPoolCacheAlignedSession = 0n37
   NonPagedPoolCacheAlignedMustSSession = 0n38
```

* If chunk is free, Pool\_Header is followed by \_LIST\_ENTRY

```c
0: kd> dt nt!_LIST_ENTRY
   +0x000 Flink            : Ptr64 _LIST_ENTRY
   +0x008 Blink            : Ptr64 _LIST_ENTRY
```
* Flink and Blink overwritten to obtain write-what-where in previous versions, like Unlink attack in glibc malloc, mitigated in Windows 7

### Lookaside Lists
Lookaside Lists are pre-allocated buffers, on which simple operations like PUSH and POP (LIFO) can be performed. Lookaside Lists are used to cache frequently used chunks of certain size instead of returning them back to the OS.
* Lookaside Lists take advantage of CPU caching 
* They are defined in Processor Control Block `ntKPRCB`
* Paged (PPPagedLookasideList) and non-paged (PPNPagedLookasideList)

```c
0: kd> dt nt!_KPRCB
... 
+0x780 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
+0x880 PPNPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
+0x1480 PPPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
... 
```

* Max Blocksize = 0x20, Max size = 0x20\*0x10
* Therefore, 32 Lookaside lists
* Lookaside list defined by `nt!GENERAL_LOOKASIDE_POOL`

```c
0: kd> dt nt!_GENERAL_LOOKASIDE_POOL
   +0x000 ListHead         : _SLIST_HEADER
   +0x000 SingleListHead   : _SINGLE_LIST_ENTRY
   +0x010 Depth            : Uint2B
   +0x012 MaximumDepth     : Uint2B
   +0x014 TotalAllocates   : Uint4B
   +0x018 AllocateMisses   : Uint4B
   +0x018 AllocateHits     : Uint4B
   +0x01c TotalFrees       : Uint4B
   +0x020 FreeMisses       : Uint4B
   +0x020 FreeHits         : Uint4B
   +0x024 Type             : _POOL_TYPE
   +0x028 Tag              : Uint4B
   +0x02c Size             : Uint4B
   +0x030 AllocateEx       : Ptr64     void* 
   +0x030 Allocate         : Ptr64     void* 
   +0x038 FreeEx           : Ptr64     void 
   +0x038 Free             : Ptr64     void 
   +0x040 ListEntry        : _LIST_ENTRY
   +0x050 LastTotalAllocates : Uint4B
   +0x054 LastAllocateMisses : Uint4B
   +0x054 LastAllocateHits : Uint4B
   +0x058 Future           : [2] Uint4B
```

* SingleListHead.Next points to first free pool chunk on singly-linked Lookaside list
* Size of the Lookaside list is limited by Depth (no. of nodes)
* Depth is adjusted periodically by the balance set manager (nt!KeBalanceSetManager) based on the number of hits and misses on the Lookaside list
	* Frequently used Lookaside list => Larger Depth value
	* Initial Depth value = 4 (nt!ExMimimumLookasideDepth)
	* MaximumDepth = 256
* If Lookaside list is full, pool chunk is freed to the appropriate ListHeads list
* Lookaside lists defined for Session pools 
	* Paged Session pools allocations use separate Lookaside lists (nt!ExpSessionPoolLookaside) defined in session space.
	* Max Blocksize of per Session Lookaside list in 0x19 (nt!ExpSesionPoolSmallLists)
	* Session Lookaside lists use `nt!GENERAL_LOOKASIDE` struct
	* Non-paged Session pool used non-paged per processor Lookaside List (PPNPagedLookasideList)
* Lookaside lists are disabled if hot/cold page separation flag (nt!ExpPoolFlags & 0x100) is set
	* Set at boot-up to increase speed
	* Disabled by a timer set in `nt!ExpBootFinishedTimer`

### Large Pool Allocations
* Pool allocations greater than a page, greater than 4080 bytes (+16 header size).
* Handled by nt!ExpAllocateBigPool which calls nt!MiAllocatePoolPages the pool page allocator
* Requested size rounded to pages 
* 'frag' chunk of Blocksize 0x1 and PreviousSize 0 is placed after large pool allocation, indicating that a fragment of the allocation is available for use.
* Excess bytes (request\_size\_rounded\_to\_pages - request size) are inserted into the PoolDescriptor->ListHeads[Blocksize]

KNODE has 4 singly-linked lists
* PagedPoolSListHead for single paged allocations
* NonPagePoolSListHead[3] for page counts 1, 2, 3
* Size of Page Lookaside lists determined by number of physical pages in system

If Lookaside lists cannot be used and allocation bitmap is used to obtain the requested pool pages.
* Bitmap (RTL\_BITMAP) - array of bits indicating memory pages in use
* Bitmap created for every major pool type
* First index holding requested unused pages returned
* Paged pool bitmap in nt!MMPagedPoolInfo

```c
0: kd> dt nt!_MM_Paged_Pool_info
   +0x000 Mutex            : _KGUARDED_MUTEX
   +0x038 PagedPoolAllocationMap : _RTL_BITMAP
   +0x048 FirstPteForPagedPool : Ptr64 _MMPTE
   +0x050 PagedPoolHint    : Uint4B
   +0x058 PagedPoolCommit  : Uint8B
   +0x060 AllocatedPagedPool : Uint8B
```

* Non-paged bitmap in nt!MiNonPagedPoolBitmap
Session pool bitmap in MM\_SESSION\_SPACE

For large pool allocations nt!ExAllocatePoolWithTag requests 8 additional bytes to store the size of the allocation. This value is checked before free for pool overflows.

**Tag** : 4-byte value tagging an allocation to logically identify the driver

### Allocation Algorithm
ExAllocatePoolWithTag is called to allocate pool memory. 
To return a chunk of requested size list check in below order:
* Lookaside lists
* ListHeads
* Page allocated by pool page allocator

```c
PVOID ExAllocatePoolWithTag( POOL_TYPE PoolType,
 SIZE_T NumberOfBytes,
 ULONG Tag)

// call pool page allocator if size is above 4080 bytes
if (NumberOfBytes > 0xff0) { 
	// call nt!ExpAllocateBigPool
}

// attempt to use lookaside lists
if (PoolType & PagedPool) {
	if (PoolType & SessionPool && BlockSize <= 0x19) {
		// try the session paged lookaside list 
		// return on success 
	} else if (BlockSize <= 0x20) {
		 // try the per-processor paged lookaside list
		// return on success 
	} 
	// lock paged pool descriptor (round robin or local node) 
} 
else { // NonPagedPool 
	if (BlockSize <= 0x20) { 
		// try the per-processor non-paged lookaside list 
		// return on success 
	}
	 // lock non-paged pool descriptor (local node) 
} 

// attempt to use listheads lists 
for (n = BlockSize-1; n < 512; n++) {
	 if (ListHeads[n].Flink == &ListHeads[n]) { // empty 
		continue; // try next block size 
	}
	// safe unlink ListHeads[n].Flink 
	// split if larger than needed 
	// return chunk 
} 
// no chunk found, call nt!MiAllocatePoolPages 
// split page and return chunk
```

When searching the ListHeads for the requested Blocksize, If ListHeads[Blocksize] is empty, the algorithm moves on to ListHeads[Blocksize+1] and so on until it finds a chunk. In this case the chunk will have unused space, and therefore will be split. There are two ways to split the returned chunk : 
* Page aligned chunk returned
	* The allocation is made at the top/front

* Not Page aligned
	* Allocation is made at the bottom/back
In both cases, the chunk is split and the unused part is inserted to ListHeads based on the Blocksize.

### Free Algorithm
Since the Pool\_Header struct in the allocation contains PoolType, `nt!ExFreePool` frees chunks to the appropriate list.
This algorithm also tries to merge adjacent chunks to reduce fragmentation.
* If page aligned nt!MiFreePoolPages is called
* \[CHECK\] Entry->BlockSize == NextEntry->PreviousSize
* If previous chunk or next chunk free, coalescing is done

```c
VOID ExFreePoolWithTag( PVOID Entry, 
ULONG Tag)
if (PAGE_ALIGNED(Entry)) {
	// call nt!MiFreePoolPages 
	// return on success 
}
if (Entry->BlockSize != NextEntry->PreviousSize) 
	BugCheckEx(BAD_POOL_HEADER);

if (Entry->PoolType & SessionPagedPool && Entry->BlockSize <= 0x19) { 
	// put in session pool lookaside list 
	// return on success 
} 
else if (Entry->BlockSize <= 0x20) {
	if (Entry->PoolType & PagedPool) {
		// put in per-processor paged lookaside list 
		// return on success 
	} 
	else { // NonPagedPool
		// put in per-processor non-paged lookaside list 
		// return on success 
	} 
} if (ExpPoolFlags & DELAY_FREE) { // 0x200 
	if (PendingFreeDepth >= 0x20) { 
		// call nt!ExDeferredFreePool 
	} 
	// add Entry to PendingFrees list 
} else { 
	if (IS_FREE(NextEntry) && !PAGE_ALIGNED(NextEntry)) {
		// safe unlink next entry 
		// merge next with current chunk 
	} 
	if (IS_FREE(PreviousEntry)) { 
		// safe unlink previous entry 
		// merge previous with current chunk 
	} if (IS_FULL_PAGE(Entry)) 
	// call nt!MiFreePoolPages 
	else { 
	// insert Entry to ListHeads[BlockSize - 1]
	}
}
```

DELAY\_FREE (`nt!ExpPoolFlags` & 0x200) if set, calling ExFreePoolWithTag appends  chunks to be freed to PendingFrees list until the PendingFreeDepth is 0x20.
When the PendingFreeDepth is >= 0x20, ExDefferedFreePool is called to free each node in PendingFrees to respective ListHeads list

```c
VOID ExDeferredFreePool( PPOOL_DESCRIPTOR PoolDesc, 
BOOLEAN bMultipleThreads) 
for each (Entry in PendingFrees) { 
	if (IS_FREE(NextEntry) && !PAGE_ALIGNED(NextEntry)) { 
		// safe unlink next entry 
		// merge next with current chunk 
	} 
	if (IS_FREE(PreviousEntry)) { 
		// safe unlink previous entry 
		// merge previous with current chunk 
	} 
	if (IS_FULL_PAGE(Entry)) 
		// add to full page list 
	else { 
		// insert Entry to ListHeads[BlockSize - 1] 
	} 
} 
for each (page in full page list) { 
	// call nt!MiFreePoolPages 
}
```

Note :
* Insertion to Lookaside and ListHeads are at the head
* Fragment/ split chunk insertions are at the tail
* Allocations are made from the front of the list



### Kernel Pool Attacks

#### ListEntry Flink Overwrite
When a chunk is being allocated from any of the ListHeads list, The LIST\_ENTRY structure of the head is validated.
**assert(ListHead[n].Flink.Blink===ListHead[n] && ListHead[n].Blink.Flink==ListHead[n])**
If only one chunk  is present in the list then, ListHead[n].Flink and ListHead(n).Blink point to the same chunk. Hence both victim.Flink and victim.Blink is checked in the safe unlink. 
But with more than one chunk :
* The next entry'ss Blink [ListHead[n].Flink.Blink) is verified to be be ListHead[n]. This leaves ListHead[n].Flink.Flink unchecked
* Similarly ListHead[n].Blink.Blink is unchecked.
Assuming we have a UAF, and there are more than 1 entry in the ListHead list corresponding to the size of the entry, this allows us to overwrite the victim.Flink
So during the unlink operation the Blink of the fake chunk that we overwrite victim.Flink with, is written with ListHead[n].
The check should instead have been :

```c
victim = Listhead[n].Flink;
assert(victim.Flink.Blink==victim && victim.Blink.FLink==victim);
```
This is similar to what is seen in glibc

#### Lookaside Next Pointer Overwrite

* Singly linked listed with each entry holding pointer to next entry.
* Pool chunk freed into Lookaside list when:
	* BlockSize <= 0x20 (paged/non-paged)
	* BlockSize <= 0x19 (paged session)
	* Lookaside list is not full
	* Hot/cold page separation disabled (ExpPoolFlags & 0x100)
* Pool page is freed to Lookaside list when:
	* NumberOfPages  = 1 for paged pool pages
	* NumberOfPages <= 3 for non-paged pool pages
	* Lookaside list for target page count is not full

**Overwriting the next pointer will give you an arbitrary write like fastbins in  glibc malloc.**
* Next pointer after POOL\_HEADER, hence 16-byte write required.

**Exploit Hinderance:** `nt!MiAllocatePoolPages` is called every time a page is requested by the OS. Therefore heap feng-shui with pool pages is difficult as page allocations are made frequently by other system threads.
When working with pool chunks, we can use infrequently used pool chunk sizes to get more control over the heap layout when triggering the vulnerability.
We examine the  `TotalAllocates` value in the `nt!_GENERAL_LOOKASIDE_POOL` to get the frequency.

#### PendingFrees Next Pointer Overwrite
PendingFree stores all the pool chunks waiting to be freed in a singly linked list.
No integrity checks are performed on this list.
**We can overwrite the next entry in this list and obtain an arbitrary free into the ListHead lists when ExDeferredFreePool is called. After that we can allocate an arbitrary chunk of the ListHeads.**
**Exploit Hindrance:** ExDeferredFreePool is called after about every 32 frees. Many threads are scheduled to the same pool in parallel and multi-core systems. 
Therefore it is likely that a chunk we abused would have been freed into LIstHead and would have satisfied some other request before our request for arbitrary write.
Attacks on PendingFree list of less frequently used session pool is more feasible.

#### PoolIndex Overwrite
The pool chunk is free in to the ListHeads array of the PoolDescriptor denoted by the `POOL_HEADER->PoolIndex`. 
**There is no validation on the PoolIndex; it can be an out of bound index.**
* only 2-byte overflow required. 
* Null page should be mappable.
* For PoolType = Paged pool, PoolIndex indices into `nt!ExpPagedPoolDescriptor` array.
* For PoolType = Non-paged pool, PoolIndex indices into `nt!ExpNonPagedPoolDescriptor` array.
* Unlike retail builds, in checked builds PoolIndex is validated against `nt!ExpNumberOfPagedPools`.

**By overwriting the PoolIndex with an out of bound index a null dereference is triggered. Allocating the null page in userspace and faking the `nt!Pool_descriptor` structure lets us perform all the previously mentioned attacks and more.**

Note: Access to PoolDescriptor->ListHead[n] list is locked so that threads cannot access them at the same time.





