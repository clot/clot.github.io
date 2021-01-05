---
layout: post
title: Reverse Engineering (ARM)
slug: Reverse Engineering (ARM)
category: REVERSE
published: true
---

```bash
Download : http://pwnable.kr/bin/leg.c
Download : http://pwnable.kr/bin/leg.asm

ssh leg@pwnable.kr -p2222 (pw:guest)
```

这题主要考一些基本的ARM知识，比较简单。

下载文件可以看到源码c文件和调试时打印的反编译后的内容。源码文件中有三个关键函数是用汇编写的，只要计算出这三个函数的返回值之和就行。

```c
int key1(){
    asm("mov r3, pc\n");
}
int key2(){
    asm(
"push {r6}\n"
"add r6, pc, $1\n"
"bx r6\n"
".code   16\n"
"mov r3, pc\n"
"add r3, $0x4\n"
"push {r3}\n"
"pop {pc}\n"
".code 32\n"
"pop {r6}\n"
    );
}
int key3(){
 asm("mov r3, lr\n");
}
```

要点：

1. 调试时候显示的pc值是将要执行的pc指令地址，但是如果是指令中从pc读取，则读取的是当前指令的下下条指令。比如：

```bash
0x00008cdc <+8>: mov r3, pc
0x00008ce0 <+12>: mov r0, r3
0x00008ce4 <+16>: sub sp, r11, #0
```

 当执行`0x00008cdc`语句时，pc的内容实际是`0x00008ce4`，而非当前的`0x00008cdc`。
2. 这类是跳入THUMB指令的标识，寄存器值末尾置为1，用`BX`跳转，切换指令模式

```c
0x00008cfc <+12>: add r6, pc, #1
0x00008d00 <+16>: bx r6
```
  
3. `r11`是 fp，类似于`ebp`, `lr`指向ret的地址，也就是调用函数返回后执行的下一条指令的地址。

    这三个函数的返回值(r0)都只是涉及到pc值的读取，so ez.
