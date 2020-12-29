---
layout: post
title: pwnable.kr - Linux IO
slug: pwnable.kr - Linux IO
category: PWN
published: true
---

还是一道pwnable.kr上的题，总结下涉及到的知识点

```
ssh input2@pwnable.kr -p2222   #password: guest
```

第一关是组装参数，需要100个，第'A'\'B'\'C'个参数需要特别定义

```
    // argv
    
    char *argv[101];
    argv[0] = "/home/input2/input";

    for(int i = 0; i < 101; i++) {
        argv[i] = "x";
    }
    
    argv['A'] = "\x00";
    argv['B'] = "\x20\x0a\x0d";
    argv['C'] = "55555";
```

第二关是IO重定向，这里用`pipe`创建了两个管道，数组中第0个是输出口，第1个是输入口。其中一个输出口重定向到stdin,另一个输出口重定向到stderr。然后通过fork建立一个子进程，在子进程中向输入数据，最终流入stdin和stderr。

```
    if ((childPid = fork()) <0) { exit(-1); }
    if (childPid == 0) {
        // waiting for parent process ready to read
        sleep(1);

        // close read
        close(pipeStdin[0]);
        close(pipeStderr[0]);

        // write data
        write(pipeStdin[1], "\x00\x0a\x00\xff", 4);
        write(pipeStderr[1], "\x00\x0a\x02\xff", 4);

        return 0;

    } else {
        // close write
        close(pipeStdin[1]);
        close(pipeStderr[1]);

        // redirection output to stdin & stderr
        dup2(pipeStdin[0], 0);
        dup2(pipeStderr[0], 
	}
```

第三关需要设置环境变量，环境变量都是`key=value`的格式，所以我们在一个env的数组中，添加两个，一个是对应的value和key，一个是NULL，因为env参数需要一个NULL作为结尾。然后调用`execve`将env变量传入。

```
char *envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe", NULL};
execve("/home/input2/input", argv, envp); //这步execve需要放在所有设置都完成后才执行。
```

第四关是文件读取，这个新建文件，塞入相应的数据即可

```
	FILE *fp = fopen("\x0a", "wb");
    if (!fp) { exit(-1); }
    fwrite("\x00\x00\x00\x00", 4, 1, fp);
    fclose(fp);
    fp = NULL;
```

最后是socket编程，题目代码中的意思是用第C个参数，来设置端口，然后监听，并且判断接收到的数据是不是它所需要的，如果正确就打印flag了。我们需要做的是，建立连接，并往这个端口输送相应的数据即可。可以通过python，也可以通过C编程。这里用的是python, 在服务器上运行exploit打开端口之后，我们再执行。最后获得flag。

```
python -c "print '\xde\xad\xbe\xef' | nc localhost 55555"
```

另外一个问题是ssh到服务器后因为权限问题，只能在新建的目录里操作，所以需要将原目录的flag文件软链接到自己新建的目录中。

```
ln -s /home/input2/flag flag
```
