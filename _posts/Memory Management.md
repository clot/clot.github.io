
# Memory Management

`malloc(size_t size)`

`realloc(void *p, size_t size)`

`calloc(size_t nmemb, size_t size)`

`free(void *p)`

`brk()`

`sbrk()`

`mmap()`

`munmap()`

`tcache (glibc >= 2.26)`

每个线程独立的一块堆空间，减少访问共享数据时候的锁操作。

由64个单链表组成，32b: 12 ~ 512B, 64b: 24 ~ 1032B,每个链表7个chunk。(除了large bin之外都能被存放)

malloc时如果大小满足先会从tcache中找，如果tcache为空，则从bin找（除了large bin），找到后先添加到tcache对应的bin中，直到7个。

free fast bin或者small bin时，会将bin链表中的其他chunk放入tache对应的位置，只要对应的bin链表没有被装满。

double free后两次malloc都时相同地址

```comment
Tcache Index:

    IDX = (CHUNKSIZE - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT
    On a 64 bit system the current values are:
        MINSIZE: 0x20
        MALLOC_ALIGNMENT: 0x10
    So we get the following equation:
    IDX = (CHUNKSIZE - 0x11) / 0x10

BUT be AWARE that CHUNKSIZE is not the x in malloc(x)
It is calculated as follows:
    IF x + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE(0x20) CHUNKSIZE = MINSIZE (0x20)
    ELSE: CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK) 
    => CHUNKSIZE = (x + 0x8 + 0xf) & ~0xf
```

`fast bin`

- 位置：

    独立的数组

- 特点：

    1. single linked list
    2. LIFO
    3. free后"P"位（是否被使用）不置0，不合并
    4. 16 ～ 64+16(B) /bins (total 10 bins)

- 来源：

    第一次从small bin请求，大小不大于MAX_FAST_SIZE,释放后放到fast bin

    `#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)` SIZE_SZ = 4(32b) or 8(64b)

- 使用策略：
    malloc的大小小于MAX_FAST_SIZE

- 合并策略：
    特定的时候释放，并与相邻的合并，放置到unsorted bin中，再放入对应大小的bin中

- 源码注解：

    ```comment
    /*
    Fastbins

    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.

    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
    */
    ```

`unsorted bin`

- 位置：

    bin[1]

- 特点：

    1. 无序排列
    2. FIFO
    3. double linked list
    4. 无大小限制

- 来源：

    1. 当small/large chunk被释放后，大小大于fast bin的MAXSIZE，而且这个chunk不与top chunk相邻
    2. 一个较大的chunk被分割后剩下的部分大于MINSIZE
    3. fast bin空闲块合并后

- 使用策略：

    malloc在查找fast bin之后查找

- 合并策略：

    malloc在遍历list的时候，如果该chunk不合适就被放入对应的bin(small/large)中

- 源码注解：

    ```comment
    /*
   Unsorted chunks

    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free (and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.

    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
    */
    ```

`small bin`

- 位置：

    bin[2 ~ 63]

- 特点：
    1. double linked list
    2. 16 ~ 504B (32b), 32 ~ 1008(64b), index * 8
    3. FIFO

- 使用策略：
    unsorted bin中无合适chunk，且大小小于small bin的max size

- 合并策略：

    合并后放如unsorted bin

`large bin`

- 位置：

    bin[64 ~ 127]

- 特点：
    1. double linked list
    2. 512+ (32b), 1024+ (64b)
    3. FIFO
    4. 每个bin包含了一定范围大小的chunk，从小到大排序。比如，第一个bin包含512～568的chunk。
    5. 前32个bin之间相差64B，接着的16个bin相差512，4096，32768。。以此类推，每个bin内部从大到小排列

- 使用策略：
    大于small bins的max size， 使用时分割成两部分，即用户需要的大小及剩下的chunk，剩下的chunk被添加到unsorted bin中

- 合并策略：
    其中一个chunk释放后既与其相邻的合并

`top chunk`

位于heap最顶部的一块arena区域，不属于任何bin，用于当bin中没有足够大小的空闲块时，如果topchunk的大小足够分配，则会被分割，剩余的部分成为新的top chunk，如果不足以分配，则会通过sbrk(main arena)或者mmap(thread arena)扩展.

- 特点：

    prev_inuse始终为1

- 源码注解：

```comment
/*
   Top

    The top-most available chunk (i.e., the one bordering the end of
    available memory) is treated specially. It is never included in
    any bin, is used only if no other chunk is available, and is
    released back to the system if it is very large (see
    M_TRIM_THRESHOLD).  Because top initially
    points to its own bin with initial zero size, thus forcing
    extension on the first malloc request, we avoid having any special
    code in malloc to check whether it even exists yet. But we still
    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the
    interval between initialization and the first call to
    sysmalloc. (This is somewhat delicate, since it relies on
    the 2 preceding words to be zero during this interval as well.)
 */
```

`last remainder chunk`

当用户请求一个small chunk, small bin 和unsorted bin都没有对应的chunk，在large bin找到对应chunk后，分割后未被使用的那部分就是last remainder chunk，同时也会被放入unsorted bin（topchunk被分割的部分不属于）。

而当第二次请求一个small chunk的时候，如果last remainder chunk是unsorted bin中唯一的一个，它就会再被分割，剩下的依然被添加到unsorted bin中，并成为新的last remiander chunk。所以两次分配的内存都是相邻的。

[Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

[Heap Related Data Structure](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/heap_structure-zh/)

[UNDERSTANDING THE GLIBC HEAP IMPLEMENTATION](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)
