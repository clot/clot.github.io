---
layout: post
title: IDA Plug-in - FRIEND
slug: IDA Plug-in - FRIEND
category: Heap Exploitation
published: true
---


FRIEND作为IDA的一款插件，可以提升反汇编的效果，并且能够在IDA中显示寄存器/指令的提示文档，使IDA更加得心应手。

### 一、安装事项

#### 本实验安装环境：	
MacOS 10.12.6	
Xcode 8.3.3		
IDA 6.8
			
#### 安装过程：
<!-- more -->

1. 下载FRIEND：[FRIEND下载地址](https://github.com/alexhude/FRIEND)
FRIEND插件依赖两个SDK：**idasdk**和**hexrays_sdk**，编译前需要先下载这两个SDK，将内容拷贝到相应目录。否则会出现编译失败。
![IMG](https://ws4.sinaimg.cn/large/006tNc79gy1fjligybo4lj30hg0gy0ud.jpg)

2. 定位到FRIEND目录下，执行以下命令：
```
$ mkdir _build
$ cd _build
$ cmake [-DUSE_HEXRAYS=OFF] ..
$ make
```

3. 在`_build`目录下可以看到相应的二进制文件已经生成：
![IMG](https://ws1.sinaimg.cn/large/006tNc79gy1fjlimmgvx2j30hk0duta2.jpg)

插件生成之后，按照原文的描述，需要复制到`/Applications/IDA Pro 6.95/idabin/plugins`这个目录，但是我发现保存到`idabin/plugins`之后打开ida是找不到这个插件的，我实际保存到的目录是`/Applications/idaq.app/Contents/MacOS/plugins`

再重新打开IDA，点击`Edit` --> `Plugins`就可以看到FRIEND插件了。

### 二、插件的配置
1. 接上一步骤，点击FRIEND，进入插件配置界面：
![IMG](https://ws1.sinaimg.cn/large/006tNc79gy1fjlison27uj30x40rk0uy.jpg)

2. 选择你想要关联的说明文档。在`/FRIEND-master/Configurations`目录下有两个XML文件，这里我们选择`AArch64_armv8arm_k.xml`。导入后，选择自己想要文档化的内容，并勾选下面三个勾，**允许做处理器扩展、允许显示提示、允许显示函数概要**。点击OK。

![IMG](https://ws2.sinaimg.cn/large/006tNc79gy1fjljv5opmsj30x40rk43q.jpg)


配置完成后，来看看效果：

 1. 指令/寄存器的解释，再也不用手动去搜了：
![](https://ws2.sinaimg.cn/large/006tNc79gy1fjmgf1k8oij30xu0gkafa.jpg)

 2. 指令更明了：
![IMG](https://github.com/alexhude/FRIEND/raw/master/Resources/screenshots/proc_ext.png)

 3. 显示函数的概要：
 ![](https://ws4.sinaimg.cn/large/006tNc79gy1fjmgn2egwmj30u00batbu.jpg)

### 三、编辑提示文档

FRIEND还提供了编辑提示文档的功能。使用`FRIEND`中提供的工具`FRIEND Hint Editor`对`/FRIEND-master/Configurations/AArch64_armv8arm_k.xml`进行编辑。

* 这个工具也在`FRIEND-master/`目录下，同样也需要手动创建：

```
$ cd HintEditor/HintEditor/
$ mkdir _build
$ cd _build
$ cmake -G Xcode ..
$ xcodebuild
```

* 创建成功后，在`HintEditor/HintEditor/Debug/`目录下生成了HintEditor.app，运行并打开`AArch64_armv8arm_k.xml`文件，看到如下界面后，便可进行添加、删除、编辑条目的操作了：
![IMG](https://ws4.sinaimg.cn/large/006tNc79gy1fjmbt33g20j31e00t07eq.jpg)

* 记得替换`AArch64_armv8arm_k.xml`文件中的文档指定路径，
![IMG](https://ws2.sinaimg.cn/large/006tNc79gy1fjmg3xas37j318o09yjui.jpg)

* 修改后可以右击条目，选择`Show Documentation`，会调起浏览器访问你所指定的ARM文档，检索你所选中的条目。

![IMG](https://ws1.sinaimg.cn/large/006tNc79gy1fjmg9q9rsrj311m0hqq9a.jpg)

***

**以上就是FRIEND插件的安装、配置和使用。看到这相信你也一定感受到这个插件所带来的便利了吧。**
