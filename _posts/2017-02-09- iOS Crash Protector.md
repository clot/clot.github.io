---
layout: post
title: iOS Crash Protector
slug: iOS Crash Protector
category: iOS Performance
published: true
---

### 概述

在 iOS 开发中，App的崩溃原因有很多种，这篇文章主要阐述我所使用的防止**发送未知消息*(unrecognized selector)***导致崩溃的方法及思路，希望能起到抛砖引玉的作用。若有错误，欢迎指出！

** unrecognized selector sent to instance 0x7faa2a132c0**

调试过程中如果看到输出这句话，我们马上就能知道某个对象并没有实现向他发送的消息。如果是在已经上线的版本中发现的……GAME OVER...（当然你也可以用热修复）


消息发送的机制我们都明白，通过superclass指针逐级向上查找该消息所对应的方法实现。如果直到根类都没有找到这个方法的实现，运行时会通过补救机制，继续尝试查找方法的实现。那么我们能不能通过重写其中的某个方法，来达到不崩溃的目的？

我们先了解下这个补救机制：

![runtime_sendMsg.png](../assets/images/runtime_sendMsg.jpg)

直到最后一步消息无法处理后，我们的App就崩溃了，随后我们就看到了熟悉的unrecognized selector...
这些方法究竟能做什么，我们来看看苹果官方的描述（我对其中比较重要的部分翻译了一下）：

**resolveInstanceMethod:**

**resolveInstanceMethod:** 和 **resolveClassMethod:** 方法允许你为一个给定的 selector 动态的提供方法的实现。
OC 方法在底层的C函数的实现中需要至少两个参数：**self 和 _cmd**。使用** class_addMethod **函数，你能够添加一个函数到一个类来作为方法使用。


**forwardingTargetForSelector:**

如果一个对象实现了这个方法，并且返回了一个非空（以及非 self）的结果，返回的对象会用来作为一个新的接收对象，随后消息会被重新派发给这个新对象。（很明显，如果你在这个方法中返回了self，那这段代码将会坠入无限循环。）
如果你这段方法在一个非 root 的类中实现，并且如果这个类根据给定的selector什么都不作返回，那么你应该返回一个 执行父类的实现后返回的结果。

这个方法为对象在**开销大的多的 forwardInvocation:  方法**接管之前提供了一次转发未知消息的机会。这对你只是想简单的重新定位消息到另一个对象是非常有用的，并且相对普通转发更快一个数量级。如果转发的目的是捕捉到NSInvocation，或者操作参数，亦或者是在转发过程中返回一个值，那这个方法就没有用了。


**forwardInvocation:**

当对象接受到一条自己不能响应的消息时，运行时会给接收者一次机会来把消息委托给另一个接收者。他委托的消息是通过NSInvocation对象来表示的，然后将这个对象作为** forwardInvocation: **的参数。接收者收到** forwardInvocation: **这条消息后可以选择转发这个NSInvacation对象给其他接收对象。（如果这个接收对象也不能响应这条消息，他也会给一次转发这条消息的机会。）

因此 **forwardInvocation:** 允许在两个对象之间通过某个消息来建立关系。转发给其他对象的这种行为，从某种意义上来说，他“继承”了他所转发给的对象的一些特征。

> **注意**
为了响应这个你无法识别的方法，你除了 **forwardInvocation:** 方法外，还必须重写 **methodSignatureForSelector: ** 方法。在转发消息的机制中会从** methodSignatureForSelector: **方法来创建NSInvocation对象。所以你必须为给定的 selector 提供一个合适的 method signature ，可以通过预先设置一个或者向另一个对象请求一个。

以上，是苹果官方文档对这三个关键方法的解释。

### 简而言之:

+ **resolveInstanceMethod: ** 会为对象或类新增一个方法。如果此时这个类是个系统原生的类，比如 **NSArray** ，你向他发送了一条 **setValue: forKey:** 的方法，这本身就是一次错发。此时如果你为他添加这个方法，这个方法一般来说就是冗余的。

+ ** forwardInvocation: ** 必须要经过 **methodSignatureForSelector: ** 方法来获得一个NSInvocation，开销比较大。苹果在** forwardingTargetForSelector **的discussion中也说这个方法是一个相对开销多的多的方法。

+ ** forwardingTargetForSelector: ** 这个方法目的单纯，就是转发给另一个对象，别的他什么都不干，相对以上两个方法，更适合重写。

既然** forwardingTargetForSelector: **方法能够转发给别其他对象，那我们可以创建一个类，所有的没查找到的方法全部转发给这个类，由他来动态的实现。而这个类中应该有一个安全的实现方法来动态的代替原方法的实现。

### 整理下思路:
1. 创建一个接收未知消息的类，暂且称之为 Protector
2. 创建一个 NSObject 的分类
3. 在分类中重写** forwardingTargetForSelector: **，在这个方法中截获未实现的方法，转发给 Protector。并为 Protector 动态的添加未实现的方法，最后返回 Protector 的实例对象。
4. 在分类中新增一个安全的方法实现，来作为 Protector 接收到的未知消息的实现

**上代码：**

创建一个Protector类，没必要new文件出来，动态生成一个就可以了。注意，如果这个方法被执行到两次，连续两次创建同一个类一定会崩溃，所以我们要加一层判断：

```
- (id)forwardingTargetForSelector:(SEL)aSelector
{
    
    Class protectorCls = NSClassFromString(@"Protector");
    if (!protectorCls)
    {
        protectorCls = objc_allocateClassPair([NSObject class], "Protector", 0);
        objc_registerClassPair(protectorCls);
    }
}
```

~~然后我们要为这个类添加方法，在添加方法之前我们也要做一层判断，是否已经添加过这个方法~~（此处文末有更新说明）

```objective
        NSString *selectorStr = NSStringFromSelector(aSelector);
        // 检查类中是否存在该方法，不存在则添加
        if (![self isExistSelector:aSelector inClass:protectorCls])
        {
            class_addMethod(protectorCls, aSelector, [self safeImplementation:aSelector],
                            [selectorStr UTF8String]);
        }
```

这里面有一个** safeImplementation: **方法，其实就是生成一个IMP，然后返回。这里我只是简单的输出一句话：
```
// 一个安全的方法实现
- (IMP)safeImplementation:(SEL)aSelector
{
    IMP imp = imp_implementationWithBlock(^()
    {
        NSLog(@"PROTECTOR: %@ Done", NSStringFromSelector(aSelector));
    });
    return imp;
}
```
**isExistSelector: inClass:**的实现代码如下，主要是根据给定的selector在class中查找，如果找到对应的实现则返回YES：

```
// 判断某个class中是否存在某个SEL
- (BOOL)isExistSelector: (SEL)aSelector inClass:(Class)currentClass
{
    BOOL isExist = NO;
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(currentClass, &methodCount);
    
    for (int i = 0; i < methodCount; i++)
    {
        Method temp = methods[i];
        SEL sel = method_getName(temp);
        NSString *methodName = NSStringFromSelector(sel);
        if ([methodName isEqualToString: NSStringFromSelector(aSelector)])
        {
            isExist = YES;
            break;
        }
    }
    return isExist;
}
```

回到我们的** forwardingTargetForSelector: **方法，接下来就该返回Protector的实例了：
```Objective-C
        Class Protector = [protectorCls class];
        id instance = [[Protector alloc] init];
        
        return instance;
```

但是经过测试，目前的代码还有个问题：App启动时有些系统方法也会经由这个方法转发对象，启动完成就不存在这种问题。所以我们在** forwardingTargetForSelector: **方法中要再加一次判断，如果 self 是我们所关心的类，我们才转发对象，否则返回nil。
以下是 **forwardTargetForSelector: **完整的代码，这里我关心的是UIResponder 和 NSNull这两个类（你也可以添加诸如NSArray\NSDictionary等类）：

```Objective-C
// 重写消息转发方法
- (id)forwardingTargetForSelector:(SEL)aSelector
{
    NSString *selectorStr = NSStringFromSelector(aSelector);
    // 做一次类的判断，只对 UIResponder 和 NSNull 有效
    if ([[self class] isSubclassOfClass: NSClassFromString(@"UIResponder")] ||
        [self isKindOfClass: [NSNull class]])
    {
        NSLog(@"PROTECTOR: -[%@ %@]", [self class], selectorStr);
        NSLog(@"PROTECTOR: unrecognized selector \"%@\" sent to instance: %p", selectorStr, self);
        // 查看调用栈
        NSLog(@"PROTECTOR: call stack: %@", [NSThread callStackSymbols]);

        // 对保护器插入该方法的实现
        Class protectorCls = NSClassFromString(@"Protector");
        if (!protectorCls)
        {
            protectorCls = objc_allocateClassPair([NSObject class], "Protector", 0);
            objc_registerClassPair(protectorCls);
        }
        
        // 检查类中是否存在该方法，不存在则添加
        if (![self isExistSelector:aSelector inClass:protectorCls])
        {
            class_addMethod(protectorCls, aSelector, [self safeImplementation:aSelector],
                            [selectorStr UTF8String]);
        }
        
        Class Protector = [protectorCls class];
        id instance = [[Protector alloc] init];
        
        return instance;
    }
    else
    {
        return nil;
    }
}
```
以上就是所有代码（所以我就不上传DEMO了）。

### 实验结果：

试验中，我对一个label perform了一个未知的方法：callMeTryTry，由于他是一个UIRespnder的子类，所以会进入调用我们的 Protector。控制台输出如下，并且没有崩溃。（所有日志不是真的崩溃时候的日志，前面都带有 PROTECTOR 字样，全都是我代码里的输出），你也可以不进行类的判断试一下，你会看到很多这样的输出。


![console_log.png](../assets/images/console_log.jpg)

以上就是本文全部，希望对各位有帮助，有问题也可以互相交流。

20170214 更新：
**class_addMethod** 方法之前，其实不需要判断是否已添加过这个方法。因为苹果官方文档说 **class_addMethod** 方法只会覆盖父类的方法，或者不存在的方法。如果是已经存在的方法，他不会重复添加或替代。
所以** - (BOOL)isExistSelector: (SEL)aSelector inClass:(Class)currentClass **可以不要了。
