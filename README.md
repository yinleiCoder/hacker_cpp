# 成为绝顶Hacker之路
`编程绝对不是靠看书能够学会的。本仓库从攻防2个角度来学习黑客编程的知识，通过一系列知识体系完成”黑客编程“的养成计划！`
- 了解攻击者的攻击思路，理解攻击是怎样开展的并独立思考和探索
- 攻击工具和技术

## 开发环境
`注：Jetbrains PyCharm，推荐Eval Reset Plugin.`
- VisualStudio 2022
- Clion
- CMake
- VMWare Workstation Pro16
- [Windows操作系统(Win11)](https://mp.weixin.qq.com/s?__biz=MzU2NzkxMzg2NQ==&mid=2247484028&idx=1&sn=0c80023581971ed1c9efdda438547025&chksm=fc94be9acbe3378cf2da2e4c6d5fd1c8c3a2459d745309ef9876292fae62a67b1761e30abfe5&token=1365422365&lang=zh_CN#rd)

## “脚本小子”script kiddie是什么？
`用别人写的程序的人，即只会使用工具的黑客。script kiddle是一个贬义词，用来描述以黑客自居并沾沾自喜的初学者。`

## 备受关注的黑客(Hacker)到底是什么?
`热衷研究、撰写程序的专才，精通各种计算机语言和系统，且必须具备乐于追根究底、穷究问题的特质。最早是指专门研究、发现计算机和网络漏洞的计算机爱好者。不同于script boy,黑客是要会编写程序的。那么，就请抛开以前当工具黑客的想法，开始学习编写程序吧！`

## 成为绝顶Hacker之前的思想准备
`抛开用工具的想法，其实是让我们抛开浮躁的想法，认真地学习一些真正的技术，哪怕只是一些入门的知识。黑客需要有创新、研发的精神，如果只是做一个只会用软件的应用级的计算机使用者，那么必定永远达不到黑客级的水平，因为工具人人都会用，而你只是比别人多知道几个工具而已。抛开浮躁，静下心来从头开始学习基础，为将来的成长做好足够的准备！`

## 攻防的广义性
`Hacker做的最多的就是“入侵”。“入侵”指的是在非授权的情况，试图存取信息、处理信息或破坏系统以使系统不可靠、不可用的故意行为。Hacker所以做的入侵指的是网络（系统）、软件的入侵。`

## 黑客编程、普通的应用程序编程的区别
`黑客编程(安全编程)，采用常规的编程技术，编写网络安全、黑客攻防类的程序、工具；其与普通的编程技术并没有本质的差别，只是开发的侧重点不同。普通的编程注重的是客户的需求，黑客编程注重的是攻与防。`
- 常见的网络攻击程序：扫描器、嗅探器、后门等
- 常见的网络防范程序：杀毒软件、防火墙、主动防御系统等
- 常见的软件攻击程序：查壳器、动态调试器、静态分析器、补丁等
- 常见的软件防范程序：壳、加密狗、电子令牌等

## 仓库文件夹及文件说明
`本仓库主要存放cpp及hacker实战的相关代码,适用于计算机系网络安全空间、信息安全等专业的本科生、研究生。`
- 黑客编程入门【Windows消息、Windows消息机制的处理、模拟鼠标键盘按键的操作、通过消息实现进程间通信、VisualStudio开发辅助工具】
- 黑客网络编程【Winsock编程、密码暴力猜解剖析、非阻塞模式开发、原始套接字的开发】
- 黑客Windows API编程【API函数、病毒和对病毒的免疫、注册表编程、服务相关的编程、进程与线程、DLL编程】
- 黑客内核驱动开发【驱动程序装载工具实现、内核下的文件操作、内核下的注册表操作】
- 黑客逆向【x86汇编语言、逆向调试分析工具、逆向反汇编分析工具、C语言代码逆向、扫雷游戏辅助工具】
- 黑客加密与解密【PE文件结构、PE查看器、查壳工具、地址转换器、破解及调试API函数、调试API函数的使用、密码显示器、KeyMake工具】
- 黑客Hook技术【Hook技术、内联钩子、导入地址表钩子、Windows钩子函数】
- 黑客剖析【恶意程序编程技术剖析、黑客工具编程技术剖析、反病毒编程技术、实现引导区解析工具、加壳与脱壳、驱动下的进程遍历、HOOK SSDT】
- 黑客安全【网络安全、网络中的破解、Web安全】
- Android软件安全【android可执行文件格式解析、Dex文件格式解析工具】
- Windows用户态【运行单一实例、DLL延迟加载、资源释放】
- Windows注入技术【全局钩子技术、远线程注入、突破SESSION 0隔离的远线程注入、APC注入】
- Windows启动技术【创建进程API、突破SESSION 0隔离创建用户进程、内存直接加载运行】
- Windows自启动技术怕【注册表、快速启动目录、计划任务、系统服务】
- Windows提权技术【进程访问令牌权限提升、Bypass UAC】
- Windows隐藏技术【进程伪装、傀儡进程、进程隐藏、DLL劫持】
- Windows压缩技术【数据压缩API、ZLIB压缩库】
- Windows加密技术【Windows自带的加密库、Crypto++密码库】
- Windows传输技术【Socket通信、FTP通信、HTTP通信、HTTPS通信】
- Windows实用功能技术【进程遍历、文件遍历、桌面截屏、按键记录、远程CMD、U盘监控、文件监控、自删除】
- Windows内核【搭建环境、驱动程序的开发与调试、驱动无源码调试、32位和64位驱动开发】
- Windows文件管理技术【内核API、IRP、NTFS解析】
- Windows注册表管理技术【内核API、HIVE文件解析】
- Windows Hook技术【SSDT Hook、过滤驱动】
- Windows监控技术【进程创建监控、模块加载监控、注册表监控、对象监控、Minifilter文件监控、WFP网络监控】
- Windows反监控技术【反进程创建监控、反线程创建监控、反模块加载监控、反注册表监控、反对象监控、反Minifilter文件监控】
- Windows内核功能技术【过PatchGuard的驱动隐藏、过PatchGuard的进程隐藏、TDI网络通信、强制结束进程、文件保护、文件强删】
- 渗透测试与红队的攻击工具(活动目录攻击、Kerberos攻击、网站攻击高级技术、更好的横向渗透方法、云漏洞、快速和智能口令破解、使用系统凭证和合法软件开展攻击、横向移动攻击、多种定制试验环境、新出现网站漏洞、物理攻击、权限提升、PowerShell攻击、勒索攻击、红队与渗透测试、搭建红队所需的基础设施、红队效果评估、开发恶意软件和规避杀毒软件)【搭建外部服务器、Metasploit框架、Cobalt Strike、PowerShell Empire、dnscat2、p0wnedShell、Pupy Shell、PoshC2、Merlin、Nishang】
- 红队侦察(网络扫描)【监控环境、云扫描、子域名发现】
- 网站应用程序漏洞利用(网络漏洞利用)【漏洞、Web攻击】
- 突破网络【从网络外部查找凭证、在网络中移动、在没有凭证的网络上、没有凭证的用户枚举、CrackMapExec扫描网络、突破主机、权限提升、工作在Windows域环境中、转储域控制器散列、横向迁移、权限提升】
- 社会工程学【开展SE行动、网络钓鱼、内部Jenkins漏洞和社会工程攻击结合】
- 物理访问攻击【复制读卡器、绕过进入点的物理工具、Packet Squirrel、Bash Bunny、WiFi】
- 规避杀毒软件检测【构建键盘记录器、Metasploit/Meterpreter规避杀毒软件和网、SharpShooter、应用程序白名单规避、代码洞穴、PowerShell混淆、没有PowerShell的PowerShell、HideMyPS】
- 破解、利用和技巧【自动化、密码破解、彻底破解全部、禁用PS记录、从本地管理员获取系统权限、在不触及LSASS的情况下获取NTLM散列值、防御工具构建培训实验室和监控平台】
- 红队分析报告


## 推荐B站UP主
`以下均是素未蒙面的各领域的启蒙老师或本人觉得十分干货的UP主，感谢各位前辈！`
- [(公务员)刘文超](https://space.bilibili.com/300722822/video)
- [(公务员)面试学长](https://space.bilibili.com/49642553/video)
- [(英语)英语兔](https://space.bilibili.com/483162496/video)
- [(计算机网络及Cisco Packet Tracer)湖科大教书匠](https://space.bilibili.com/360996402/channel/series)
- [(C)谭玉刚](https://space.bilibili.com/41036636/channel/detail?cid=161507&ctype=0)
- [(C++、算法)代码随想录](https://space.bilibili.com/525438321/video)
- [(C++、C、Kotlin)bennyhuo不是算命的](https://space.bilibili.com/28615855/video)
- [(C++、算法)花花酱的表世界](https://space.bilibili.com/9880352/video)
- [(C++)Cherno](https://www.bilibili.com/video/BV1VJ411M7WR?spm_id_from=333.999.0.0)
- [(OpenGL)Cherno](https://www.bilibili.com/video/BV1MJ411u7Bc?spm_id_from=333.999.0.0)
- [(游戏引擎开发)Cherno](https://www.bilibili.com/video/BV1KE41117BD?spm_id_from=333.999.0.0)
- [(C)编程日课DailyCoding](https://space.bilibili.com/494537125/)
- [(全栈)free-coder](https://space.bilibili.com/31273057/video)
- [(Go)橙卡](https://space.bilibili.com/10/video)
- [(Go)幼麟实验室](https://space.bilibili.com/567195437/video)
- [(Java)颜群](https://space.bilibili.com/326782142/video)
- [(人工智能)跟李沐学A](https://space.bilibili.com/1567748478/?spm_id_from=333.999.0.0)
- [(人工智能)同济子豪兄](https://space.bilibili.com/1900783/video)
- [(前端)CodingStartup起码课](https://space.bilibili.com/451368848/)
- [(前端)峰华前端工程师](https://space.bilibili.com/302954484/)
- [(前端)向军大叔](https://space.bilibili.com/282190994/video)
- [(Android)longway777](https://space.bilibili.com/137860026/video)
- [(Android)扔物线](https://space.bilibili.com/27559447/video)
- [(iOS)Xiaoyouxinqing](https://space.bilibili.com/502566212/video)
- [(Flutter)ducafecat](https://space.bilibili.com/404904528/video)
- [(硬件)硬件茶谈](https://space.bilibili.com/14871346/video)
- [(嵌入式)太极创客](https://space.bilibili.com/103589285/video)
- [(理财)DeltaF](https://space.bilibili.com/31721731/video)
- [(吉他)吉他情报局](https://space.bilibili.com/103600069/video)

## 申明
`由于技术的两面性，希望各位coder有一个良好的学习心态，本仓库的代码仅供学习参考与交流，把学到的技术用到安全保护上！请勿使用自己的知识做出有碍公德之事，在准备通过技术手段进行蓄意破坏时，请想想无数“高手”的下场！`

### —— Google.End@YinLei.Coder ——
