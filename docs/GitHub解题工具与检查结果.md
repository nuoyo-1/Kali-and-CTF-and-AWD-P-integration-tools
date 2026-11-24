# GitHub 解题工具与本轮检查

本轮按题型与可封装性选择工具，没有可核实的“所有 CTF 通用最强工具”排名。新增6个项目的12个专用入口，CTF精选合计74项；新增6个任务引导，新手模式合计25项。GitHub解题精选按密码、Pwn、逆向、隐写与压缩包、取证分组，共12个项目卡片，其中10个有本地执行入口，2个只作参考链接。已有的4个项目复用原入口，不重复登记相同功能。Web和AWDplus功能仍在原CTF分类与Kali全工具页中。

| 分类 | 项目 | 可执行功能 | 安装方式 |
| --- | --- | --- | --- |
| 密码 | [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) | 弱RSA私钥恢复、公钥与密文分析 | 固定提交源码安装到独立Python环境 |
| 密码 | [xortool](https://github.com/hellman/xortool) | 重复XOR密钥长度、明文候选 | 固定PyPI版本 |
| 隐写与压缩包 | [bkcrack](https://github.com/kimci86/bkcrack) | ZIP条目与加密类型、已知明文分析 | 固定源码在Kali编译 |
| 逆向 | [angr](https://github.com/angr/angr) | 指定成功分支与输入长度，寻找候选输入 | 固定PyPI版本，Python 3.12+ |
| 数字取证 | [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Windows系统信息、进程列表、进程关系树 | 固定PyPI版本 |
| 数字取证 | [oletools](https://github.com/decalage2/oletools) | Office容器风险概览、VBA静态分析 | Kali APT |
| Pwn | pwntools、ROPgadget | 复用保护检查与指令片段查找 | 原有APT适配 |
| 图片隐写 | zsteg、Stegseek | 复用位平面检查、字典提取 | 原有Ruby安装器或APT |

CyberChef仅提供官方在线页面链接，本版没有安装其离线发行包，平台不会自动传输题目数据。Ciphey上游出现Rust版本，与Kali快照中的Python版本参数不同，因此暂保留参考链接，不计作新增本地功能。原“上游源码库”的状态也已同步：有专用功能的项目会显示实际功能数量，未接入的项目仍明确标为源码参考。

## 安装与版本

点击工具表单中的“安装工具”即可。APT只负责固定的系统依赖，授权由Kali系统窗口处理；第三方Python环境和bkcrack二进制保存在`data/vendor/ctf/<项目>/`。请用普通Kali用户双击启动平台。安装需要联网，当前Python/CPU架构是否有兼容依赖仍由实际安装结果决定，不会绕过兼容性限制。

RsaCtfTool的PyPI 1.1版限制Python 3.8，不能直接用于新版Kali，因此本版使用已收集的固定提交源码。xortool、angr、Volatility固定直接包版本，间接依赖在线解析；安装后保存`dependencies.txt`。清单内的GitHub提交是资料快照的版本，PyPI发行版本可能来自不同提交，二者不会冒充同一份二进制。各项目资料、源码ZIP及SHA-256位于`resources/ctf-projects/manifest.json`，ZIP不在Windows展开。源码许可证保留在对应上游ZIP中，APT和PyPI安装也保留其包内许可。

RsaCtfTool只适用弱RSA，部分攻击需要额外SageMath，部分可能联网查询FactorDB。bkcrack针对ZipCrypto而非AES ZIP，需要至少12字节已知明文、其中8字节连续；压缩条目的明文数据还必须相匹配。angr需要人工确定成功地址、输入长度与PIE基址，限制90秒、3000步、1024个活动状态，返回的是所建模型的候选输入。Volatility的这些预设针对Windows镜像，可能需要联网下载符号；没有把Linux/macOS符号配置伪装为自动完成。

## 检查结论

52项标准库自动测试通过，覆盖原平台流程、完整官方目录、名称去重、分类、输入边界、新增参数数组、源码哈希、安装器白名单、参考资源状态及来源页一致性。真实Chrome浏览器验收通过：新手演示执行与下载、781个官方条目、2740个独立命令按钮、12个GitHub项目卡片、RSA双文件表单、取证分类筛选、20个原始来源卡片，以及桌面和移动端布局；没有JavaScript异常。

在项目独立的Windows验证环境中安装了清单固定的xortool、angr和Volatility版本，实际检查结果是：xortool从重复密钥XOR样例恢复出完全一致的原文；angr从一个仅读取1字节并比较字母的ELF测试程序中求出了正确输入A；Volatility接受windows.pslist插件并展示其参数。ELF只交给angr模拟，没有在本机原生执行。可选复验脚本是`scripts/verify_ctf_runtime.py`，不属于日常用户操作，也不要求用户安装测试环境。

实测发现并修复了新版angr的claripy导入路径变化，同时把求解超时设置到实际求解器；修复了Windows预览反复查询外部命令导致页面加载慢的问题；同步了来源页中已接入项目的说明和安装后卡片状态。原来仅靠参数结构检查不会发现angr运行错误，因此实际样例求解是本轮补充的重要检查。

尚未完成的验证：Kali上的APT与pkexec授权、bkcrack本地编译、RsaCtfTool完整依赖与攻击结果、Office样本分析，以及Volatility真实内存镜像与符号加载。本轮结果不能替代这些Kali实测，也不代表2751个外部程序全部运行验证过。分发包会另外检查每份源码ZIP、逐文件清单与整体SHA-256，排除本机data、验证环境和review资料。
