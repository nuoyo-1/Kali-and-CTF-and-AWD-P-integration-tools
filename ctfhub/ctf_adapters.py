"""Task-specific adapters for selected upstream projects; no shell commands."""

def register(tool, field, file_field):
    rsa='https://github.com/RsaCtfTool/RsaCtfTool'
    note='用于存在弱点的 RSA 题，不保证恢复。部分算法需要额外 SageMath；默认安装不包含 SageMath。某些因数分解算法可能联网查询 FactorDB。'
    tool('rsa-private','RsaCtfTool · 弱 RSA 私钥恢复','crypto','上传 PEM 公钥，尝试常见弱 RSA 分解和私钥恢复。','RsaCtfTool',fields=[field('key','RSA 公钥（PEM）','file')],args=['--publickey','{key}','--private','--timeout','90'],source=rsa,timeout=180,guide=note+' 看日志中的私钥或因数；没有结果时需要根据题目分析 RSA 参数。')
    tool('rsa-decrypt','RsaCtfTool · 弱 RSA 密文恢复','crypto','同时提供公钥和原始密文字节文件，尝试恢复明文。','RsaCtfTool',fields=[field('key','RSA 公钥（PEM）','file'),field('cipher','原始密文字节文件','file',hint='不是十进制 c 数字文本；可先用编码转换生成原始字节。')],args=['--publickey','{key}','--decryptfile','{cipher}','--timeout','90'],source=rsa,timeout=180,guide=note+' 成功时日志展示候选明文；超时只表示本次未完成。')
    xor='https://github.com/hellman/xortool'
    tool('xortool-length','xortool · XOR 密钥长度分析','crypto','分析重复密钥 XOR 密文，估计可能的密钥长度。','xortool',fields=[file_field],args=['{file}'],source=xor,guide='上传原始二进制密文；查看可能长度与置信提示，然后用“XOR 明文候选”继续。长度只是统计线索。')
    tool('xortool-guess','xortool · XOR 明文候选','crypto','指定明文最常见字节，推测重复 XOR 密钥并生成候选。','xortool',fields=[file_field,field('common','猜测明文最常见字节','select','20',hint='20=英文文本的空格；00=某些二进制中的零字节。假设错误会产生无意义输出。',options=['20','00'])],args=['-c','{common}','{file}'],source=xor,guide='查看日志里的候选密钥及 xortool_out 结果目录。统计推测不是确定解密，需判断文件内容和题目提示。')
    bk='https://github.com/kimci86/bkcrack'
    tool('bkcrack-list','bkcrack · ZIP 加密类型检查','misc','查看 ZIP 中的条目、压缩方法及加密方式。','bkcrack',fields=[file_field],args=['-L','{file}'],source=bk,guide='记录内部条目名称，确认是否为传统 ZipCrypto；AES ZIP 不适用已知明文分析。列出条目不会恢复密码。')
    tool('bkcrack-known','bkcrack · ZIP 已知明文分析','misc','提供加密 ZIP 和对应明文 ZIP，尝试恢复 ZipCrypto 内部密钥。','bkcrack',fields=[field('encrypted','加密 ZIP','file'),field('cipher_entry','加密 ZIP 内的条目名称',hint='先用 ZIP 加密类型检查查看完整名称，大小写要一致。'),field('plain','已知明文 ZIP','file'),field('plain_entry','明文 ZIP 内对应条目名称',hint='压缩后的明文字节必须与加密条目相匹配；通常需要相同内容与压缩方法。')],args=['-C','{encrypted}','-c','{cipher_entry}','-P','{plain}','-p','{plain_entry}'],source=bk,timeout=600,guide='需要至少12个已知明文字节，其中8个连续；压缩条目须匹配压缩后的数据。结果是3个内部密钥，不一定是原密码。本预设只分析并记录密钥，不自动覆盖 ZIP。')
    tool('angr-find','angr · 指定成功地址求输入','reverse','对 ELF 的固定长度标准输入做符号执行，寻找能到达指定地址的候选。','python',fields=[file_field,field('find','成功分支地址',hint='先用反汇编确定地址，如 0x401234。PIE 程序填写 angr 映射后的地址，不能直接填写文件偏移。'),field('avoid','失败分支地址（可留空）',required=False),field('length','输入字节长度',default='32',hint='1～256；不自动追加换行。'),field('printable','仅搜索可打印 ASCII','select','yes',options=['yes','no'])],args=['-u','-m','ctfhub.ctf_runners','angr-find','{file}','{find}','{avoid}','{length}','{printable}'],source='https://github.com/angr/angr',timeout=120,guide='进阶任务：必须自己确定成功地址和输入长度。限定90秒、3000步和1024个活动状态；只返回本预设模型的候选输入，不保证适用于任意程序，也不调用 AI。')
    vol='https://github.com/volatilityfoundation/volatility3'
    for id,name,plugin,tip in [('info','系统信息','windows.info','检查内存镜像是否识别为 Windows，并读取内核信息。'),('pslist','进程列表','windows.pslist','查看进程名、PID、父进程和时间。单独看到陌生进程不等于恶意。'),('pstree','进程关系树','windows.pstree','沿父子关系定位可疑进程；继续分析需要结合题目线索。')]:
        tool('vol-'+id,'Volatility 3 · '+name,'forensics',tip,'vol',fields=[field('file','Windows 内存镜像','file',hint='超过256 MiB请填写 Kali 本机绝对路径，避免重复上传大镜像。')],args=['-f','{file}',plugin],source=vol,timeout=600,guide=tip+' 初次可能联网下载符号；符号缺失、镜像损坏或系统类型不匹配会失败。本预设针对 Windows，不自动适配 Linux/macOS 符号。')
    ole='https://github.com/decalage2/oletools'
    tool('olevba','oletools · Office 宏提取分析','forensics','静态提取 Office 文档中的 VBA 宏和可疑特征，不执行宏。','olevba','oletools',[file_field],['{file}'],source=ole,guide='查看 VBA 源码、自动执行触发点、可疑字符串和 IOC。可疑标签是线索；没有提取出宏可能是文档无宏或格式不支持。')
    tool('oleid','oletools · Office 文档风险概览','forensics','检查 Office 容器、宏、加密和嵌入对象等属性。','oleid','oletools',[file_field],['{file}'],source=ole,guide='先确认文档类型与是否含宏，再使用 Office 宏提取分析；全程静态读取，不启动 Office。')

    installers={'rsa-private':'rsa','rsa-decrypt':'rsa','xortool-length':'xor','xortool-guess':'xor','bkcrack-list':'bkcrack','bkcrack-known':'bkcrack','angr-find':'angr','vol-info':'volatility','vol-pslist':'volatility','vol-pstree':'volatility'}
    return installers
