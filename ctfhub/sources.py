"""Upstream reference snapshots and links to the task adapters now available."""
SOURCES = [
    {'repo': 'DasSecurity-HatLab/AoiAWD', 'category': 'awd', 'description': 'AWD 行为监控与可视化，部署需要服务端和靶机探针。'},
    {'repo': 'AabyssZG/AWD-Guide', 'category': 'awd', 'description': 'AWD 比赛指南与脚本参考。'},
    {'repo': 'H4cking2theGate/JarPatcher', 'category': 'awd', 'description': 'Java JAR 补丁框架，需按题目编写补丁。'},
    {'repo': 'zardus/ctf-tools', 'category': 'misc', 'description': 'CTF 工具与安装环境集合。'},
    {'repo': 'apsdehal/awesome-ctf', 'category': 'misc', 'description': '跨类别 CTF 工具和学习资源索引。'},
    {'repo': 'Gallopsled/pwntools', 'category': 'pwn', 'description': '二进制题目分析与利用开发库。'},
    {'repo': 'pwndbg/pwndbg', 'category': 'pwn', 'description': 'GDB/LLDB 调试扩展。'},
    {'repo': 'bata24/gef', 'category': 'pwn', 'description': 'GDB 调试辅助扩展。'},
    {'repo': 'JonathanSalwan/ROPgadget', 'category': 'pwn', 'description': 'ROP 指令片段查找。'},
    {'repo': 'RsaCtfTool/RsaCtfTool', 'category': 'crypto', 'description': 'RSA 题目的密钥分析工具。'},
    {'repo': 'hellman/xortool', 'category': 'crypto', 'description': '重复密钥 XOR 分析。'},
    {'repo': 'GCHQ/CyberChef', 'category': 'crypto', 'description': '编码与数据转换工作台；源码需构建，不是直接可用的发行包。'},
    {'repo': 'angr/angr', 'category': 'reverse', 'description': '符号执行与二进制分析框架。'},
    {'repo': 'NationalSecurityAgency/ghidra', 'category': 'reverse', 'description': '图形化逆向与反编译平台。'},
    {'repo': 'volatilityfoundation/volatility3', 'category': 'forensics', 'description': '内存取证框架，分析可能需要额外符号文件。'},
    {'repo': 'RickdeJager/stegseek', 'category': 'misc', 'description': 'Steghide 字典恢复。'},
    {'repo': 'zed-0xff/zsteg', 'category': 'misc', 'description': 'PNG/BMP 位平面隐写检测。'},
    {'repo': 'sqlmapproject/sqlmap', 'category': 'web', 'description': 'SQL 注入检测工具。'},
    {'repo': 'ffuf/ffuf', 'category': 'web', 'description': 'Web 路径与参数 fuzzing 工具。'},
    {'repo': 's0md3v/XSStrike', 'category': 'web', 'description': 'XSS 分析工具。'},
]

def annotate(items):
    from ctfhub.catalog import BY_ID
    from ctfhub.featured import listing
    mapping={p['url'].removeprefix('https://github.com/').lower():p['tools'] for p in listing()['projects']}
    mapping.update({'sqlmapproject/sqlmap':['sqlmap'],'ffuf/ffuf':['ffuf'],'nationalsecurityagency/ghidra':['ghidra']})
    return [dict(item,adapted_tools=[dict(id=id,name=BY_ID[id]['name']) for id in mapping.get(item['repo'].lower(),[])]) for item in items]
