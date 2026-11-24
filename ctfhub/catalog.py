"""Declarative, typed tool adapters. Values are never interpolated into a shell."""
from pathlib import Path
import ipaddress
import json
import re
from urllib.parse import urlsplit

CATEGORIES = {'web': 'Web 安全', 'pwn': 'Pwn 二进制', 'reverse': '逆向分析', 'crypto': '密码与编码', 'misc': 'Misc 隐写', 'forensics': '数字取证', 'awd': 'AWDplus'}

def field(key, label, kind='text', default='', hint='', options=None, required=True):
    return dict(key=key, label=label, type=kind, default=default, hint=hint, options=options or [], required=required)

FILE = field('file', '题目文件', 'file', hint='选择电脑上的文件，或填写 Kali 上的绝对文件路径。')
WORD = field('wordlist', '字典文件', 'file', hint='请选择字典；不会自动猜测或下载大字典。')
URL = field('url', '比赛靶场网址', 'url', hint='例如 http://192.168.56.10:8080/，必须包含 http:// 或 https://。')
HOST = field('host', '比赛靶机地址', 'host', hint='单个 IP 或主机名，不接受网段和命令参数。')
TEXT = field('text', '输入内容', 'textarea')
TOOLS = []

def tool(id, name, category, description, executable=None, package=None, fields=(), args=(), builtin=None, guide='', gui=False, source=None, timeout=300):
    TOOLS.append(dict(id=id, name=name, category=category, description=description, executable=executable, package=package, fields=list(fields), args=list(args), builtin=builtin, guide=guide or '点击执行后查看日志与结果文件；没有匹配结果不代表题目没有隐藏内容。', gui=gui, source=source or (f'https://www.kali.org/tools/{package}/' if package else ''), timeout=timeout))

tool('http', 'HTTP 响应检查', 'web', '查看网页状态、响应头与响应正文。', fields=[URL], builtin='http', guide='适合先确认题目是否在线。响应保存在 response.txt，超时或连接失败会显示原因。')
tool('nmap', 'Nmap 端口识别', 'web', '识别单台靶机的常见 TCP 端口与服务。', 'nmap', 'nmap', [HOST], ['-sT', '-sV', '--top-ports', '100', '--host-timeout', '120s', '-oN', '{out}/nmap.txt', '{host}'])
tool('whatweb', 'WhatWeb 技术识别', 'web', '识别网页使用的服务器和技术组件。', 'whatweb', 'whatweb', [URL], ['--color=never', '--log-json={out}/whatweb.json', '{url}'])
tool('nikto', 'Nikto Web 检查', 'web', '检查常见 Web 服务配置和已知问题。', 'nikto', 'nikto', [URL], ['-h', '{url}', '-maxtime', '120', '-output', '{out}/nikto.txt'])
tool('ffuf', 'ffuf 目录发现', 'web', '用指定字典寻找题目中的隐藏路径。', 'ffuf', 'ffuf', [URL, WORD], ['-u', '{url}/FUZZ', '-w', '{wordlist}', '-t', '10', '-rate', '30', '-maxtime', '120', '-noninteractive', '-of', 'json', '-o', '{out}/ffuf.json'])
tool('gobuster', 'Gobuster 目录发现', 'web', '按照字典探测目录，输出命中的路径。', 'gobuster', 'gobuster', [URL, WORD], ['dir', '-u', '{url}', '-w', '{wordlist}', '-t', '10', '--timeout', '5s', '-o', '{out}/gobuster.txt'])
tool('sqlmap', 'sqlmap 注入检测', 'web', '对指定带参数的比赛 URL 做基础 SQL 注入检测。', 'sqlmap', 'sqlmap', [URL], ['-u', '{url}', '--batch', '--level=1', '--risk=1', '--threads=1', '--timeout=10', '--retries=0', '--output-dir={out}/sqlmap'], guide='填写包含查询参数的题目网址，例如 ?id=1。本预设检测注入点，结果保存在 sqlmap 目录。')
tool('sslscan', 'SSLScan TLS 检查', 'web', '检查 HTTPS 服务支持的协议和证书。', 'sslscan', 'sslscan', [HOST], ['--no-colour', '{host}'])
tool('curl', 'curl 请求详情', 'web', '显示 HTTP 请求的响应头和正文。', 'curl', 'curl', [URL], ['--max-time', '30', '-i', '--url', '{url}'])
tool('burp', 'Burp Suite', 'web', '打开图形化抓包与请求重放工具。', 'burpsuite', 'burpsuite', gui=True, guide='打开独立窗口后，在 Burp 中设置代理并访问题目。启动成功只代表窗口程序已启动。')
tool('zap', 'OWASP ZAP', 'web', '打开图形化 Web 测试工作台。', 'zaproxy', 'zaproxy', gui=True)

tool('elf', 'ELF 文件结构', 'pwn', '查看架构、程序头、节区和符号表。', 'readelf', 'binutils', [FILE], ['-a', '{file}'])
tool('checksec', '二进制保护检查', 'pwn', '通过 pwntools 检查 NX、PIE、Canary 与 RELRO。', 'pwn', 'python3-pwntools', [FILE], ['checksec', '{file}'])
tool('ropgadget', 'ROPgadget 查找', 'pwn', '查找题目文件里的 ROP 指令片段。', 'ROPgadget', 'python3-ropgadget', [FILE], ['--binary', '{file}', '--depth', '5'])
tool('ropper', 'Ropper 查找', 'pwn', '枚举二进制中的可用 gadget。', 'ropper', 'ropper', [FILE], ['--file', '{file}', '--nocolor'])
tool('symbols', '符号表查看', 'pwn', '列出程序中的函数和全局符号。', 'nm', 'binutils', [FILE], ['-C', '{file}'])
tool('disasm', '反汇编查看', 'reverse', '输出程序的静态反汇编，不执行题目程序。', 'objdump', 'binutils', [FILE], ['-d', '{file}'])
tool('rabin', 'Radare2 二进制概览', 'reverse', '查看二进制格式、编译信息和安全属性。', 'rabin2', 'radare2', [FILE], ['-I', '{file}'])
tool('strings', '可读字符串提取', 'reverse', '寻找文件中可读的文本、路径和提示。', 'strings', 'binutils', [FILE], ['-a', '-n', '4', '{file}'])
tool('upx', 'UPX 壳检测', 'reverse', '测试文件是否是有效的 UPX 压缩程序。', 'upx', 'upx-ucl', [FILE], ['-t', '{file}'])
tool('ghidra', 'Ghidra 逆向工作台', 'reverse', '打开图形化反编译工作台。', 'ghidra', 'ghidra', gui=True)
tool('cutter', 'Cutter 逆向工作台', 'reverse', '打开图形化二进制分析工具。', 'cutter', 'rizin-cutter', gui=True)
tool('jadx', 'JADX APK 反编译', 'reverse', '将 APK 或 DEX 反编译到结果目录。', 'jadx', 'jadx', [FILE], ['-d', '{out}/jadx', '{file}'], timeout=900)
tool('apktool', 'Apktool 资源解码', 'reverse', '解码 APK 资源与 Smali 文件。', 'apktool', 'apktool', [FILE], ['d', '-f', '-o', '{out}/apk', '{file}'], timeout=900)

tool('decode', '常见编码转换', 'crypto', '转换 Base64、十六进制和 URL 编码。', fields=[TEXT, field('mode', '转换方式', 'select', 'base64-decode', options=['base64-decode', 'base64-encode', 'hex-decode', 'hex-encode', 'url-decode', 'url-encode', 'rot13'])], builtin='decode')
tool('caesar', '凯撒密码枚举', 'crypto', '一次展示全部 26 种字母偏移结果。', fields=[TEXT], builtin='caesar')
tool('xor', '单字节 XOR 枚举', 'crypto', '枚举十六进制密文的 256 个单字节密钥。', fields=[field('text', '十六进制密文', 'textarea')], builtin='xor')
tool('digest', '文件哈希计算', 'crypto', '计算文件的 MD5、SHA-1 和 SHA-256。', fields=[FILE], builtin='digest')
tool('hashid', 'HashID 类型识别', 'crypto', '根据哈希格式列出可能的算法。', 'hashid', 'hashid', [field('hash', '哈希值')], ['{hash}'])
tool('john', 'John 字典破解', 'crypto', '用字典尝试恢复本地哈希文件对应的密码。', 'john', 'john', [FILE, WORD], ['--wordlist={wordlist}', '--pot={out}/john.pot', '--session={out}/john-session', '{file}'], timeout=900, guide='上传哈希文件和字典。恢复的内容存储在 john.pot，日志会显示命中；最长运行 15 分钟。')
tool('hashcat', 'Hashcat 字典破解', 'crypto', '选择哈希算法后使用指定字典进行离线破解。', 'hashcat', 'hashcat', [FILE, WORD, field('mode', '哈希算法', 'select', '0', options=['0', '100', '1400', '1800', '3200', '1000'])], ['-m', '{mode}', '-a', '0', '--runtime', '600', '--potfile-path', '{out}/hashcat.pot', '--outfile', '{out}/cracked.txt', '{file}', '{wordlist}'], guide='模式编号：0=MD5，100=SHA1，1400=SHA256，1800=sha512crypt，3200=bcrypt，1000=NTLM。需要可用的 OpenCL/CUDA 计算设备。', timeout=900)
tool('openssl', 'OpenSSL 公钥查看', 'crypto', '读取 PEM 公钥的位数与参数。', 'openssl', 'openssl', [FILE], ['pkey', '-pubin', '-in', '{file}', '-text', '-noout'])

tool('file', '文件真实类型', 'misc', '根据文件内容识别格式，不依赖扩展名。', 'file', 'file', [FILE], ['-k', '{file}'])
tool('identify', '不知道用什么？先识别文件', 'misc', '上传文件，获得格式线索和下一步操作建议，不执行题目文件。', fields=[FILE], builtin='identify', guide='先识别文件类型，再从新手模式选择对应任务；文件不会被执行或自动解压。')
tool('entropy', '文件熵与字节分布', 'misc', '计算文件信息熵，辅助判断压缩或加密数据。', fields=[FILE], builtin='entropy', guide='信息熵接近 8 可能来自压缩、加密或随机数据，不能单独作为加密结论。')
tool('zipinspect', 'ZIP 结构查看', 'forensics', '无需安装额外软件，查看 ZIP 内部条目与加密标记。', fields=[FILE], builtin='zipinspect')
tool('exiftool', 'ExifTool 元数据', 'misc', '查看图片、音频、文档中的元数据。', 'exiftool', 'libimage-exiftool-perl', [FILE], ['-a', '-u', '-g1', '{file}'])
tool('binwalk', 'Binwalk 嵌入文件扫描', 'misc', '识别文件内嵌的格式与特征。', 'binwalk', 'binwalk', [FILE], ['{file}'])
tool('zsteg', 'zsteg 图片隐写检查', 'misc', '检查 PNG、BMP 的常见位平面隐藏数据。', 'zsteg', 'zsteg', [FILE], ['-a', '{file}'])
tool('pngcheck', 'PNG 完整性检查', 'misc', '检查 PNG 块结构和 CRC 校验。', 'pngcheck', 'pngcheck', [FILE], ['-v', '{file}'])
tool('steghide', 'Steghide 提取', 'misc', '使用已知密码提取 JPEG、BMP、WAV、AU 隐写。', 'steghide', 'steghide', [FILE, field('password', '隐写密码', 'password', required=False, hint='无密码时留空。')], ['extract', '-sf', '{file}', '-p', '{password}', '-xf', '{out}/hidden.bin', '-f'])
tool('stegseek', 'Stegseek 字典检测', 'misc', '用字典恢复 Steghide 隐藏数据。', 'stegseek', 'stegseek', [FILE, WORD], ['{file}', '{wordlist}', '{out}/hidden.bin'], timeout=900)
tool('outguess', 'OutGuess 提取', 'misc', '尝试提取 JPEG 中的 OutGuess 数据。', 'outguess', 'outguess', [FILE], ['-r', '{file}', '{out}/hidden.bin'])
tool('qr', '二维码读取', 'misc', '识别图片中的二维码和条形码。', 'zbarimg', 'zbar-tools', [FILE], ['--raw', '{file}'])
tool('archive', '压缩包目录检查', 'misc', '列出压缩包文件和加密属性。', '7z', '7zip', [FILE], ['l', '-slt', '{file}'])
tool('audio', '音频频谱图', 'misc', '把音频转换成频谱图，寻找图案或文字。', 'sox', 'sox', [FILE], ['{file}', '-n', 'spectrogram', '-o', '{out}/spectrogram.png'])
tool('audacity', 'Audacity 音频工作台', 'misc', '打开图形化音频与频谱分析工具。', 'audacity', 'audacity', gui=True)

tool('tshark', '流量协议统计', 'forensics', '分析 PCAP 中的协议分布与会话数量。', 'tshark', 'tshark', [FILE], ['-r', '{file}', '-q', '-z', 'io,phs', '-z', 'conv,tcp'])
tool('httpflows', 'HTTP 流量提取', 'forensics', '列出 PCAP 中的 HTTP 请求路径。', 'tshark', 'tshark', [FILE], ['-r', '{file}', '-Y', 'http.request', '-T', 'fields', '-e', 'ip.src', '-e', 'http.host', '-e', 'http.request.uri'])
tool('capinfos', '抓包文件概览', 'forensics', '查看抓包时间、数据量和封装类型。', 'capinfos', 'wireshark-common', [FILE], ['{file}'])
tool('foremost', 'Foremost 文件恢复', 'forensics', '从磁盘镜像或数据流中恢复常见文件。', 'foremost', 'foremost', [FILE], ['-i', '{file}', '-o', '{out}/recovered'], timeout=900)
tool('pdfinfo', 'PDF 信息查看', 'forensics', '查看 PDF 页面、加密与文档属性。', 'pdfinfo', 'poppler-utils', [FILE], ['{file}'])
tool('pdftotext', 'PDF 文本提取', 'forensics', '提取 PDF 可搜索文字。', 'pdftotext', 'poppler-utils', [FILE], ['-layout', '{file}', '{out}/document.txt'])
tool('mmls', '磁盘分区分析', 'forensics', '查看磁盘镜像的分区起止位置。', 'mmls', 'sleuthkit', [FILE], ['{file}'])
tool('fls', '文件系统目录分析', 'forensics', '列出文件系统镜像中的文件与已删除目录项。', 'fls', 'sleuthkit', [FILE], ['-r', '{file}'])
tool('wireshark', 'Wireshark 流量工作台', 'forensics', '打开图形化网络流量分析工具。', 'wireshark', 'wireshark', gui=True)

DIRECTORY = field('directory', '本机源码目录', 'directory', hint='填写 Kali 上已存在的绝对目录路径，例如 /home/kali/challenge。操作针对本机文件。')
tool('baseline', '创建文件基线', 'awd', '记录源码目录每个文件的 SHA-256，作为后续比较依据。', fields=[DIRECTORY], builtin='baseline', guide='生成 baseline.json。修改前先记录基线，之后用“文件变化对比”检查新增、删除与修改。')
tool('compare', '文件变化对比', 'awd', '对照基线检测目录里新增、删除和修改的文件。', fields=[DIRECTORY, field('file', '原始 baseline.json', 'file')], builtin='compare')
tool('sourcecheck', '源码可疑特征检查', 'awd', '按规则定位 PHP、Python、JavaScript 的高风险调用。', fields=[DIRECTORY], builtin='sourcecheck', guide='这是静态特征定位，会有误报和漏报。结果提供文件、行号与命中特征，便于手工判断，不会自动修改源码。')
tool('backup', '源码目录备份', 'awd', '把指定本机目录保存为 ZIP，便于修改前留底。', fields=[DIRECTORY], builtin='backup')
tool('flags', 'Flag 提取与去重', 'awd', '从上传的日志或文本中提取常见格式 Flag。', fields=[FILE, field('prefix', 'Flag 前缀', default='flag', hint='例如 flag 或 ctf；匹配 prefix{内容}，区分大小写。')], builtin='flags')
tool('services', '比赛服务检查', 'awd', '逐个检查手工填写的比赛服务 URL，记录状态和耗时。', fields=[field('urls', '服务 URL（每行一个，最多 30 个）', 'textarea')], builtin='services', timeout=600)

from ctfhub.ctf_adapters import register
CTF_INSTALLERS = register(tool,field,FILE)

for t in TOOLS:
    t['installer'] = 'ctf-'+CTF_INSTALLERS[t['id']] if t['id'] in CTF_INSTALLERS else t['id'] if t['id'] in ('outguess','zsteg') else None
    if t['id'] in CTF_INSTALLERS:
        t['ctf_project'] = CTF_INSTALLERS[t['id']]
        t['guide'] += ' 缺少工具时点击安装，系统依赖经授权安装，工具保存在本项目 data/vendor/ctf 的独立环境；需要联网。'
    elif t['installer']:
        t['package'] = None
        t['source'] = 'https://github.com/' + ('zed-0xff/zsteg' if t['id']=='zsteg' else 'resurrecting-open-source-projects/outguess')
        t['guide'] += ' 此工具使用独立安装器：系统授权仅安装编译依赖，工具本体安装到项目 data/vendor。'

for t in TOOLS:
    t['success_codes'] = [0,1] if t['id']=='hashcat' else [0]

# Base Debian packages often have no dedicated Kali tools documentation page.
resources = Path(__file__).resolve().parent.parent / 'resources'
try:
    index = {i['name'] for i in json.loads((resources/'kali-index.json').read_text(encoding='utf-8'))['tools']}
    packages = json.loads((resources/'kali-packages.json').read_text(encoding='utf-8'))['packages']
    for t in TOOLS:
        package = t['package']
        if package and package not in index:
            homepage = packages.get(package,{}).get('Homepage','')
            t['source'] = homepage if homepage.startswith(('https://','http://')) else f'https://packages.debian.org/stable/{package}'
        if package and packages.get(package,{}).get('component')=='non-free':
            t['guide'] += ' 此包属于 Kali non-free 仓库，安装时需要软件源已启用该组件。'
except (OSError,KeyError,ValueError):
    pass

BY_ID = {t['id']: t for t in TOOLS}

def validate(spec, values):
    if not isinstance(values, dict):
        raise ValueError('参数格式不正确')
    result = {}
    for f in spec['fields']:
        v = values.get(f['key'], f['default'])
        if not isinstance(v, str) or '\x00' in v or len(v) > 200000:
            raise ValueError(f"{f['label']}：内容无效或过长")
        v = v if f['type'] in ('textarea', 'password') else v.strip()
        if not v and f['required']:
            raise ValueError(f"请填写{f['label']}")
        if f['type'] == 'select' and v not in f['options']:
            raise ValueError('选项无效')
        if f['type'] in ('file', 'directory'):
            p = Path(v).expanduser()
            if not p.is_absolute() or (not p.is_file() if f['type'] == 'file' else not p.is_dir()):
                raise ValueError(f"{f['label']}不存在，请选择文件或填写绝对路径")
            v = str(p.resolve())
        if f['type'] == 'url':
            check_url(v)
        if f['type'] == 'host':
            try:
                ipaddress.ip_address(v)
            except ValueError:
                if not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', v):
                    raise ValueError('请输入单个合法 IP 或主机名')
        if f['type'] not in ('textarea', 'password', 'file', 'directory') and v.startswith('-'):
            raise ValueError('输入内容不能以短横线开头')
        result[f['key']] = v
    if spec['id'] == 'flags' and not re.fullmatch(r'[\w-]{1,40}', result['prefix']):
        raise ValueError('Flag 前缀只能包含字母、数字、下划线和短横线')
    if spec['id'] == 'services':
        urls = [u.strip() for u in result['urls'].splitlines() if u.strip()]
        if not 1 <= len(urls) <= 30:
            raise ValueError('请填写 1 至 30 个服务地址')
        for u in urls:
            check_url(u)
    if spec['id'] == 'angr-find':
        from ctfhub.ctf_runners import settings
        settings(result['find'],result['avoid'],result['length'],result['printable'])
    return result

def check_url(v):
    try:
        u = urlsplit(v)
        if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
            raise ValueError()
        u.port
    except ValueError:
        raise ValueError('网址必须是完整的 HTTP/HTTPS 地址，且不包含账号密码') from None

def command(spec, values, out):
    context = dict(values, out=str(out))
    # Replace only registered placeholders, never interpret user braces or shell syntax.
    def expand(arg):
        return re.sub(r'\{(\w+)\}', lambda m: context[m[1]], arg)
    return [spec['executable']] + [expand(a) for a in spec['args']]
