"""Deterministic, read-only file triage for beginners."""
import json
from pathlib import Path

FORMATS=[
 (b'\x89PNG\r\n\x1a\n','PNG 图片',['exiftool','pngcheck','binwalk'],'先查看元数据和完整性，再检查是否嵌入其他格式。'),
 (b'\xff\xd8\xff','JPEG 图片',['exiftool','steghide','stegseek'],'先查看元数据；题目提供隐写密码时再尝试提取。'),
 (b'GIF8','GIF 动画',['exiftool','binwalk'],'先查看元数据和内嵌文件；动画帧需要在图形工具中查看。'),
 (b'PK\x03\x04','ZIP 格式容器',['zipinspect','archive'],'先查看压缩包目录；APK、DOCX 等文件也使用 ZIP 容器。'),
 (b'%PDF-','PDF 文档',['pdfinfo','pdftotext'],'先查看文档属性，再提取可搜索文本。'),
 (b'\x7fELF','ELF 可执行文件',['elf','checksec','strings'],'先静态查看结构、保护和字符串，不要直接执行不明文件。'),
 (b'MZ','Windows 可执行文件线索',['strings','rabin'],'先静态查看字符串和文件信息，必要时打开逆向工作台。'),
 (b'\x0a\x0d\x0d\x0a','PCAPNG 抓包',['capinfos','tshark','httpflows'],'先看抓包概览和协议统计，再查看 HTTP 请求。'),
 (b'\xd4\xc3\xb2\xa1','PCAP 抓包',['capinfos','tshark','httpflows'],'先看抓包概览和协议统计，再查看 HTTP 请求。'),
 (b'\xa1\xb2\xc3\xd4','PCAP 抓包',['capinfos','tshark','httpflows'],'先看抓包概览和协议统计，再查看 HTTP 请求。'),
 (b'SQLite format 3\x00','SQLite 数据库',['file','strings'],'先确认格式，再用数据库查看工具打开副本。'),
 (b'RIFF','RIFF 容器（可能是音频或图片）',['exiftool','file'],'先确认具体格式；WAV 音频可用频谱图工具继续分析。'),
]

def inspect(path):
    p=Path(path)
    with p.open('rb') as f:data=f.read(65536)
    for magic,name,tools,hint in FORMATS:
        if data.startswith(magic):return dict(kind=name,tools=tools,hint=hint,size=p.stat().st_size)
    try:
        text=data.decode('utf-8')
        if not text or sum(c.isprintable() or c.isspace() for c in text)/len(text)>.95:
            return dict(kind='UTF-8 文本线索',tools=['flags','decode','digest'],hint='先找可读内容与 Flag；只有确认是编码文本后再选择对应解码方式。',size=p.stat().st_size)
    except UnicodeDecodeError:pass
    return dict(kind='暂未识别的二进制数据',tools=['file','entropy','strings','binwalk'],hint='先用真实类型、熵分析和字符串工具收集线索，不代表文件损坏。',size=p.stat().st_size)

def run(path,out):
    result=inspect(path)
    (out/'文件识别.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    report=f"识别线索：{result['kind']}\n文件大小：{result['size']} 字节\n下一步：{result['hint']}\n\n这项识别只检查文件头与文本特征，结果是格式线索。请回到新手模式选择对应任务。"
    (out/'下一步建议.txt').write_text(report,encoding='utf-8')
    print(report,flush=True)
