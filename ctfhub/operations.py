"""Built-in operations, executed in isolated task processes."""
import base64
import codecs
import hashlib
import json
import math
from collections import Counter
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MAX_FILE = 64 * 1024 * 1024

def save(out, name, value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
    (out / name).write_text(text, encoding='utf-8')
    print(text[:120000], flush=True)

def read(path):
    p = Path(path)
    if p.stat().st_size > MAX_FILE:
        raise ValueError('此内置功能单文件限制为 64 MiB；请使用对应专业工具处理大文件')
    return p.read_bytes()

def files(directory, out):
    root = Path(directory).resolve()
    platform_data = Path(os.environ.get('CTF_DECK_DATA', str(Path(__file__).resolve().parent.parent / 'data'))).resolve()
    count = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(parent) / d).is_symlink() and not (Path(parent) / d).resolve().is_relative_to(platform_data) and not (Path(parent) / d).resolve().is_relative_to(out.resolve()))
        for name in sorted(names):
            p = Path(parent) / name
            if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):
                continue
            count += 1
            if count > 20000:
                raise ValueError('目录超过 20000 个文件，请缩小范围')
            yield p, str(p.relative_to(root))

def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def http(url):
    start = time.monotonic()
    req = urllib.request.Request(url, headers={'User-Agent': 'CTF-Deck/1.0'})
    try:
        response = urllib.request.urlopen(req, timeout=12)
    except urllib.error.HTTPError as error:
        response = error
    with response as r:
        body = r.read(2 * 1024 * 1024)
        return {'url': url, 'status': r.status, 'elapsed_ms': round((time.monotonic()-start)*1000), 'headers': dict(r.headers), 'body': body.decode('utf-8', 'replace'), 'body_limit': '最多读取 2 MiB'}

def run(operation, v, out):
    out = Path(out)
    if operation == 'identify':
        from ctfhub.identify import run as identify
        identify(v['file'],out)
    elif operation == 'http':
        result = http(v['url'])
        save(out, 'response.txt', f"HTTP {result['status']} · {result['elapsed_ms']} ms\n" + json.dumps(result, ensure_ascii=False, indent=2))
    elif operation == 'services':
        results = []
        for url in filter(None, map(str.strip, v['urls'].splitlines())):
            try:
                r = http(url)
                r.pop('body')
            except Exception as e:
                r = dict(url=url, error=str(e))
            results.append(r)
            print(json.dumps(r, ensure_ascii=False), flush=True)
        save(out, 'services.json', results)
        if all('error' in r for r in results):
            raise ValueError('所有服务均连接失败，请查看 services.json')
    elif operation == 'decode':
        raw, mode = v['text'], v['mode']
        actions = {
            'base64-decode': lambda: base64.b64decode(''.join(raw.split()), validate=True),
            'base64-encode': lambda: base64.b64encode(raw.encode()),
            'hex-decode': lambda: bytes.fromhex(raw),
            'hex-encode': lambda: raw.encode().hex().encode(),
            'url-decode': lambda: urllib.parse.unquote_to_bytes(raw),
            'url-encode': lambda: urllib.parse.quote(raw).encode(),
            'rot13': lambda: codecs.encode(raw, 'rot_13').encode(),
        }
        data = actions[mode]()
        (out / 'decoded.bin').write_bytes(data)
        save(out, 'result.txt', data.decode('utf-8', 'replace'))
    elif operation == 'caesar':
        lines = []
        for shift in range(26):
            s = ''.join(chr((ord(c)-(65 if c.isupper() else 97)+shift)%26+(65 if c.isupper() else 97)) if c.isascii() and c.isalpha() else c for c in v['text'])
            lines.append(f'{shift:02d}: {s}')
        save(out, 'caesar.txt', '\n'.join(lines))
    elif operation == 'xor':
        data = bytes.fromhex(v['text'])
        rows = []
        for key in range(256):
            b = bytes(c ^ key for c in data)
            score = sum(32 <= c < 127 or c in (10, 13, 9) for c in b) / max(len(b), 1)
            rows.append((score, key, b.decode('utf-8', 'replace')))
        save(out, 'xor.txt', '\n'.join(f'key=0x{k:02x} 可打印率={s:.0%}: {t}' for s,k,t in sorted(rows, reverse=True)))
    elif operation == 'digest':
        hashes = {name: hashlib.new(name) for name in ('md5', 'sha1', 'sha256')}
        with Path(v['file']).open('rb') as f:
            for chunk in iter(lambda: f.read(1024*1024), b''):
                for h in hashes.values():
                    h.update(chunk)
        save(out, 'hashes.json', {n:h.hexdigest() for n,h in hashes.items()})
    elif operation == 'entropy':
        data = read(v['file'])
        counts = Counter(data)
        entropy = -sum((n/len(data))*math.log2(n/len(data)) for n in counts.values()) if data else 0
        save(out, 'entropy.json', dict(bytes=len(data),entropy_bits_per_byte=round(entropy,6),byte_counts={f'{b:02x}':counts[b] for b in range(256)}))
    elif operation == 'zipinspect':
        with zipfile.ZipFile(v['file']) as z:
            save(out, 'zip-entries.json', [dict(name=i.filename,size=i.file_size,compressed=i.compress_size,encrypted=bool(i.flag_bits&1),crc=f'{i.CRC:08x}') for i in z.infolist()])
    elif operation in ('baseline', 'compare'):
        baseline = {}
        for p, rel in files(v['directory'], out):
            baseline[rel] = digest(p)
        if operation == 'baseline':
            save(out, 'baseline.json', baseline)
        else:
            old = json.loads(read(v['file']))
            if not isinstance(old, dict) or any(not isinstance(k,str) or not isinstance(x,str) for k,x in old.items()):
                raise ValueError('不是有效的基线文件')
            save(out, 'changes.json', {'新增': sorted(baseline.keys()-old.keys()), '删除': sorted(old.keys()-baseline.keys()), '修改': sorted(k for k in old.keys() & baseline.keys() if old[k] != baseline[k])})
    elif operation == 'backup':
        total = 0
        with zipfile.ZipFile(out / 'backup.zip', 'w', zipfile.ZIP_DEFLATED) as z:
            for p, rel in files(v['directory'], out):
                total += p.stat().st_size
                if total > 1024*1024*1024:
                    raise ValueError('备份超过 1 GiB，请缩小目录范围')
                z.write(p, rel)
        print('已生成 backup.zip。请下载保存后再修改源码。', flush=True)
    elif operation == 'flags':
        data = read(v['file']).decode('utf-8', 'replace')
        flags = list(dict.fromkeys(re.findall(re.escape(v['prefix']) + r'\{[^{}\r\n]{1,256}\}', data)))
        save(out, 'flags.txt', '\n'.join(flags))
        print(f'提取并去重后共 {len(flags)} 个 Flag。', flush=True)
    elif operation == 'sourcecheck':
        patterns = [('动态代码执行', r'\b(eval|exec|assert)\s*\('), ('系统命令调用', r'\b(system|shell_exec|passthru|popen|subprocess\.(?:run|Popen|call))\s*\('), ('反序列化', r'\b(unserialize|pickle\.loads|yaml\.load)\s*\('), ('编码混淆', r'\b(base64_decode|gzinflate|str_rot13)\s*\(')]
        findings, skipped = [], 0
        for p, rel in files(v['directory'], out):
            if p.suffix.lower() not in ('.php', '.py', '.js', '.java', '.jsp', '.phtml', '.inc'):
                continue
            if p.stat().st_size > 2*1024*1024:
                skipped += 1
                continue
            for line, text in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                for label, pattern in patterns:
                    if re.search(pattern, text):
                        findings.append(dict(file=rel, line=line, rule=label, text=text[:300]))
        save(out, 'findings.json', dict(findings=findings, skipped_large_files=skipped, note='特征命中需要手工确认，不是漏洞结论。'))
    else:
        raise ValueError('未知内置功能')
