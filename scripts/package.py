"""Verify collected artifacts and build a portable, checksummed release."""
import ast
import hashlib
import json
import os
import sys
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parent.parent
SKIP={'data','.git','.venv','__pycache__','dist','node_modules','review'}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def verify_resources():
    resources=ROOT/'resources'
    index=json.loads((resources/'kali-index.json').read_text(encoding='utf-8'))
    full=json.loads((resources/'kali-full.json').read_text(encoding='utf-8'))
    if {t['name'] for t in index['tools']}!={t['name'] for t in full['tools']} or any(t['status']!='collected' for t in full['tools']):
        raise ValueError('全目录采集不完整，不能作为全工具版本打包')
    sources=json.loads((resources/'sources.json').read_text(encoding='utf-8'))
    for item in sources:
        if item.get('status')!='collected':
            raise ValueError('上游资料收集不完整：'+item['repo'])
        folder=resources/'upstream'/item['repo'].replace('/','__')
        if sha((folder/'README.md').read_bytes())!=item['readme_sha256']:
            raise ValueError('上游说明校验失败：'+item['repo'])
        if item.get('archive'):
            archive=resources/item['archive']
            if sha(archive.read_bytes())!=item['archive_sha256']:
                raise ValueError('源码 ZIP 校验失败：'+item['repo'])
            with zipfile.ZipFile(archive) as z:
                if z.testzip():
                    raise ValueError('源码 ZIP 损坏：'+item['repo'])
    optional=resources/'optional'
    data=json.loads((optional/'manifest.json').read_text(encoding='utf-8'))
    for name in ('outguess','zsteg'):
        item=data[name]
        if sha((optional/item['file']).read_bytes())!=item['sha256']:
            raise ValueError('可选安装资料校验失败：'+name)
    ctf=resources/'ctf-projects'
    projects=json.loads((ctf/'manifest.json').read_text(encoding='utf-8'))['projects']
    for item in projects:
        if item.get('status')!='collected':raise ValueError('CTF 项目采集不完整：'+item['id'])
        if item.get('archive'):
            archive=ctf/item['archive']
            if sha(archive.read_bytes())!=item['sha256']:raise ValueError('CTF 源码校验失败：'+item['id'])
            with zipfile.ZipFile(archive) as z:
                if z.testzip():raise ValueError('CTF 源码 ZIP 损坏：'+item['id'])
    sys.path.insert(0,str(ROOT))
    from ctfhub.featured import listing
    featured=listing()
    if len({p['id'] for p in featured['projects']})!=len(featured['projects']):raise ValueError('GitHub 精选项目重复')

def package():
    verify_resources()
    out=ROOT/'dist';out.mkdir(exist_ok=True)
    target=out/'Kali-Deck-Chinese.zip'
    manifest={}
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
        for parent,dirs,files in os.walk(ROOT):
            dirs[:]=sorted(d for d in dirs if d not in SKIP)
            for name in sorted(files):
                p=Path(parent)/name;rel=p.relative_to(ROOT)
                if p.suffix in ('.pyc','.part') or p.is_symlink():
                    continue
                content=p.read_bytes()
                if p.suffix=='.py':
                    ast.parse(content,filename=str(rel))
                info=zipfile.ZipInfo('Kali-Deck/'+rel.as_posix());info.create_system=3
                info.external_attr=(0o100755 if p.suffix in ('.desktop','.py') else 0o100644)<<16
                info.compress_type=zipfile.ZIP_DEFLATED
                archive.writestr(info,content)
                manifest[rel.as_posix()]=sha(content)
        archive.writestr('Kali-Deck/MANIFEST.json',json.dumps(manifest,ensure_ascii=False,indent=2))
    with zipfile.ZipFile(target) as z:
        if z.testzip():
            raise ValueError('分发包完整性检查失败')
        if any('/data/' in n or n.lower().endswith('.php') for n in z.namelist()):
            raise ValueError('分发包包含本机数据或散落的 PHP 文件')
    checksum=sha(target.read_bytes())
    target.with_suffix('.zip.sha256').write_text(f'{checksum}  {target.name}\n',encoding='ascii')
    print(f'{target}\n{target.stat().st_size:,} bytes\nSHA-256: {checksum}\n{len(manifest)} files verified',flush=True)

if __name__=='__main__':
    package()
