"""Collect optional upstream installers without extracting files on Windows."""
import hashlib
import json
from pathlib import Path
import urllib.request
import re
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parent.parent
DEST=ROOT/'resources'/'optional'
DEST.mkdir(parents=True,exist_ok=True)

def fetch(url):
    req=urllib.request.Request(url,headers={'User-Agent':'CTF-Deck/1.0'})
    with urllib.request.urlopen(req,timeout=60) as r:
        data=r.read(40*1024*1024)
        return data

def main():
    repo='resurrecting-open-source-projects/outguess'
    page=fetch('https://github.com/'+repo).decode('utf-8')
    match=re.search(r'"currentOid":"([0-9a-f]{40})"',page)
    if not match:
        raise ValueError('无法从上游仓库页面确认提交版本')
    commit=match[1]
    content=fetch(f'https://codeload.github.com/{repo}/zip/{commit}')
    (DEST/'outguess-source.zip').write_bytes(content)
    gem=json.loads(fetch('https://rubygems.org/api/v1/gems/zsteg.json'))
    gem_url=f'https://rubygems.org/downloads/zsteg-{gem["version"]}.gem'
    gem_bytes=fetch(gem_url)
    if hashlib.sha256(gem_bytes).hexdigest()!=gem['sha']:
        raise ValueError('RubyGems checksum mismatch')
    (DEST/'zsteg.gem').write_bytes(gem_bytes)
    manifest=dict(collected=datetime.now(timezone.utc).isoformat(),outguess=dict(repo=repo,commit=commit,file='outguess-source.zip',sha256=hashlib.sha256(content).hexdigest()),zsteg=dict(version=gem['version'],source=gem_url,file='zsteg.gem',sha256=gem['sha']))
    (DEST/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(manifest,ensure_ascii=True),flush=True)

if __name__=='__main__':
    main()
