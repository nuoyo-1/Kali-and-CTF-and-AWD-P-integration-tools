"""Pin selected public CTF projects and published Python versions; no extraction."""
import hashlib
import json
from pathlib import Path
import re
import urllib.request
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parent.parent
DEST=ROOT/'resources'/'ctf-projects'
PROJECTS=[
 ('rsa','RsaCtfTool/RsaCtfTool','RsaCtfTool'),
 ('xor','hellman/xortool','xortool'),
 ('bkcrack','kimci86/bkcrack',None),
 ('angr','angr/angr','angr'),
 ('volatility','volatilityfoundation/volatility3','volatility3'),
 ('oletools','decalage2/oletools',None),
 ('ciphey','Ciphey/Ciphey',None),
 ('cyberchef','GCHQ/CyberChef',None),
]

def fetch(url,limit=50*1024*1024):
    req=urllib.request.Request(url,headers={'User-Agent':'Kali-Deck-CTF-Research/1.0'})
    with urllib.request.urlopen(req,timeout=60) as response:
        data=response.read(limit+1)
    if len(data)>limit:raise ValueError('下载超过大小上限')
    return data

def main():
    DEST.mkdir(parents=True,exist_ok=True)
    records=[]
    for id,repo,pypi in PROJECTS:
        record=dict(id=id,repo=repo,url='https://github.com/'+repo)
        try:
            page=fetch(record['url']).decode('utf-8')
            match=re.search(r'"currentOid":"([a-f0-9]{40})"',page)
            if not match:raise ValueError('未能确认上游提交版本')
            commit=match[1];record['commit']=commit
            record['archived']='This repository was archived by the owner' in page
            if id in ('rsa','xor','bkcrack','angr','volatility'):
                raw=fetch(f'https://codeload.github.com/{repo}/zip/{commit}')
                name=id+'-source.zip';(DEST/name).write_bytes(raw)
                record.update(archive=name,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
            if pypi:
                package=json.loads(fetch('https://pypi.org/pypi/'+pypi+'/json'))
                record.update(pypi=pypi,version=package['info']['version'],requires_python=package['info'].get('requires_python'),distribution_source='https://pypi.org/project/'+pypi+'/')
            record['status']='collected'
        except Exception as error:record.update(status='failed',error=str(error))
        records.append(record)
        (DEST/'manifest.json').write_text(json.dumps(dict(collected=datetime.now(timezone.utc).isoformat(),projects=records),ensure_ascii=False,indent=2),encoding='utf-8')
        print(id+': '+record['status']+(' '+record.get('error','') if record['status']=='failed' else ' '+record.get('version','')),flush=True)

if __name__=='__main__':main()
