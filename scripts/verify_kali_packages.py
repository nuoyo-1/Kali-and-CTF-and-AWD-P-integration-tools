"""Collect package availability from Kali's official rolling amd64 index."""
import gzip
import hashlib
import json
from pathlib import Path
import sys
import urllib.request
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ctfhub.catalog import TOOLS

def main():
    url='https://kali.download/kali/dists/kali-rolling/main/binary-amd64/Packages.gz'
    names={t['package'] for t in TOOLS if t['package']}
    found={}
    headers={'User-Agent':'CTF-Deck/1.0'}
    for component in ('main','contrib','non-free','non-free-firmware'):
        component_url=url.replace('/main/',f'/{component}/')
        with urllib.request.urlopen(urllib.request.Request(component_url,headers=headers),timeout=60) as response:
            with gzip.GzipFile(fileobj=response) as stream:
                record={}
                for raw in stream:
                    if raw==b'\n':
                        name=record.get('Package')
                        if name in names:
                            found[name]={key:record.get(key,'') for key in ('Package','Version','Architecture','Source','Homepage','Installed-Size')}
                            found[name]['component']=component
                        record={}
                    elif raw[:1]!=b' ':
                        key,_,value=raw.decode('utf-8','replace').partition(': ')
                        if key in ('Package','Version','Architecture','Source','Homepage','Installed-Size'):
                            record[key]=value.strip()
    result=dict(source=url,collected=datetime.now(timezone.utc).isoformat(),architecture='amd64',packages=found,missing=sorted(names-found.keys()))
    path=ROOT/'resources'/'kali-packages.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'Verified {len(found)}/{len(names)} packages; missing: {result["missing"]}',flush=True)

if __name__=='__main__':
    main()
