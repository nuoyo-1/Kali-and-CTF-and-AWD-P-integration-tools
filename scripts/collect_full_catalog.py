"""Collect all official tool pages with resumable bounded concurrency."""
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import time
import urllib.request

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ctfhub.discovery import ToolPage

def collect(item):
    for attempt in range(3):
        try:
            req=urllib.request.Request(item['url'],headers={'User-Agent':'CTF-Deck-Catalog/2.0'})
            with urllib.request.urlopen(req,timeout=25) as r:
                raw=r.read(2*1024*1024).decode('utf-8','replace')
            p=ToolPage();p.feed(raw)
            return p.record(item['name'],item['url'])
        except Exception as error:
            last=str(error);time.sleep(attempt+.2)
    return dict(item,status='failed',error=last,packages=[],binaries=[],categories=[])

def main():
    path=ROOT/'resources'/'kali-full.json'
    index=json.loads((ROOT/'resources'/'kali-index.json').read_text(encoding='utf-8'))
    previous=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {'tools':[]}
    records={t['name']:t for t in previous['tools'] if t.get('status')=='collected'}
    pending=[t for t in index['tools'] if t['name'] not in records]
    def save():
        data=dict(source=index['source'],collected=datetime.now(timezone.utc).isoformat(),tools=[records.get(t['name'],dict(t,status='pending',packages=[],binaries=[],categories=[])) for t in index['tools']])
        path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures=[pool.submit(collect,t) for t in pending]
        for i,future in enumerate(as_completed(futures),1):
            t=future.result();records[t['name']]=t
            if i%25==0 or i==len(futures):
                save();print(f'{len(records)}/{len(index["tools"])} pages; failures: {sum(t["status"]!="collected" for t in records.values())}',flush=True)
    save()

if __name__=='__main__':main()
