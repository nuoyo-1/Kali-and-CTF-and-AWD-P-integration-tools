"""Download commit-pinned source ZIPs; never extract or run them."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / 'resources' / 'sources.json'
SELECTED = {'DasSecurity-HatLab/AoiAWD','AabyssZG/AWD-Guide','H4cking2theGate/JarPatcher','hellman/xortool','JonathanSalwan/ROPgadget','zed-0xff/zsteg','RickdeJager/stegseek','ffuf/ffuf','sqlmapproject/sqlmap'}

def main():
    records = json.loads(MANIFEST.read_text(encoding='utf-8'))
    for item in records:
        if item['repo'] not in SELECTED or not item.get('commit'):
            continue
        target = ROOT/'resources'/'upstream'/item['repo'].replace('/','__')/'source.zip'
        tmp = target.with_suffix('.part')
        try:
            request = urllib.request.Request(f"https://codeload.github.com/{item['repo']}/zip/{item['commit']}",headers={'User-Agent':'CTF-Deck/1.0'})
            checksum = hashlib.sha256()
            size = 0
            with urllib.request.urlopen(request,timeout=60) as response, tmp.open('wb') as out:
                while True:
                    chunk = response.read(1024*1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 80*1024*1024:
                        raise ValueError('源码包超过 80 MiB，跳过')
                    checksum.update(chunk)
                    out.write(chunk)
            tmp.replace(target)
            item.update(archive='upstream/'+item['repo'].replace('/','__')+'/source.zip',archive_sha256=checksum.hexdigest(),archive_bytes=size)
            item.pop('archive_error',None)
            print(f"{item['repo']}: {size} bytes",flush=True)
        except Exception as error:
            tmp.unlink(missing_ok=True)
            item['archive_error'] = str(error)
            print(f"{item['repo']}: {error}",flush=True)
        MANIFEST.write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')

if __name__ == '__main__':
    main()
