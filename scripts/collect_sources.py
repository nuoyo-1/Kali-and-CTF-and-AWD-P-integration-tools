"""Fetch official index and verified upstream snapshots. Run by maintainer."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import urllib.request
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ctfhub.sources import SOURCES

DEST = ROOT / 'resources'
DEST.mkdir(exist_ok=True)

def fetch(url, limit=12*1024*1024):
    request = urllib.request.Request(url, headers={'User-Agent': 'CTF-Deck-Source-Collector/1.0', 'Accept': 'application/vnd.github+json' if 'api.github.com' in url else '*/*'})
    with urllib.request.urlopen(request, timeout=40) as r:
        content = r.read(limit+1)
        if len(content) > limit:
            raise ValueError('下载超过大小限制')
        return content

class Index(HTMLParser):
    def __init__(self):
        super().__init__()
        self.items = {}
    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get('href','')
        match = re.fullmatch(r'(?:https://www.kali.org)?/tools/([a-z0-9][a-z0-9+.-]*)/', href)
        if tag == 'a' and match and match[1] not in ('all-tools','kali-meta'):
            self.items[match[1]] = dict(name=match[1], url='https://www.kali.org/tools/'+match[1]+'/')

def main():
    status = []
    try:
        raw = fetch('https://www.kali.org/tools/all-tools/')
        parser = Index()
        parser.feed(raw.decode())
        if len(parser.items) < 200:
            raise ValueError('官方目录条目过少，页面格式可能发生变化')
        data = dict(source='https://www.kali.org/tools/all-tools/', collected=datetime.now(timezone.utc).isoformat(), tools=sorted(parser.items.values(),key=lambda i:i['name']))
        (DEST / 'kali-index.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        print(f'Kali index: {len(parser.items)} tools',flush=True)
    except Exception as e:
        print(f'Kali index failed: {e}',flush=True)
    for source in SOURCES:
        repo = source['repo']
        record = dict(source)
        try:
            metadata = json.loads(fetch('https://api.github.com/repos/'+repo))
            branch = metadata['default_branch']
            commit = json.loads(fetch('https://api.github.com/repos/'+repo+'/commits/'+branch))['sha']
            target = DEST / 'upstream' / repo.replace('/','__')
            target.mkdir(parents=True,exist_ok=True)
            # README and license are collected locally. Archives are opt-in in the UI.
            readme = json.loads(fetch('https://api.github.com/repos/'+repo+'/readme?ref='+commit))
            content = fetch(readme['download_url'])
            (target/'README.md').write_bytes(content)
            license_name = None
            try:
                license_meta = json.loads(fetch('https://api.github.com/repos/'+repo+'/license?ref='+commit))
                license_content = fetch(license_meta['download_url'])
                (target / 'LICENSE.upstream').write_bytes(license_content)
                license_name = (license_meta.get('license') or {}).get('spdx_id')
            except Exception:
                pass
            record.update(commit=commit, branch=branch, archived=metadata['archived'], updated=metadata['updated_at'], license=license_name, readme_sha256=hashlib.sha256(content).hexdigest(), collected=datetime.now(timezone.utc).isoformat(), status='collected')
            print(repo+': collected',flush=True)
        except Exception as e:
            record.update(status='failed',error=str(e))
            print(repo+': '+str(e),flush=True)
        status.append(record)
        (DEST / 'sources.json').write_text(json.dumps(status,ensure_ascii=False,indent=2),encoding='utf-8')
    return status

if __name__ == '__main__':
    main()
