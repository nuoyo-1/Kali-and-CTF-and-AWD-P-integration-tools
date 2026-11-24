"""Restore pinned archives excluded from Git, without extracting them."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ctfhub.artifacts import ensure

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--all',action='store_true',help='also fetch reference snapshots needed by package.py');args=parser.parse_args()
    resources=ROOT/'resources'
    optional=json.loads((resources/'optional/manifest.json').read_text(encoding='utf-8'))
    for id in ('zsteg','outguess'):
        item=optional[id];url=item.get('source') or 'https://codeload.github.com/'+item['repo']+'/zip/'+item['commit']
        ensure(resources/'optional'/item['file'],url,item['sha256'])
    for item in json.loads((resources/'ctf-projects/manifest.json').read_text(encoding='utf-8'))['projects']:
        if item.get('archive'):ensure(resources/'ctf-projects'/item['archive'],'https://codeload.github.com/'+item['repo']+'/zip/'+item['commit'],item['sha256'])
    if args.all:
        for item in json.loads((resources/'sources.json').read_text(encoding='utf-8')):
            if item.get('archive'):ensure(resources/item['archive'],'https://codeload.github.com/'+item['repo']+'/zip/'+item['commit'],item['archive_sha256'])
    print('Pinned archives ready. No sources extracted.')

if __name__=='__main__':main()
