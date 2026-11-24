"""Use the official category landing page to tag source entries."""
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import urllib.request

ROOT=Path(__file__).resolve().parent.parent
class Categories(HTMLParser):
    def __init__(self):super().__init__();self.heading=False;self.buffer=[];self.category=None;self.tags={}
    def handle_starttag(self,tag,attrs):
        if tag=='h3':self.heading=True;self.buffer=[]
        if tag=='a' and self.category:
            href=dict(attrs).get('href') or ''
            m=re.match(r'(?:https://www.kali.org)?/tools/([a-z0-9][a-z0-9+.-]*)/',href)
            if m:self.tags.setdefault(m[1],set()).add(self.category)
    def handle_data(self,data):
        if self.heading:self.buffer.append(data)
    def handle_endtag(self,tag):
        if tag=='h3' and self.heading:self.category=''.join(self.buffer).strip();self.heading=False

if __name__=='__main__':
    req=urllib.request.Request('https://www.kali.org/tools/',headers={'User-Agent':'CTF-Deck-Catalog/2.0'})
    with urllib.request.urlopen(req,timeout=30) as r:raw=r.read().decode()
    parser=Categories();parser.feed(raw)
    path=ROOT/'resources/kali-full.json';data=json.loads(path.read_text(encoding='utf-8'))
    for item in data['tools']:item['categories']=sorted(parser.tags.get(item['name'],[])) or ['Other / Components']
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Official category tags:',len(parser.tags),'sources; remaining sources marked Other / Components')
