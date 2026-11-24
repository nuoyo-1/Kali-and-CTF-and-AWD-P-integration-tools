"""Parse official documentation into conservative, provenance-preserving forms."""
from html.parser import HTMLParser
import re

def options_from_help(help_text):
    result={}
    for line in help_text.splitlines():
        if not re.match(r'^\s*-',line):
            continue
        parts=re.split(r'\s{2,}',line.strip(),maxsplit=1)
        declaration=parts[0]
        # A long option is preferred to an alias. Never interpret examples as flags.
        flags=re.findall(r'(?<!\w)--?[A-Za-z][A-Za-z0-9_-]*',declaration)
        if not flags:
            continue
        flag=next((x for x in flags if x.startswith('--')),flags[0])
        tail=declaration[declaration.find(flag)+len(flag):].strip(' ,')
        takes_value=bool(re.match(r'^(?:=|<|\[|[A-Z][A-Z0-9_:-]*(?:\s|$))',tail))
        if re.search(r'(?:^|\s)(?:FILE|PATH|URL|HOST|PORT|VALUE|STRING|INT|NUM|TARGET)\b',declaration):
            takes_value=True
        desc=parts[1] if len(parts)>1 else declaration
        if flag not in result:
            result[flag]=dict(flag=flag,takes_value=takes_value,description=desc[:240],declaration=declaration[:200],inferred=True)
    return list(result.values())[:150]

class ToolPage(HTMLParser):
    def __init__(self):
        super().__init__();self.heading=None;self.heading_text=[];self.pre=False;self.pre_text=[];self.current=None;self.package=None;self.binaries=[];self.text=[];self.categories=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag in ('h3','h5'):
            self.heading=tag;self.heading_text=[]
        if tag=='pre':
            self.pre=True;self.pre_text=[]
        if tag=='a' and '/tools/category/' in (a.get('href') or ''):
            self.categories.append(a['href'].rstrip('/').split('/')[-1])
    def handle_data(self,data):
        self.text.append(data)
        if self.heading:self.heading_text.append(data)
        if self.pre:self.pre_text.append(data)
    def handle_endtag(self,tag):
        if tag==self.heading:
            value=''.join(self.heading_text).strip().strip('$ ')
            if tag=='h3':
                self.package=value if re.fullmatch(r'[a-z0-9][a-z0-9+.-]*',value) else None
                self.current=None
            elif re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*',value) and self.package:
                self.current=dict(name=value,package=self.package,help='')
                self.binaries.append(self.current)
            self.heading=None
        if tag=='pre' and self.pre:
            if self.current:
                self.current['help']+=''.join(self.pre_text)[:20000]
            self.pre=False
    def record(self,name,url):
        text=' '.join(self.text)
        packages=list(dict.fromkeys(re.findall(r'sudo apt install\s+([a-z0-9][a-z0-9+.-]*)',text)))
        binaries=list({(b['name'],b['package']):b for b in self.binaries}.values())
        for b in binaries:
            b['options']=options_from_help(b['help'])
        return dict(name=name,url=url,packages=packages,binaries=binaries,categories=sorted(set(self.categories)),status='collected')
