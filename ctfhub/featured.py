"""Merge presentation metadata with collected provenance and live adapters."""
import json
import sys
from ctfhub.paths import ROOT, executable
from ctfhub.catalog import BY_ID

def listing():
    base=ROOT/'resources/ctf-projects'
    pinned=json.loads((base/'manifest.json').read_text(encoding='utf-8'))
    records={p['id']:p for p in pinned['projects']}
    projects=json.loads((base/'featured.json').read_text(encoding='utf-8'))
    for project in projects:
        source=records.get(project['id'],{})
        project['url']=source.get('url',project.get('url',''))
        project['commit']=source.get('commit','')
        project['version']=source.get('version','') if project['id'] in ('xor','angr','volatility') else ''
        project['actions']=[dict(id=id,name=BY_ID[id]['name'],installed=bool(sys.platform=='linux' and executable(BY_ID[id]))) for id in project['tools']]
        project['integrated']=bool(project['actions'])
    return dict(collected=pinned['collected'],projects=projects)
