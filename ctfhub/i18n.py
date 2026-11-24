"""Chinese navigation data and conservative option labels."""
import json
import re
from pathlib import Path

DATA=json.loads((Path(__file__).resolve().parent.parent/'resources/chinese-labels.json').read_text(encoding='utf-8'))
GROUPS={key:(value['name'],value['description']) for key,value in DATA['groups'].items()}

def info(name,official=()):
    item=DATA['tools'].get(name,{})
    group=item.get('group','system')
    label,description=GROUPS[group]
    return dict(group=group,group_name=label,title_zh=item.get('title',label+'工具'),specific_title=item.get('specific_title',False),description_zh=item.get('description',description),classification_source=item.get('basis','人工归组'))

def option_label(option):
    flag=option['flag'].lstrip('-')
    names=DATA['options']
    if flag in names:return names[flag]
    words=re.split(r'[-_]',flag)
    if len(words)>1 and all(w in names for w in words):return ' · '.join(names[w] for w in words)
    description=option.get('description','').lower()
    for phrase,label in DATA['phrases'].items():
        if phrase in description:return label
    return '工具专用参数（可展开原始说明）'
