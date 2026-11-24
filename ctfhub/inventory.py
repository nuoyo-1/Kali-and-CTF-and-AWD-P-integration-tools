"""Full official catalogue: package controls and structured executable adapters."""
from functools import lru_cache
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
import time
from ctfhub.paths import ROOT
from ctfhub.i18n import GROUPS,info,option_label

@lru_cache(maxsize=2)
def _load(stamp):
    path=ROOT/'resources'/'kali-full.json'
    data=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {'tools':[]}
    specs={}
    for item in data['tools']:
        item['id']='package.'+item['name']
        for binary in item['binaries']:
            binary['id']='binary.'+hashlib.sha256((item['name']+'\0'+binary['package']+'\0'+binary['name']).encode()).hexdigest()[:20]
            specs[binary['id']]=dict(id=binary['id'],name=binary['name'],category='kali',description=item['name'],executable=binary['name'],package=binary['package'],fields=[],args=[],builtin=None,installer=None,gui=False,timeout=3600,source=item['url'],generic=True,options=binary['options'],help=binary['help'],success_codes=[0])
            specs[binary['id']].update(info(item['name'],item['categories']))
            specs[binary['id']]['options']=[dict(o,label_zh=option_label(o)) for o in binary['options']]
        for package in item['packages']:
            specs['package.'+item['name']+'.'+package]=dict(id='package.'+item['name']+'.'+package,name=package,category='kali',description='安装软件包',executable=None,package=package,fields=[],args=[],builtin=None,installer=None,gui=False,timeout=1800,source=item['url'],package_only=True)
    return data,specs

def load():
    path=ROOT/'resources'/'kali-full.json'
    return _load(path.stat().st_mtime_ns if path.exists() else 0)

DESKTOPS={}

def get_spec(id):
    if not isinstance(id,str):raise ValueError('工具编号格式无效')
    return DESKTOPS.get(id) or load()[1].get(id)

def desktop_entries(package_id):
    spec=load()[1].get(package_id)
    if not spec or not spec.get('package_only'):raise ValueError('软件包未登记')
    if sys.platform!='linux' or not shutil.which('dpkg-query'):return []
    p=subprocess.run(['dpkg-query','-L',spec['package']],capture_output=True,text=True,timeout=15,check=False)
    result=[]
    for raw in p.stdout.splitlines():
        path=Path(raw)
        if not path.is_absolute() or path.suffix!='.desktop' or not path.is_file():continue
        id='desktop.'+hashlib.sha256((spec['package']+'\0'+raw).encode()).hexdigest()[:20]
        entry=dict(spec,id=id,name=path.stem,package_only=False,executable='gio',args=['launch',str(path)],gui=True)
        DESKTOPS[id]=entry;result.append(dict(id=id,name=path.stem))
    return result

_installed=(0,set())
_detection_error=None
def installed_packages(refresh=False):
    global _installed,_detection_error
    if not refresh and time.monotonic()-_installed[0]<15:return _installed[1]
    result=set()
    _detection_error=None
    if sys.platform=='linux' and shutil.which('dpkg-query'):
        try:
            p=subprocess.run(['dpkg-query','-W','-f','${binary:Package}\t${db:Status-Status}\n'],capture_output=True,text=True,timeout=15,check=False)
            if p.returncode!=0:raise OSError('系统软件包查询失败')
            result={line.split('\t')[0].split(':')[0] for line in p.stdout.splitlines() if line.endswith('\tinstalled')}
        except (OSError,subprocess.TimeoutExpired):_detection_error='无法查询系统软件包，不能据此判断是否安装'
    else:_detection_error='当前不是 Kali/Debian 软件包检测环境'
    _installed=(time.monotonic(),result)
    return result

def listing():
    data,_=load();installed=installed_packages(refresh=True);tools=[];paths={}
    for original in data['tools']:
        for b in original['binaries']:
            if b['name'] not in paths:paths[b['name']]=bool(shutil.which(b['name'])) if sys.platform=='linux' else False
        binaries=[dict(name=b['name'],package=b['package'],id=b['id'],installed=paths[b['name']],option_count=len(b['options'])) for b in original['binaries']]
        has_binary=any(b['installed'] for b in binaries)
        has_package=any(p in installed for p in original['packages'])
        installation_state='program-found' if has_binary else 'package-only' if has_package else 'unknown' if _detection_error else 'not-installed' if original['packages'] else 'reference'
        tools.append(dict(name=original['name'],url=original['url'],categories=original['categories'],status=original['status'],error=original.get('error'),packages=[dict(name=p,id='package.'+original['name']+'.'+p,installed=p in installed,detection_known=_detection_error is None) for p in original['packages']],binaries=binaries,installed=has_binary or has_package,installation_state=installation_state,execution_verified=False,**info(original['name'],original['categories'])))
    groups=[dict(id=k,name=v[0],description=v[1],count=sum(t['group']==k for t in tools)) for k,v in GROUPS.items()]
    # A command can be provided by alternative packages. Show it once, retaining
    # all package variants for an explicit choice rather than deleting adapters.
    variants={}
    for t in tools:
        for b in t['binaries']:variants.setdefault(b['name'],[]).append(dict(b,source_name=t['name']))
    owners={name:min(items,key=lambda b:(not b['installed'],b['source_name']!=name,b['id']))['id'] for name,items in variants.items()}
    for t in tools:
        for b in t['binaries']:
            b['display_primary']=owners[b['name']]==b['id']
            b['variants']=variants[b['name']]
    return dict(source=data.get('source'),collected=data.get('collected'),tools=tools,groups=groups,detection_error=_detection_error,total=len(tools),binary_count=sum(len(t['binaries']) for t in tools),unique_binary_count=len(variants),form_count=sum(b['option_count']>0 for t in tools for b in t['binaries']))

def validate_generic(spec,values):
    if not isinstance(values,dict):raise ValueError('参数格式无效')
    chosen=values.get('options',[]);positional=values.get('positionals',[])
    mode=values.get('mode','batch')
    if mode not in ('batch','interactive','desktop'):raise ValueError('运行模式无效')
    if not isinstance(chosen,list) or len(chosen)>150 or not isinstance(positional,list) or len(positional)>100:raise ValueError('参数过多或格式错误')
    allowed={o['flag'] for o in spec['options']};args=[]
    for option in chosen:
        if not isinstance(option,dict) or option.get('flag') not in allowed:raise ValueError('参数选项不在官方文档清单中')
        flag=option['flag'];value=option.get('value')
        args.append(flag)
        if value is not None:
            if not isinstance(value,str) or '\x00' in value or len(value)>8192:raise ValueError('选项值无效')
            # Preserve leading '-' as a value of a long option, not a new option.
            if value.startswith('-') and flag.startswith('--'):args[-1]=flag+'='+value
            elif value.startswith('-'):raise ValueError('短选项的值不能以短横线开头')
            else:args.append(value)
    for value in positional:
        if not isinstance(value,str) or '\x00' in value or value.startswith('-') or len(value)>8192:raise ValueError('目标/文件/子命令值无效')
    if values.get('position_first',False):args=positional+args
    else:args+=positional
    if sum(map(len,args))>100000:raise ValueError('参数总长度过大')
    elevated=values.get('elevated',False)
    if not isinstance(elevated,bool):raise ValueError('系统授权选项格式无效')
    return dict(argv=args,mode=mode,elevated=elevated)
