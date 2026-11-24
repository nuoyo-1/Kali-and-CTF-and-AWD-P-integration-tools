"""Allowlisted, user-local builds. Dependencies are the only elevated action."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from ctfhub.paths import ROOT, VENDOR, environment

PROJECTS={
    'rsa':dict(entry='RsaCtfTool',module='RsaCtfTool',method='source',deps=['libgmp-dev','libmpfr-dev','libmpc-dev','libssl-dev','libffi-dev']),
    'xor':dict(entry='xortool',module='xortool',method='pypi',package='xortool'),
    'angr':dict(entry='python',module='angr',method='pypi',package='angr'),
    'volatility':dict(entry='vol',module='volatility3',method='pypi',package='volatility3'),
    'bkcrack':dict(entry='bkcrack',method='cmake'),
}

def records():
    data=json.loads((ROOT/'resources/ctf-projects/manifest.json').read_text(encoding='utf-8'))
    return {p['id']:p for p in data['projects']}

def directory(id):
    if id not in PROJECTS:
        raise ValueError('未知的 CTF 安装项目')
    return VENDOR/'ctf'/id

def artifact(id):
    record=records()[id]
    base=ROOT/'resources/ctf-projects'
    archive=(base/record['archive']).resolve()
    if not archive.is_relative_to(base.resolve()):raise ValueError('安装资料路径无效')
    from ctfhub.artifacts import ensure
    ensure(archive,'https://codeload.github.com/'+record['repo']+'/zip/'+record['commit'],record['sha256'])
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=record['sha256']:
        raise ValueError('CTF 源码包 SHA-256 校验失败，请重新复制完整安装包')
    return archive

def pip_target(id):
    project=PROJECTS[id]
    if project['method']=='source':
        return str(ROOT/'resources/ctf-projects'/records()[id]['archive'])
    if project['method']!='pypi':
        raise ValueError('此项目不使用 pip')
    return project['package']+'=='+records()[id]['version']

def install(id):
    from ctfhub.installers import dependencies, execute, safe_extract
    if sys.platform!='linux':
        raise ValueError('CTF 工具安装需要 Kali Linux')
    if os.geteuid()==0:
        raise ValueError('请用 Kali 普通用户双击启动平台；只在依赖安装授权窗口中输入系统密码，不要用 root 启动平台')
    project=PROJECTS.get(id)
    if not project:
        raise ValueError('未知的 CTF 安装项目')
    if id=='angr' and sys.version_info<(3,12):
        raise ValueError('本版 angr 要求 Python 3.12 或更新，请先升级 Kali 的 Python 环境')
    dest=directory(id)
    (dest/'installed.json').unlink(missing_ok=True)
    if project['method']=='cmake':
        archive=artifact(id)
        dependencies(['build-essential','cmake','zlib1g-dev'])
        build=VENDOR/'build'/('bkcrack-'+records()[id]['commit'][:12])
        safe_extract(archive,build)
        roots=[p for p in build.iterdir() if p.is_dir() and (p/'CMakeLists.txt').is_file()]
        if len(roots)!=1:raise ValueError('bkcrack 源码目录结构不符')
        source=roots[0]
        execute(['cmake','-S',source,'-B',source/'build','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_INSTALL_PREFIX='+str(dest)])
        execute(['cmake','--build',source/'build','--parallel','2'])
        execute(['cmake','--install',source/'build'])
        binary=dest/'bin'/'bkcrack'
        execute([binary,'--help'])
    else:
        if project['method']=='source':artifact(id)
        target=pip_target(id)
        dependencies(['python3-venv','python3-dev','build-essential']+project.get('deps',[]))
        dest.mkdir(parents=True,exist_ok=True)
        execute([sys.executable,'-m','venv',dest])
        python=dest/'bin'/'python'
        execute([python,'-m','pip','--require-virtualenv','install','--disable-pip-version-check','--index-url','https://pypi.org/simple',target])
        execute([python,'-c','import '+project['module']])
        binary=dest/'bin'/project['entry']
        if not binary.is_file():raise ValueError('安装结束但未生成所需程序：'+project['entry'])
        frozen=subprocess.check_output([str(python),'-m','pip','freeze'],env=environment(),text=True)
        (dest/'dependencies.txt').write_text(frozen,encoding='utf-8')
        if id!='angr':execute([binary,'--help'])
    dest.mkdir(parents=True,exist_ok=True)
    record=records()[id]
    (dest/'installed.json').write_text(json.dumps(dict(id=id,source=record['url'],commit=record['commit'],method=project['method'],version=record.get('version') if project['method']=='pypi' else None),ensure_ascii=False,indent=2),encoding='utf-8')
    print('安装完成：'+id+'；环境与依赖记录保存在 '+str(dest),flush=True)
