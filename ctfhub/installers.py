"""Optional user-local installations. Only apt dependencies require elevation."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import zipfile
from ctfhub.paths import ROOT,VENDOR,environment

def execute(args,cwd=None):
    print('步骤：'+' '.join(map(str,args)),flush=True)
    subprocess.run(list(map(str,args)),cwd=cwd,env=environment(),stdin=subprocess.DEVNULL,check=True,shell=False)

def dependencies(packages):
    apt=shutil.which('apt-get')
    if not apt:
        raise ValueError('未找到 apt-get，请在 Kali 中使用')
    args=[apt,'install','-y']+packages
    if os.geteuid()!=0:
        pkexec=shutil.which('pkexec')
        if not pkexec:
            raise ValueError('缺少系统图形授权组件 pkexec')
        args.insert(0,pkexec)
    execute(args)

def safe_extract(archive,target):
    target=Path(target).resolve()
    target.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        total=0
        for entry in z.infolist():
            destination=(target/entry.filename).resolve()
            mode=entry.external_attr>>16
            total+=entry.file_size
            if not destination.is_relative_to(target) or stat.S_ISLNK(mode) or total>200*1024*1024:
                raise ValueError('源码包包含不允许的路径、符号链接或过大的内容')
            if entry.is_dir():
                destination.mkdir(parents=True,exist_ok=True)
            else:
                destination.parent.mkdir(parents=True,exist_ok=True)
                with z.open(entry) as source,destination.open('wb') as out:
                    shutil.copyfileobj(source,out)
                if mode&0o111:
                    destination.chmod(0o755)

def install(id):
    if sys.platform!='linux':
        raise ValueError('可选工具安装仅支持 Kali Linux')
    if id.startswith('ctf-'):
        from ctfhub.ctf_installers import install as install_ctf
        return install_ctf(id[4:])
    base=ROOT/'resources'/'optional'
    manifest=json.loads((base/'manifest.json').read_text(encoding='utf-8'))
    if id not in ('zsteg','outguess'):
        raise ValueError('未知安装器')
    item=manifest[id]
    artifact=base/item['file']
    from ctfhub.artifacts import ensure
    url=item['source'] if id=='zsteg' else 'https://codeload.github.com/'+item['repo']+'/zip/'+item['commit']
    ensure(artifact,url,item['sha256'])
    if hashlib.sha256(artifact.read_bytes()).hexdigest()!=item['sha256']:
        raise ValueError('安装资料的 SHA-256 校验不一致，请重新获取完整分发包')
    if id=='zsteg':
        dependencies(['ruby','ruby-dev','build-essential'])
        execute([shutil.which('gem'),'install',artifact,'--no-document','--install-dir',VENDOR/'gems','--bindir',VENDOR/'gems'/'bin'])
    else:
        dependencies(['build-essential','autoconf','automake','libtool'])
        target=VENDOR/'build'/('outguess-'+item['commit'][:12])
        safe_extract(artifact,target)
        source=next(p for p in target.iterdir() if p.is_dir())
        execute(['sh','autogen.sh'],source)
        execute(['sh','configure','--with-generic-jconfig','--prefix='+str(VENDOR/'outguess')],source)
        execute(['make','-j2'],source)
        execute(['make','install'],source)
    print('可选工具安装完成。',flush=True)

if __name__=='__main__':
    try:
        install(sys.argv[1])
    except Exception as error:
        print('安装失败：'+str(error),flush=True)
        sys.exit(1)
