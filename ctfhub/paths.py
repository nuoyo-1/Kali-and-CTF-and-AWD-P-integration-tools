import os
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parent.parent
DATA=Path(os.environ.get('CTF_DECK_DATA',str(ROOT/'data'))).resolve()
VENDOR=DATA/'vendor'

def executable(spec):
    name=spec.get('executable')
    if not name:
        return None
    if spec.get('ctf_project'):
        from ctfhub.ctf_installers import directory,PROJECTS
        id=spec['ctf_project']
        folder=directory(id)
        local=folder/'bin'/PROJECTS[id]['entry']
        if (folder/'installed.json').is_file() and local.is_file() and os.access(local,os.X_OK):
            return str(local)
        # A system Python executable does not imply that angr is installed.
        if id=='angr':return None
        return shutil.which(name)
    elif name=='zsteg':
        local=VENDOR/'gems'/'bin'/'zsteg'
    elif name=='outguess':
        local=VENDOR/'outguess'/'bin'/'outguess'
    else:
        local=None
    if local and local.is_file() and os.access(local,os.X_OK):
        return str(local)
    return shutil.which(name)

def environment():
    env=os.environ.copy()
    env['PYTHONPATH']=str(ROOT)+os.pathsep+env.get('PYTHONPATH','')
    env['PYTHONIOENCODING']='utf-8'
    env['NO_COLOR']='1'
    if (VENDOR/'gems').exists():
        env['GEM_HOME']=str(VENDOR/'gems')
        env['GEM_PATH']=str(VENDOR/'gems')
    env['PATH']=os.pathsep.join([str(VENDOR/'gems'/'bin'),str(VENDOR/'outguess'/'bin'),env.get('PATH','')])
    return env
