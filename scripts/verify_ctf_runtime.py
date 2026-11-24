"""Optional runtime checks with installed upstream tools, outside the stdlib suite.

Run using the validation venv's Python. All generated fixtures stay under data/.
The tiny ELF reads one byte, compares it with A and exits; it is simulated only.
"""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ctfhub.paths import environment

def elf_fixture():
    base=0x400000
    code=(b'\x31\xc0\x31\xff\x48\x8d\x35\x21\0\0\0'
          b'\xba\x01\0\0\0\x0f\x05\x80\x3e\x41\x75\x09'
          b'\xb8\x3c\0\0\0\x31\xff\x0f\x05'
          b'\xb8\x3c\0\0\0\xbf\x01\0\0\0\x0f\x05\0')
    size=0x80+len(code)
    identity=b'\x7fELF\x02\x01\x01'+b'\0'*9
    header=struct.pack('<16sHHIQQQIHHHHHH',identity,2,62,1,base+0x80,64,0,0,64,56,1,64,0,0)
    segment=struct.pack('<IIQQQQQQ',1,7,0,base,base,size,size,0x1000)
    return (header+segment).ljust(0x80,b'\0')+code,base+0x80+23,base+0x80+32

def run(args,cwd,timeout=120):
    env=environment()
    env['APPDATA']=str(cwd/'appdata')
    env['XDG_CACHE_HOME']=str(cwd/'cache')
    p=subprocess.run(list(map(str,args)),cwd=cwd,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
    (cwd/(Path(str(args[0])).stem+'.log')).write_text(p.stdout+'\n'+p.stderr,encoding='utf-8')
    if p.returncode:raise RuntimeError(f'{args[0]} exited {p.returncode}: '+p.stdout[-2000:]+p.stderr[-2000:])
    return p.stdout+p.stderr

def main():
    base=ROOT/'data/validation';base.mkdir(parents=True,exist_ok=True)
    dest=Path(tempfile.mkdtemp(prefix='runtime-',dir=base))
    scripts=Path(sys.executable).parent
    suffix='.exe' if os.name=='nt' else ''
    plaintext=(b'The quick brown fox jumps over the lazy dog. This is a CTF XOR sample with many English words and spaces. '*300)
    key=b'ICE';cipher=bytes(b^key[i%3] for i,b in enumerate(plaintext))
    file=dest/'xor.bin';file.write_bytes(cipher)
    run([scripts/('xortool'+suffix),'-c','20',file],dest)
    assert any(p.read_bytes()==plaintext for p in (dest/'xortool_out').glob('*') if p.is_file()),'xortool did not recover the known sample'
    print('PASS: xortool recovered exact plaintext from repeating-key XOR.',flush=True)
    help=run([scripts/('vol'+suffix),'windows.pslist','-h'],dest)
    assert 'windows.pslist' in help and '--pid' in help,'Volatility windows.pslist entry is missing'
    print('PASS: Volatility windows.pslist accepts the selected plugin and exposes its options (no memory-image analysis claimed).',flush=True)
    image,goal,avoid=elf_fixture();elf=dest/'read-one-byte.elf';elf.write_bytes(image)
    run([sys.executable,'-u','-m','ctfhub.ctf_runners','angr-find',elf,hex(goal),hex(avoid),'1','yes'],dest)
    result=json.loads((dest/'candidate.json').read_text(encoding='utf-8'))
    assert result['found'] and (dest/'candidate.bin').read_bytes()==b'A','angr candidate does not satisfy the known branch'
    print('PASS: angr found A for the ELF branch that requires exactly A.',flush=True)
    report=dict(xortool='exact plaintext recovered',volatility='plugin help verified; no memory-image fixture',angr='ELF branch solved; candidate A',directory=str(dest))
    (base/'runtime-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Logs: '+str(dest),flush=True)

if __name__=='__main__':main()
