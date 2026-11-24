"""Fetch a pinned upstream artifact when a Git checkout has no bundled archive."""
import hashlib
from pathlib import Path
import urllib.request

def ensure(path,url,sha256,limit=100*1024*1024):
    path=Path(path)
    if path.is_file():
        if hashlib.sha256(path.read_bytes()).hexdigest()!=sha256:
            raise ValueError('安装资料SHA-256不一致：'+path.name)
        return path
    if not url.startswith('https://'):raise ValueError('安装资料必须来自HTTPS')
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.part')
    print('下载固定版本安装资料：'+path.name,flush=True)
    try:
        request=urllib.request.Request(url,headers={'User-Agent':'Kali-Deck/1.0'})
        digest=hashlib.sha256();total=0
        with urllib.request.urlopen(request,timeout=60) as response,temp.open('wb') as output:
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                total+=len(chunk)
                if total>limit:raise ValueError('安装资料超过大小上限')
                digest.update(chunk);output.write(chunk)
        if digest.hexdigest()!=sha256:raise ValueError('下载资料SHA-256校验失败：'+path.name)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)
    return path
