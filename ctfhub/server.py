import argparse
import atexit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import threading
from urllib.parse import parse_qs, quote, urlsplit
import uuid
import webbrowser

from ctfhub.catalog import CATEGORIES, TOOLS
from ctfhub.jobs import DATA, JOBS, ROOT, UPLOADS, JobManager
from ctfhub.sources import SOURCES
from ctfhub.paths import executable
from ctfhub.inventory import listing, get_spec, desktop_entries

WEB = ROOT / 'web'
TOKEN = secrets.token_urlsafe(32)
MANAGER = None

def resource(name, default):
    p = ROOT / 'resources' / name
    return json.loads(p.read_text(encoding='utf-8')) if p.exists() else default

class Handler(BaseHTTPRequestHandler):
    server_version = 'CTFDeck/1.0'

    def log_message(self, *_):
        pass

    def send(self, status, body, content_type='application/json; charset=utf-8', attachment=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if attachment:
            self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + quote(attachment))
        self.end_headers()
        self.wfile.write(body)

    def trusted(self, auth=False):
        expected = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host') != expected:
            self.send(403, {'error':'请使用 127.0.0.1 的本地访问地址'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + expected:
            self.send(403, {'error':'请求来源不被允许'})
            return False
        if auth and not secrets.compare_digest(self.headers.get('X-CTF-Token',''), TOKEN):
            self.send(403, {'error':'会话已失效，请刷新页面'})
            return False
        return True

    def do_GET(self):
        if not self.trusted():
            return
        path = urlsplit(self.path).path
        try:
            if path == '/api/health':
                return self.send(200, dict(app='ctf-deck', version='1.0'))
            if path in ('/', '/index.html'):
                page = (WEB / 'index.html').read_text(encoding='utf-8').replace('__CTF_TOKEN__', TOKEN)
                return self.send(200, page.encode(), 'text/html; charset=utf-8')
            if path in ('/app.js','/full.js','/beginner.js','/featured.js','/style.css','/readability.css','/full.css','/beginner.css','/featured.css'):
                return self.send(200,(WEB/path[1:]).read_bytes(),'application/javascript; charset=utf-8' if path.endswith('.js') else 'text/css; charset=utf-8')
            if path.startswith('/api/') and not self.trusted(auth=True):
                return
            if path == '/api/tools':
                tools = [dict(t, installed=bool(t['builtin'] or (platform.system()=='Linux' and executable(t)))) for t in TOOLS]
                return self.send(200,dict(tools=tools,categories=CATEGORIES,system=dict(os=platform.system(),release=platform.release(),python=platform.python_version(),kali=Path('/etc/os-release').exists() and 'kali' in Path('/etc/os-release').read_text(errors='replace').lower(),data=str(DATA))))
            if path == '/api/catalog':
                return self.send(200,resource('kali-index.json',dict(tools=[],source='https://www.kali.org/tools/all-tools/')))
            if path == '/api/beginner':
                return self.send(200,resource('beginner-guide.json',[]))
            if path == '/api/featured':
                from ctfhub.featured import listing as featured_listing
                return self.send(200,featured_listing())
            if path == '/api/inventory':
                return self.send(200,listing())
            if path.startswith('/api/program/'):
                spec=get_spec(path.split('/')[-1])
                if not spec:raise ValueError('程序不在官方登记表中')
                return self.send(200,dict(spec,installed=bool(executable(spec))))
            if path.startswith('/api/desktops/'):
                return self.send(200,desktop_entries(path.split('/')[-1]))
            if path == '/api/sources':
                from ctfhub.sources import annotate
                return self.send(200,annotate(resource('sources.json',SOURCES)))
            if path == '/api/directories':
                q = parse_qs(urlsplit(self.path).query)
                folder = Path(q.get('path',[str(Path.home())])[0]).expanduser().resolve()
                if not folder.is_dir():
                    raise ValueError('目录不存在')
                entries = []
                for p in folder.iterdir():
                    if p.name.startswith('.'):
                        continue
                    try:
                        if p.is_dir():
                            entries.append(p.name)
                    except OSError:
                        continue
                entries = sorted(entries,key=str.lower)[:1000]
                return self.send(200,dict(path=str(folder),parent=str(folder.parent),directories=entries,separator=os.sep))
            if path == '/api/jobs':
                return self.send(200,MANAGER.list())
            if path.startswith('/api/jobs/'):
                return self.send(200,MANAGER.detail(path.split('/')[-1]))
            if path == '/api/file':
                q = parse_qs(urlsplit(self.path).query)
                id = q.get('job',[''])[0]
                name = q.get('name',[''])[0]
                if id not in MANAGER.jobs:
                    raise ValueError('任务不存在')
                root = (JOBS / id).resolve()
                f = (root / name).resolve()
                if not f.is_relative_to(root) or not f.is_file() or f.name in ('_input.json','job.json'):
                    raise ValueError('结果文件不存在')
                # Stream large results rather than loading a backup into memory.
                self.send_response(200)
                self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Length',str(f.stat().st_size))
                from urllib.parse import quote
                self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(f.name))
                self.send_header('X-Content-Type-Options','nosniff')
                self.end_headers()
                with f.open('rb') as stream:
                    shutil.copyfileobj(stream,self.wfile,1024*1024)
                return
            self.send(404,dict(error='页面不存在'))
        except (ValueError,OSError) as e:
            self.send(400,dict(error=str(e)))

    def do_POST(self):
        # Read a bounded body before rejection, avoiding a TCP reset from unread
        # POST data that could hide the error response on Windows clients.
        self.connection.settimeout(60)
        try:
            length = int(self.headers.get('Content-Length','-1'))
        except ValueError:
            return self.send(400,dict(error='请求长度无效'))
        body_bytes = None
        if 0 <= length <= 1024*1024:
            body_bytes = self.rfile.read(length)
        if not self.trusted(auth=True):
            return
        try:
            path = urlsplit(self.path).path
            limit = 256*1024*1024 if path == '/api/upload' else 1024*1024
            if length < 0 or length > limit:
                raise ValueError('文件最大 256 MiB；大文件请直接填写 Kali 绝对路径')
            if path == '/api/upload':
                original = parse_qs(urlsplit(self.path).query).get('name',['upload.bin'])[0]
                safe = Path(original.replace('\\','/')).name
                safe = ''.join(c if c.isalnum() or c in '._-' else '_' for c in safe)[:120] or 'upload.bin'
                f = UPLOADS / (uuid.uuid4().hex+'_'+safe)
                remaining = length
                with f.open('wb') as target:
                    if body_bytes is not None:
                        target.write(body_bytes)
                        remaining -= len(body_bytes)
                    while remaining:
                        chunk = self.rfile.read(min(1024*1024,remaining))
                        if not chunk:
                            raise ValueError('文件上传中断')
                        target.write(chunk)
                        remaining -= len(chunk)
                return self.send(200,dict(path=str(f),name=safe,size=length))
            body = json.loads(body_bytes if body_bytes is not None else self.rfile.read(length))
            if not isinstance(body,dict):
                raise ValueError('请求格式不正确')
            if path == '/api/run':
                return self.send(201,MANAGER.submit(body.get('tool',''),body.get('values',{})))
            if path == '/api/install':
                return self.send(201,MANAGER.submit(body.get('tool',''),{},install=True))
            if path == '/api/stop':
                MANAGER.stop(body.get('id',''))
                return self.send(200,dict(ok=True))
            if path == '/api/input':
                MANAGER.input(body.get('id',''),body.get('text',''))
                return self.send(200,dict(ok=True))
            if path == '/api/shutdown':
                if any((j.get('install') or j.get('elevated')) and j['status'] in ('running','queued') for j in MANAGER.list()):
                    raise ValueError('系统安装或授权任务仍在运行，请退出工具后关闭平台')
                self.send(200,dict(ok=True))
                threading.Thread(target=self.server.shutdown,daemon=True).start()
                return
            self.send(404,dict(error='接口不存在'))
        except (ValueError,OSError) as e:
            self.send(400,dict(error=str(e)))

def serve(port=8765, browser=True):
    global MANAGER
    MANAGER = JobManager()
    atexit.register(MANAGER.close)
    server = ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads = True
    url = f'http://127.0.0.1:{server.server_port}'
    print('CTF Deck: '+url,flush=True)
    if browser:
        threading.Timer(.7,lambda:webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        MANAGER.close()
        server.server_close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--no-browser',action='store_true')
    args = parser.parse_args()
    serve(args.port,not args.no_browser)
