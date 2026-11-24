import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from ctfhub.catalog import BY_ID, command, validate
from ctfhub.paths import ROOT, DATA, executable, environment
from ctfhub.inventory import get_spec, validate_generic

JOBS = DATA / 'jobs'
UPLOADS = DATA / 'uploads'
for d in (JOBS, UPLOADS):
    d.mkdir(parents=True, exist_ok=True)

class JobManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.jobs = {}
        self.processes = {}
        self.inputs = {}
        for f in JOBS.glob('*/job.json'):
            try:
                j = json.loads(f.read_text(encoding='utf-8'))
                if j['status'] in ('queued', 'running'):
                    j.update(status='interrupted', message='平台曾关闭，任务已中断', ended=time.time())
                    self._persist(j)
                self.jobs[j['id']] = j
            except (ValueError, KeyError, OSError):
                continue

    def _persist(self, job):
        p = JOBS / job['id'] / 'job.json'
        tmp = p.with_suffix('.tmp')
        tmp.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding='utf-8')
        tmp.replace(p)

    def update(self, job, **values):
        with self.lock:
            job.update(values)
            self._persist(job)

    def submit(self, tool_id, values, install=False):
        spec = BY_ID.get(tool_id) if isinstance(tool_id,str) else None
        spec = spec or get_spec(tool_id)
        if not spec:
            raise ValueError('未知工具')
        if install:
            if sys.platform != 'linux' or not (spec['package'] or spec.get('installer')):
                raise ValueError('软件安装仅适用于 Kali Linux 的系统工具')
            if os.geteuid() != 0 and not shutil.which('pkexec'):
                raise ValueError('未找到图形授权组件 pkexec，请先在 Kali 软件管理器安装 policykit-1')
            values = {}
        else:
            if spec.get('package_only'):
                raise ValueError('这是组件软件包，请使用安装按钮或选择具体程序')
            values = validate_generic(spec,values) if spec.get('generic') else validate(spec, values)
            if values.get('elevated') and (sys.platform!='linux' or not shutil.which('pkexec')):
                raise ValueError('系统授权运行需要 Kali Linux 和 pkexec')
            if spec['executable'] and not executable(spec):
                raise ValueError('工具尚未安装，请点击“安装工具”')
        with self.lock:
            if sum(j['status'] in ('queued','running') for j in self.jobs.values()) >= 4:
                raise ValueError('最多同时执行 4 个任务，请等待或停止现有任务')
            if install and any(j.get('install') and j['status'] in ('queued','running') for j in self.jobs.values()):
                raise ValueError('已有安装任务正在运行，请等待完成')
            id = uuid.uuid4().hex
            out = JOBS / id
            out.mkdir()
            job = dict(id=id, tool_id=tool_id, name=('安装 / 更新 ' if install else '') + spec['name'], status='queued', created=time.time(), install=install, message='准备执行', timeout=1800 if install else spec['timeout'])
            job['elevated']=bool(values.get('elevated'))
            self.jobs[id] = job
            self._persist(job)
            threading.Thread(target=self._run, args=(job, spec, values, out), daemon=True).start()
            return dict(job)

    def _run(self, job, spec, values, out):
        p = None
        try:
            if job['install']:
                apt = shutil.which('apt-get')
                if not apt:
                    raise ValueError('未找到 apt-get，请使用 Kali Linux')
                if spec.get('installer'):
                    args = [sys.executable,'-u','-m','ctfhub.installers',spec['installer']]
                else:
                    args = ([shutil.which('pkexec')] if os.geteuid() else []) + [apt, 'install', '-y', spec['package']]
            elif spec['builtin']:
                descriptor = out / '_input.json'
                descriptor.write_text(json.dumps(dict(operation=spec['builtin'], values=values), ensure_ascii=False), encoding='utf-8')
                args = [sys.executable, '-u', '-m', 'ctfhub.worker', str(descriptor)]
            else:
                args = [spec['executable']]+values['argv'] if spec.get('generic') else command(spec, values, out)
                args[0] = executable(spec)
                if job.get('elevated'):args.insert(0,shutil.which('pkexec'))
            env = environment()
            with (out / 'output.log').open('wb') as log:
                log.write(('正在执行：' + job['name'] + '\n').encode('utf-8'))
                log.flush()
                with self.lock:
                    if job['status'] == 'cancelled':
                        return
                    interactive = spec.get('generic') and values.get('mode')=='interactive' and not job['install']
                    job['interactive'] = bool(interactive)
                    if interactive and os.name!='nt':
                        import pty
                        master,slave=pty.openpty()
                        p = subprocess.Popen(args,cwd=out,env=env,stdin=slave,stdout=slave,stderr=slave,shell=False,start_new_session=True)
                        os.close(slave)
                        self.inputs[job['id']]=master
                        def pump():
                            try:
                                while True:
                                    chunk=os.read(master,8192)
                                    if not chunk:break
                                    log.write(chunk);log.flush()
                            except (OSError,ValueError):pass
                        threading.Thread(target=pump,daemon=True).start()
                    else:
                        p = subprocess.Popen(args, cwd=out, env=env, stdin=subprocess.PIPE if interactive else subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, shell=False, start_new_session=(os.name != 'nt'))
                        if interactive:self.inputs[job['id']]=p.stdin
                    self.processes[job['id']] = p
                    self.update(job, status='running', started=time.time(), message='系统授权窗口等待确认' if job['install'] else ('正在启动独立图形窗口；以程序实际窗口状态为准' if spec['gui'] or values.get('mode')=='desktop' else '交互会话等待输出或回复' if interactive else '正在处理'))
                deadline = time.monotonic() + job['timeout']
                while p.poll() is None:
                    if time.monotonic() > deadline:
                        if job['install'] or job.get('elevated'):
                            self.update(job, message='系统授权任务仍在进行，请检查授权窗口或在工具中完成操作并退出')
                            deadline = time.monotonic() + 1800
                            time.sleep(.2)
                            continue
                        self._kill(p)
                        self.update(job, status='timeout', ended=time.time(), message='达到运行时限，已停止；可以下载已有结果')
                        break
                    if not job['install'] and not job.get('elevated') and (out / 'output.log').stat().st_size > 16*1024*1024:
                        self._kill(p)
                        self.update(job, status='failed', ended=time.time(), message='日志超过 16 MiB，已停止')
                        break
                    time.sleep(.15)
                p.wait()
            with self.lock:
                if job['status'] == 'running':
                    ok = p.returncode in ([0] if job['install'] else spec.get('success_codes',[0]))
                    missing_after_install = ok and job['install'] and not spec.get('package_only') and not executable(spec)
                    if missing_after_install:
                        ok = False
                    message = ('安装完成，工具可用' if job['install'] else '执行完成') if ok else ('安装程序已结束，但未找到工具可执行文件，请查看日志' if missing_after_install else f'程序退出码 {p.returncode}，请查看日志')
                    if ok and not job['install'] and spec['id']=='hashcat' and p.returncode==1:
                        message = '字典遍历完成，未恢复密码；可查看日志或更换字典'
                    self.update(job, status='success' if ok else 'failed', ended=time.time(), exit_code=p.returncode, message=message)
        except Exception as e:
            self.update(job, status='failed', ended=time.time(), message=str(e))
        finally:
            with self.lock:
                self.processes.pop(job['id'], None)
                writer=self.inputs.pop(job['id'],None)
                if writer is not None:
                    try:
                        if isinstance(writer,int):os.close(writer)
                        else:writer.close()
                    except OSError:pass
            (out / '_input.json').unlink(missing_ok=True)

    def _kill(self, p):
        try:
            if os.name == 'nt':
                p.kill()
            else:
                os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def stop(self, id):
        with self.lock:
            j = self.jobs.get(id)
            if not j:
                raise ValueError('任务不存在')
            if j['status'] not in ('running', 'queued'):
                return
            if j.get('install') or j.get('elevated'):
                raise ValueError('系统授权任务由系统管理，请在工具本身退出；平台不强制终止提权进程')
            self.update(j, status='cancelled', ended=time.time(), message='已停止；可下载已有结果')
            if id in self.processes:
                self._kill(self.processes[id])

    def close(self):
        for id in list(self.processes):
            if not self.jobs[id].get('install') and not self.jobs[id].get('elevated'):
                self.stop(id)

    def input(self,id,text):
        if not isinstance(text,str) or len(text)>8192 or '\x00' in text:
            raise ValueError('交互输入无效')
        with self.lock:
            writer=self.inputs.get(id)
            if writer is None or self.jobs[id]['status']!='running':
                raise ValueError('该任务当前没有可用的交互会话')
            data=text.encode('utf-8')
            if isinstance(writer,int):os.write(writer,data)
            else:writer.write(data);writer.flush()

    def list(self):
        with self.lock:
            return [dict(j) for j in sorted(self.jobs.values(), key=lambda j:j['created'], reverse=True)]

    def detail(self, id):
        with self.lock:
            if id not in self.jobs:
                raise ValueError('任务不存在')
            result = dict(self.jobs[id])
        out = JOBS / id
        log = out / 'output.log'
        if log.exists():
            with log.open('rb') as f:
                f.seek(max(0, log.stat().st_size - 180000))
                result['log'] = f.read().decode('utf-8','replace')
        else:
            result['log'] = ''
        result['files'] = []
        root=out.resolve()
        for p in out.rglob('*'):
            if p.name in ('_input.json','job.json','job.tmp'):continue
            try:
                if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root):
                    result['files'].append(dict(name=str(p.relative_to(out)).replace('\\','/'),size=p.stat().st_size))
            except OSError:
                # A running tool can rename/remove a file between enumeration and stat.
                continue
            if len(result['files'])>=500:break
        return result
