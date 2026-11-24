import base64
import contextlib
import io
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile
from urllib.parse import quote

# Each test run has its own disposable state and cannot touch a user's tasks.
STATE = tempfile.TemporaryDirectory(prefix='ctf-deck-test-')
os.environ['CTF_DECK_DATA'] = str(Path(STATE.name)/'platform')
from ctfhub.catalog import BY_ID, CATEGORIES, TOOLS, command, validate
from ctfhub.operations import run
from ctfhub.jobs import JobManager, JOBS
from ctfhub.jobs import ROOT
from ctfhub import server
from ctfhub.installers import safe_extract
from ctfhub.discovery import ToolPage,options_from_help
from ctfhub.inventory import load as inventory_load,validate_generic,get_spec,desktop_entries
from ctfhub import inventory
from ctfhub.i18n import GROUPS,info,option_label
from ctfhub.identify import inspect as identify_file

class OperationsTests(unittest.TestCase):
    def test_beginner_file_identification_is_read_only_and_uses_content(self):
        f=self.root/'misnamed.txt';data=b'\x89PNG\r\n\x1a\n'+b'example'
        f.write_bytes(data)
        result=identify_file(f)
        self.assertEqual(result['kind'],'PNG 图片')
        self.assertIn('pngcheck',result['tools'])
        self.assertEqual(f.read_bytes(),data)
    def test_beginner_tasks_reference_real_curated_tools(self):
        tasks=json.loads((ROOT/'resources/beginner-guide.json').read_text(encoding='utf-8'))
        self.assertEqual(len(tasks),25)
        self.assertEqual(len({t['id'] for t in tasks}),len(tasks))
        for task in tasks:
            self.assertIn(task['tool'],BY_ID)
            self.assertTrue(task['prepare'] and task['action'] and task['result'])
    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.out = self.root/'out'
        self.out.mkdir()
    def tearDown(self):
        self.output.__exit__(None,None,None)
        self.tmp.cleanup()
    def test_decode_preserves_binary_and_rejects_invalid(self):
        run('decode',{'text':'AP8=','mode':'base64-decode'},self.out)
        self.assertEqual((self.out/'decoded.bin').read_bytes(),b'\x00\xff')
        with self.assertRaises(ValueError):
            run('decode',{'text':'%%%','mode':'base64-decode'},self.out)
    def test_baseline_detects_all_three_change_kinds(self):
        src=self.root/'source';src.mkdir()
        (src/'edit.php').write_text('old')
        (src/'delete.php').write_text('delete')
        run('baseline',{'directory':str(src)},self.out)
        (src/'edit.php').write_text('new')
        (src/'delete.php').unlink()
        (src/'add.php').write_text('added')
        run('compare',{'directory':str(src),'file':str(self.out/'baseline.json')},self.out)
        result=json.loads((self.out/'changes.json').read_text(encoding='utf-8'))
        self.assertEqual(result,{'新增':['add.php'],'删除':['delete.php'],'修改':['edit.php']})
    def test_backup_is_readable_and_does_not_change_source(self):
        src=self.root/'src';src.mkdir()
        (src/'a.txt').write_bytes(b'content')
        run('backup',{'directory':str(src)},self.out)
        with zipfile.ZipFile(self.out/'backup.zip') as archive:
            self.assertEqual(archive.read('a.txt'),b'content')
        self.assertEqual((src/'a.txt').read_bytes(),b'content')
    def test_baseline_includes_nested_files_and_skips_output(self):
        src=self.root/'src';(src/'nested').mkdir(parents=True)
        (src/'nested'/'test.txt').write_text('nested')
        output=src/'output';output.mkdir()
        (output/'ignore.txt').write_text('generated')
        run('baseline',{'directory':str(src)},output)
        result=json.loads((output/'baseline.json').read_text(encoding='utf-8'))
        self.assertEqual(set(result),{str(Path('nested')/'test.txt')})
    def test_flags_deduplicated_with_literal_prefix(self):
        f=self.root/'log';f.write_text('flag{a} flag{a} ctf{b} flag{x}',encoding='utf-8')
        run('flags',{'file':str(f),'prefix':'flag'},self.out)
        self.assertEqual((self.out/'flags.txt').read_text(), 'flag{a}\nflag{x}')
    def test_source_rules_report_line_without_modifying(self):
        src=self.root/'src';src.mkdir();f=src/'sample.py';text='# benign static-analysis fixture\neval("1 + 1")'
        f.write_text(text)
        run('sourcecheck',{'directory':str(src)},self.out)
        finding=json.loads((self.out/'findings.json').read_text(encoding='utf-8'))['findings'][0]
        self.assertEqual(finding['line'],2)
        self.assertEqual(f.read_text(),text)
    def test_digest_streams_known_hash(self):
        f=self.root/'a';f.write_bytes(b'abc')
        run('digest',{'file':str(f)},self.out)
        result=json.loads((self.out/'hashes.json').read_text())
        self.assertEqual(result['sha256'],hashlib.sha256(b'abc').hexdigest())
    def test_entropy_empty_and_constant(self):
        f=self.root/'a';f.write_bytes(b'')
        run('entropy',{'file':str(f)},self.out)
        self.assertEqual(json.loads((self.out/'entropy.json').read_text())['entropy_bits_per_byte'],0)
        f.write_bytes(bytes(range(256)))
        run('entropy',{'file':str(f)},self.out)
        self.assertEqual(json.loads((self.out/'entropy.json').read_text())['entropy_bits_per_byte'],8)
    def test_zip_does_not_extract_traversal_name(self):
        f=self.root/'test.zip'
        with zipfile.ZipFile(f,'w') as z:
            z.writestr('../outside.txt','hello')
        run('zipinspect',{'file':str(f)},self.out)
        self.assertFalse((self.root/'outside.txt').exists())

class InstallerArchiveTests(unittest.TestCase):
    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);archive=root/'input.zip'
            with zipfile.ZipFile(archive,'w') as z:
                z.writestr('../outside.txt','not executable')
            with self.assertRaises(ValueError):
                safe_extract(archive,root/'output')
            self.assertFalse((root/'outside.txt').exists())
    def test_rejects_symlink_entries(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);archive=root/'input.zip'
            with zipfile.ZipFile(archive,'w') as z:
                info=zipfile.ZipInfo('link');info.create_system=3;info.external_attr=0o120777<<16
                z.writestr(info,'/etc/passwd')
            with self.assertRaises(ValueError):
                safe_extract(archive,root/'output')
    def test_extracts_nested_regular_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);archive=root/'input.zip'
            with zipfile.ZipFile(archive,'w') as z:
                z.writestr('source/nested/readme.txt','example')
            safe_extract(archive,root/'output')
            self.assertEqual((root/'output/source/nested/readme.txt').read_text(),'example')

class FullCatalogTests(unittest.TestCase):
    def test_duplicate_programs_have_one_visible_primary_and_keep_variants(self):
        with patch.object(inventory.sys,'platform','win32'):
            data=inventory.listing()
        primary=[b for t in data['tools'] for b in t['binaries'] if b['display_primary']]
        self.assertEqual(len(primary),len({b['name'] for b in primary}))
        self.assertEqual(len(primary),data['unique_binary_count'])
        duplicated=[b for b in primary if len(b['variants'])>1]
        self.assertEqual(len(duplicated),11)
        self.assertTrue(all(len({v['package'] for v in b['variants']})>1 for b in duplicated))
    def test_all_tools_have_chinese_classification_and_labels(self):
        data,_=inventory_load()
        for t in data['tools']:
            label=info(t['name'])
            self.assertIn(label['group'],GROUPS)
            self.assertRegex(label['title_zh'],r'[\u4e00-\u9fff]')
        self.assertEqual(info('aircrack-ng')['group'],'wifi')
        self.assertEqual(info('bluelog')['group'],'bluetooth')
        self.assertEqual(info('wireshark')['group'],'network')
        self.assertEqual(option_label({'flag':'--output-file'}),'输出 · 文件')
    def test_package_detection_failure_is_unknown_not_not_installed(self):
        with patch.object(inventory.sys,'platform','linux'),patch.object(inventory.shutil,'which',side_effect=lambda n:'/fake/dpkg' if n=='dpkg-query' else None),patch.object(inventory.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='')):
            data=inventory.listing()
            nmap=next(t for t in data['tools'] if t['name']=='nmap')
            self.assertEqual(nmap['installation_state'],'unknown')
            self.assertTrue(all(not p['detection_known'] for p in nmap['packages']))
    def test_installed_package_without_path_entry_is_reported_separately(self):
        with patch.object(inventory.sys,'platform','linux'),patch.object(inventory.shutil,'which',side_effect=lambda n:'/fake/dpkg' if n=='dpkg-query' else None),patch.object(inventory.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='nmap\tinstalled\n')):
            data=inventory.listing()
            nmap=next(t for t in data['tools'] if t['name']=='nmap')
            self.assertEqual(nmap['installation_state'],'package-only')
            self.assertTrue(nmap['installed'])
    def test_every_index_entry_is_collected(self):
        index=json.loads((ROOT/'resources/kali-index.json').read_text(encoding='utf-8'))
        data,specs=inventory_load()
        self.assertEqual({t['name'] for t in index['tools']},{t['name'] for t in data['tools']})
        self.assertTrue(all(t['status']=='collected' for t in data['tools']))
        self.assertGreater(len(specs),4000)
    def test_program_points_to_its_documented_package(self):
        data,_=inventory_load()
        for tool in data['tools']:
            for binary in tool['binaries']:
                self.assertIn(binary['package'],tool['packages'],tool['name'])
                self.assertEqual(get_spec(binary['id'])['executable'],binary['name'])
    def test_option_arity_and_null_href(self):
        parser=ToolPage();parser.feed('<a href>skip</a><h3>demo</h3><h5>demo-cli</h5><pre>  --port &lt;PORT&gt;  Port number\n  --verbose  More output</pre>sudo apt install demo')
        record=parser.record('demo','https://www.kali.org/tools/demo/')
        options=record['binaries'][0]['options']
        self.assertEqual([(o['flag'],o['takes_value']) for o in options],[('--port',True),('--verbose',False)])
    def test_generic_values_are_not_shell_text(self):
        spec=dict(options=[dict(flag='--input')])
        values=validate_generic(spec,dict(options=[dict(flag='--input',value='x; $(not-executed)')],positionals=['subcommand'],position_first=True,mode='interactive'))
        self.assertEqual(values['argv'],['subcommand','--input','x; $(not-executed)'])
        with self.assertRaises(ValueError):validate_generic(spec,dict(options=[dict(flag='--unknown')]))
        with self.assertRaises(ValueError):validate_generic(spec,dict(positionals=['--unregistered']))
    def test_desktop_discovery_cannot_take_arbitrary_package_or_path(self):
        with self.assertRaises(ValueError):desktop_entries('/tmp/custom.desktop')

class ValidationTests(unittest.TestCase):
    def test_all_categories_and_unique_ids(self):
        self.assertEqual(set(CATEGORIES),{t['category'] for t in TOOLS})
        self.assertEqual(len(TOOLS),len(BY_ID))
    def test_host_cannot_be_option_cidr_or_shell(self):
        for v in ['--script=evil','127.0.0.1;id','192.168.0.0/24','a b','$(id)']:
            with self.subTest(v=v),self.assertRaises(ValueError):
                validate(BY_ID['nmap'],{'host':v})
    def test_url_validation_rejects_other_schemes_and_credentials(self):
        for url in ['file:///etc/passwd','https://user:pass@target/','target','http://a:invalid/']:
            with self.subTest(url=url),self.assertRaises(ValueError):
                validate(BY_ID['http'],{'url':url})
    def test_shell_chars_remain_a_single_argument(self):
        url='http://127.0.0.1/?x=$(id);cat%20/etc/passwd'
        values=validate(BY_ID['curl'],{'url':url})
        argv=command(BY_ID['curl'],values,Path('/tmp/out'))
        self.assertEqual(argv[-1],url)
        self.assertEqual(argv[0],'curl')
    def test_select_and_types_are_checked(self):
        with self.assertRaises(ValueError):
            validate(BY_ID['decode'],{'text':'x','mode':'execute'})
        with self.assertRaises(ValueError):
            validate(BY_ID['http'],{'url':{'bad':'value'}})
    def test_services_limit_validated_before_task(self):
        with self.assertRaises(ValueError):
            validate(BY_ID['services'],{'urls':'\n'.join(['http://127.0.0.1/']*31)})

class JobLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.manager=JobManager()
        BY_ID['_test_sleep'] = dict(BY_ID['curl'],id='_test_sleep',name='Test sleep',executable=sys.executable,fields=[],args=['-u','-c','import time; print("started",flush=True); time.sleep(30)'],timeout=1)
    def tearDown(self):
        self.manager.close()
        BY_ID.pop('_test_sleep',None)
    def wait_terminal(self,id):
        for _ in range(100):
            j=self.manager.detail(id)
            if j['status'] not in ('queued','running'):
                return j
            time.sleep(.05)
        self.fail('Task did not terminate')
    def test_timeout_stops_process_and_preserves_log(self):
        job=self.manager.submit('_test_sleep',{})
        result=self.wait_terminal(job['id'])
        self.assertEqual(result['status'],'timeout')
        self.assertIn('started',result['log'])
    def test_cancelled_queued_job_does_not_start(self):
        with self.manager.lock:
            job=self.manager.submit('_test_sleep',{})
            self.manager.stop(job['id'])
        self.assertEqual(self.wait_terminal(job['id'])['status'],'cancelled')
        time.sleep(.1)
        self.assertNotIn(job['id'],self.manager.processes)
    def test_stop_running_process(self):
        BY_ID['_test_sleep']['timeout']=30
        job=self.manager.submit('_test_sleep',{})
        for _ in range(80):
            if self.manager.detail(job['id'])['status']=='running':
                break
            time.sleep(.03)
        self.manager.stop(job['id'])
        self.assertEqual(self.wait_terminal(job['id'])['status'],'cancelled')
    def test_interactive_session_accepts_input_and_keeps_output(self):
        spec=BY_ID['_test_sleep']
        spec.update(generic=True,options=[],timeout=10,args=[])
        # Use the same generic argument builder as official adapters, with Python
        # only as a local harmless test executable.
        spec['options']=[dict(flag='-c')]
        job=self.manager.submit('_test_sleep',{'mode':'interactive','options':[{'flag':'-c','value':'print(input(),flush=True)'}]})
        for _ in range(80):
            if self.manager.detail(job['id'])['status']=='running':break
            time.sleep(.03)
        self.manager.input(job['id'],'hello-interactive\n')
        result=self.wait_terminal(job['id'])
        self.assertEqual(result['status'],'success',result)
        self.assertIn('hello-interactive',result['log'])

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.MANAGER=JobManager()
        cls.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        cls.port=cls.http.server_port
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();server.MANAGER.close()
    def request(self,method,path,body=None,token=True,extra=None):
        headers={'X-CTF-Token':server.TOKEN} if token else {}
        headers.update(extra or {})
        if isinstance(body,dict):
            body=json.dumps(body).encode();headers['Content-Type']='application/json'
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        c.request(method,path,body,headers)
        response=c.getresponse();data=response.read();status=response.status;c.close()
        return status,data
    def test_landing_page_and_no_remote_scripts(self):
        status,body=self.request('GET','/',token=False)
        self.assertEqual(status,200)
        self.assertIn(server.TOKEN.encode(),body)
        self.assertNotIn(b'cdn.',body)
    def test_api_requires_token(self):
        self.assertEqual(self.request('GET','/api/tools',token=False)[0],403)
        self.assertEqual(self.request('POST','/api/run',{'tool':'decode'},token=False)[0],403)
    def test_cross_origin_and_rebinding_rejected(self):
        self.assertEqual(self.request('GET','/',extra={'Host':'attacker.example'})[0],403)
        self.assertEqual(self.request('POST','/api/run',{},extra={'Origin':'https://attacker.example'})[0],403)
    def test_upload_run_download_and_history(self):
        status,body=self.request('POST','/api/upload?name=sample.txt',b'abc')
        self.assertEqual(status,200)
        uploaded=json.loads(body)['path']
        status,body=self.request('POST','/api/run',{'tool':'digest','values':{'file':uploaded}})
        self.assertEqual(status,201)
        id=json.loads(body)['id']
        for _ in range(80):
            _,body=self.request('GET','/api/jobs/'+id)
            result=json.loads(body)
            if result['status'] not in ('queued','running'):
                break
            time.sleep(.05)
        self.assertEqual(result['status'],'success',result)
        status,body=self.request('GET',f'/api/file?job={id}&name=hashes.json')
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['md5'],hashlib.md5(b'abc').hexdigest())
        self.assertEqual(self.request('GET',f'/api/file?job={id}&name=../../outside')[0],400)
        self.assertEqual(self.request('GET',f'/api/file?job={id}&name=_input.json')[0],400)
        restored=JobManager()
        self.assertIn(id,[j['id'] for j in restored.list()])
    def test_unknown_tool_is_rejected(self):
        self.assertEqual(self.request('POST','/api/run',{'tool':'nonexistent','values':{}})[0],400)
    def test_directories_picker(self):
        status,body=self.request('GET','/api/directories?path='+quote(str(ROOT)))
        self.assertEqual(status,200,body.decode())
        self.assertIsInstance(json.loads(body)['directories'],list)
    def test_malformed_json_is_reported(self):
        self.assertEqual(self.request('POST','/api/run',b'{broken')[0],400)
    def test_install_not_available_on_windows(self):
        if sys.platform=='linux':
            self.skipTest('No apt operations are triggered by test suite')
        self.assertEqual(self.request('POST','/api/install',{'tool':'nmap'})[0],400)

if __name__=='__main__':
    unittest.main()
