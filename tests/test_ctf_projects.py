import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ctfhub.catalog import BY_ID, command, validate
from ctfhub.ctf_installers import artifact, pip_target, records, PROJECTS
from ctfhub.ctf_runners import settings
from ctfhub.featured import listing
from ctfhub.paths import ROOT, executable

class CtfProjectsTests(unittest.TestCase):
    def test_provenance_and_archives_are_complete(self):
        sources=records()
        self.assertEqual(len(sources),8)
        for id,item in sources.items():
            self.assertEqual(item['status'],'collected')
            self.assertRegex(item['commit'],r'^[0-9a-f]{40}$')
            self.assertTrue(item['url'].startswith('https://github.com/'))
            if item.get('archive') and (ROOT/'resources/ctf-projects'/item['archive']).exists():
                data=(ROOT/'resources/ctf-projects'/item['archive']).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(),item['sha256'])

    def test_corrupt_source_is_rejected_before_install(self):
        from ctfhub.artifacts import ensure
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'source.zip';path.write_bytes(b'corrupt')
            with patch('ctfhub.artifacts.urllib.request.urlopen') as network,self.assertRaises(ValueError):
                ensure(path,'https://example.com/source.zip','0'*64)
            network.assert_not_called()

    def test_installation_pins_and_rsa_source_avoid_obsolete_pypi(self):
        self.assertEqual(Path(pip_target('rsa')).name,'rsa-source.zip')
        self.assertEqual(pip_target('xor'),'xortool=='+records()['xor']['version'])
        self.assertEqual(pip_target('angr'),'angr=='+records()['angr']['version'])
        self.assertEqual(pip_target('volatility'),'volatility3=='+records()['volatility']['version'])
        with self.assertRaises(KeyError):pip_target('arbitrary-project')

    def test_featured_reuses_existing_adapters_and_labels_references(self):
        projects=listing()['projects']
        self.assertEqual(len(projects),12)
        self.assertEqual(len({p['id'] for p in projects}),12)
        self.assertEqual(sum(p['integrated'] for p in projects),10)
        for p in projects:
            self.assertEqual(p['integrated'],bool(p['tools']))
            for action in p['actions']:
                self.assertIn(action['id'],BY_ID)
                self.assertEqual(BY_ID[action['id']]['category'],p['category'])
        for p in projects:
            if p['id'] in ('cyberchef','ciphey'):self.assertFalse(p['integrated'])

    def test_angr_not_detected_from_plain_system_python(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with patch('ctfhub.ctf_installers.VENDOR',root),patch('ctfhub.paths.shutil.which',return_value='/usr/bin/python'):
                self.assertIsNone(executable(BY_ID['angr-find']))
                dest=root/'ctf/angr';(dest/'bin').mkdir(parents=True)
                binary=dest/'bin/python';binary.write_text('test');binary.chmod(0o755)
                self.assertIsNone(executable(BY_ID['angr-find']))
                (dest/'installed.json').write_text('{}')
                self.assertEqual(executable(BY_ID['angr-find']),str(binary))

    def test_bkcrack_preserves_two_files_and_internal_names(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);one=root/'encrypted.zip';two=root/'plain.zip'
            one.write_bytes(b'fixture');two.write_bytes(b'fixture')
            values=validate(BY_ID['bkcrack-known'],dict(encrypted=str(one),plain=str(two),cipher_entry='folder/file name.txt',plain_entry='plain.txt'))
            self.assertEqual(command(BY_ID['bkcrack-known'],values,root),['bkcrack','-C',str(one.resolve()),'-c','folder/file name.txt','-P',str(two.resolve()),'-p','plain.txt'])

    def test_angr_settings_limits_and_optional_address(self):
        self.assertEqual(settings('0x401000','','32','yes'),(0x401000,None,32,True))
        for arguments in [('0','','32','yes'),('0x1','0x1','32','yes'),('0x401000','','257','yes'),('0x401000','','0','yes'),('0x401000','','1;echo hi','yes'),('$(id)','','32','yes'),('0x401000','bad','32','yes'),('0x401000','','32','maybe')]:
            with self.subTest(arguments=arguments),self.assertRaises(ValueError):settings(*arguments)

    def test_angr_addresses_are_checked_before_job_submission(self):
        with tempfile.NamedTemporaryFile() as file:
            with self.assertRaises(ValueError):validate(BY_ID['angr-find'],dict(file=file.name,find='invalid',avoid='',length='32',printable='yes'))

    def test_no_extra_installer_can_be_selected(self):
        for spec in BY_ID.values():
            if spec.get('ctf_project'):
                self.assertIn(spec['ctf_project'],PROJECTS)
                self.assertEqual(spec['installer'],'ctf-'+spec['ctf_project'])

    def test_volatility_plugins_are_fixed_not_user_commands(self):
        for id,plugin in [('vol-info','windows.info'),('vol-pslist','windows.pslist'),('vol-pstree','windows.pstree')]:
            self.assertEqual(BY_ID[id]['args'],['-f','{file}',plugin])

    def test_reference_page_recognizes_newly_integrated_projects(self):
        from ctfhub.sources import annotate
        sources=annotate(json.loads((ROOT/'resources/sources.json').read_text(encoding='utf-8')))
        by_repo={s['repo']:s for s in sources}
        self.assertEqual([t['id'] for t in by_repo['RsaCtfTool/RsaCtfTool']['adapted_tools']],['rsa-private','rsa-decrypt'])
        self.assertEqual(by_repo['GCHQ/CyberChef']['adapted_tools'],[])
        self.assertEqual(by_repo['DasSecurity-HatLab/AoiAWD']['adapted_tools'],[])

if __name__=='__main__':unittest.main()
