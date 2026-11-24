import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ctfhub.artifacts import ensure

class ArtifactTests(unittest.TestCase):
    def test_download_is_verified_before_replacing_destination(self):
        content=b'pinned public artifact';sha=hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'test.zip'
            with patch('ctfhub.artifacts.urllib.request.urlopen',return_value=io.BytesIO(content)):
                self.assertEqual(ensure(path,'https://example.com/test.zip',sha),path)
            self.assertEqual(path.read_bytes(),content)
            self.assertFalse(path.with_name('test.zip.part').exists())
    def test_bad_download_leaves_no_artifact(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'test.zip'
            with patch('ctfhub.artifacts.urllib.request.urlopen',return_value=io.BytesIO(b'wrong')),self.assertRaises(ValueError):
                ensure(path,'https://example.com/test.zip','0'*64)
            self.assertFalse(path.exists())
            self.assertFalse(path.with_name('test.zip.part').exists())
    def test_size_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'test.zip'
            with patch('ctfhub.artifacts.urllib.request.urlopen',return_value=io.BytesIO(b'too large')),self.assertRaises(ValueError):
                ensure(path,'https://example.com/test.zip','0'*64,limit=2)
            self.assertFalse(path.exists())
