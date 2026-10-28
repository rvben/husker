import base64
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import unittest
import zlib
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from factory_apk import gzip_parts, verify_apk


class ApkTests(unittest.TestCase):
    def fixture(self, control_arch='aarch64', files=None):
        def section(files):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as archive:
                for name, data in files.items():
                    item = tarfile.TarInfo(name); item.size = len(data)
                    archive.addfile(item,io.BytesIO(data))
            return gzip.compress(stream.getvalue(),mtime=0)
        signature = section({'.SIGN.RSA.fixture.rsa.pub':b'not a verified signature'})
        payload = section({'usr/bin/tool':b'fixture executable'} if files is None else files)
        info = ('pkgname = tool\npkgver = 1.0-r0\narch = '+control_arch+'\ndepend = lib\nprovides = cmd:tool=1.0-r0\ndatahash = '+hashlib.sha256(payload).hexdigest()+'\n').encode()
        control = section({'.PKGINFO':info,'.post-install':b'exit 99\n'})
        blob = signature+control+payload
        package = {'archive_size':len(blob),'index_checksum':'Q1'+base64.b64encode(hashlib.sha1(control).digest()).decode(),
                   'version':'1.0-r0','architecture':'aarch64','dependencies':['lib'],'provides':['cmd:tool=1.0-r0']}
        return blob, package, signature, control, payload

    def test_control_and_data_integrity_no_hooks_execution(self):
        blob, package, *_ = self.fixture()
        with patch('subprocess.run',side_effect=AssertionError('must not execute hooks')):
            receipt, data = verify_apk(blob,package,'tool')
        self.assertEqual(receipt['ignored_hooks'],['.post-install'])
        self.assertFalse(receipt['publisher_signature_verified'])
        self.assertEqual(receipt['archive_digest'],'sha256:'+hashlib.sha256(blob).hexdigest())
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            self.assertEqual(archive.extractfile('usr/bin/tool').read(),b'fixture executable')

    def test_wrong_package_name_dependencies_and_control_hash(self):
        blob, package, *_ = self.fixture()
        for modified, name in [(package,'other'),(dict(package,dependencies=['different']),'tool'),
                               (dict(package,index_checksum='Q1'+'A'*27+'='),'tool')]:
            with self.assertRaises(ValueError): verify_apk(blob,modified,name)

    def test_noarch_index_rewrite_is_allowed_but_foreign_target_is_rejected(self):
        blob, package, *_ = self.fixture(control_arch='noarch')
        receipt, _ = verify_apk(blob,package,'tool')
        self.assertEqual(receipt['package_architecture'],'noarch')
        blob, package, *_ = self.fixture(control_arch='x86_64')
        with self.assertRaises(ValueError):verify_apk(blob,package,'tool')

    def test_data_substitution_detected_even_after_size_update(self):
        blob, package, signature, control, payload = self.fixture()
        substituted = signature+control+gzip.compress(b'different archive',mtime=0)
        with self.assertRaises(ValueError):verify_apk(substituted,dict(package,archive_size=len(substituted)),'tool')

    def test_truncation_extra_sections_and_expansion_limit(self):
        blob, _, signature, *_ = self.fixture()
        for modified in (blob[:-1],blob+signature,blob+b'extra'):
            with self.assertRaises((ValueError,zlib.error)):
                gzip_parts(modified)
        with patch('factory_apk.MAX_DATA',10), self.assertRaises(ValueError):gzip_parts(blob)


if __name__ == '__main__': unittest.main()
