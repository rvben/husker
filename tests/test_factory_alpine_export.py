import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from export_factory_alpine import export, package_members, resolve_file
from factory_apk import verify_apk
from prepare_factory_arm64 import sha
import test_factory_apk as fixtures


class AlpineExportTests(unittest.TestCase):
    def fixture(self, root, replace=False):
        elf = bytearray(64); elf[:6] = b'\x7fELF\x02\x01'; elf[18:20] = (183).to_bytes(2,'little')
        blob, package, *_ = fixtures.ApkTests().fixture(files={'usr/bin/tool':bytes(elf)})
        package.update(origin='index',filename='tool-1.0-r0.apk')
        packages = root/'packages'; packages.mkdir(); (packages/package['filename']).write_bytes(blob)
        base = root/'base.tar'
        with tarfile.open(base,'w') as archive:
            for name in ('usr','usr/bin'):
                item = tarfile.TarInfo(name); item.type = tarfile.DIRTYPE; item.mode = 0o755; archive.addfile(item)
            if replace:
                item = tarfile.TarInfo('usr/bin/tool')
                if replace == 'regular':
                    item.size = 9; archive.addfile(item,io.BytesIO(b'protected'))
                else:
                    item.type = tarfile.SYMTYPE; item.mode = 0o777; item.linkname = '/bin/busybox'; archive.addfile(item)
        closure = root/'closure.json'
        closure.write_text(json.dumps({'version':1,'architecture':'aarch64','base_digest':sha(base),'packages':{'tool':package}}))
        receipt, _ = verify_apk(blob,package,'tool')
        downloads = root/'downloads.json'
        downloads.write_text(json.dumps({'version':1,'closure_digest':sha(closure),'packages':{'tool':dict(receipt,filename=package['filename'])}}))
        pin = lambda path:{'path':str(path),'digest':sha(path)}
        return pin(closure),pin(downloads),pin(base),packages

    def test_sealed_base_and_explicit_busybox_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); closure, downloads, base, packages = self.fixture(root,replace=True)
            with patch('export_factory_alpine.CORE',('usr/bin/tool',)), patch('subprocess.run',side_effect=AssertionError('must not execute hooks')):
                receipt = export(closure,downloads,base,packages,root/'output',['usr/bin/tool'])
            self.assertFalse(receipt['runtime_verified']); self.assertFalse(receipt['package_hooks_executed'])
            self.assertFalse(receipt['package_database_updated'])
            self.assertEqual(receipt['replacements'][0]['previous_target'],'/bin/busybox')
            self.assertEqual((root/'output/base.tar').stat().st_mode & 0o777,0o400)
            self.assertEqual(receipt['base_digest'],sha(root/'output/base.tar'))

    def test_undeclared_replacement_missing_allowance_and_corrupt_archive_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); closure, downloads, base, packages = self.fixture(root,replace=True)
            with self.assertRaises(ValueError):export(closure,downloads,base,packages,root/'no-allowance')
            self.assertFalse((root/'no-allowance').exists())
            with patch('export_factory_alpine.CORE',()), self.assertRaises(ValueError):
                export(closure,downloads,base,packages,root/'unused-allowance',['usr/bin/tool','usr/bin/unused'])
            (packages/'tool-1.0-r0.apk').write_bytes(b'changed')
            with self.assertRaises(ValueError):export(closure,downloads,base,packages,root/'corrupt',['usr/bin/tool'])
            self.assertFalse((root/'corrupt').exists())

    def tar(self, items):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            for name, kind, target in items:
                item = tarfile.TarInfo(name); item.type = kind; item.mode = 0o755
                if kind == tarfile.REGTYPE:
                    item.size = len(target); archive.addfile(item,io.BytesIO(target))
                else:
                    item.linkname = target; archive.addfile(item)
        return stream.getvalue()

    def test_hardlink_materialization_and_bounds(self):
        data = self.tar([('usr/bin/tool',tarfile.REGTYPE,b'ELF fixture'),('usr/bin/alias',tarfile.LNKTYPE,'usr/bin/tool')])
        result = package_members(data,1000,100)
        self.assertEqual(result['usr/bin/alias'],result['usr/bin/tool'])
        self.assertEqual(result['usr/bin/alias'][0],'file')
        with self.assertRaises(ValueError):package_members(data,15,100)
        with self.assertRaises(ValueError):package_members(data,1000,1)

    def test_unsafe_hardlinks_and_special_payloads(self):
        for items in [[('a',tarfile.LNKTYPE,'../outside')],
                      [('a',tarfile.LNKTYPE,'b'),('b',tarfile.LNKTYPE,'a')],
                      [('a',tarfile.LNKTYPE,'b'),('b',tarfile.SYMTYPE,'file')],
                      [('device',tarfile.CHRTYPE,'')]]:
            with self.assertRaises(ValueError):package_members(self.tar(items),1000,100)

    def test_guest_symlink_cycles_escape_and_missing_core(self):
        for entries in [{'a':('link',0o777,'a')},{'a':('link',0o777,'../outside')},
                        {'a':('link',0o777,'missing')}]:
            with self.assertRaises(ValueError):resolve_file(entries,'a')

    def test_preexisting_output_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); args = self.fixture(root)
            output = root/'existing'; output.mkdir(); (output/'keep').write_text('preserve')
            with self.assertRaises(FileExistsError):export(*args,output)
            self.assertEqual((output/'keep').read_text(),'preserve')

    def test_regular_base_file_cannot_be_replaced_even_when_listed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); args = self.fixture(root,replace='regular')
            with self.assertRaises(ValueError):export(*args,root/'output',['usr/bin/tool'])
            self.assertFalse((root/'output').exists())


if __name__ == '__main__': unittest.main()
