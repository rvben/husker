import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from plan_factory_alpine import dependency, plan, records, resolve, satisfies
from prepare_factory_arm64 import sha


def package(name, version='1.0.0-r0', depends='', provides=''):
    return {'P':name,'V':version,'A':'aarch64','C':'Q1'+'A'*27+'=',
            'S':'123','D':depends,'p':provides}


class AlpinePlanTests(unittest.TestCase):
    def fixture(self, root):
        index = root/'index.tar.gz'; base = root/'base.tar.gz'
        text = lambda items:'\n\n'.join('\n'.join(key+':'+value for key,value in item.items()) for item in items)+'\n'
        for path, member, items in [(index,'APKINDEX',[package('tool',depends='lib>=2.3.0'),package('lib','2.5.0-r0')]),
                                   (base,'./lib/apk/db/installed',[package('lib','2.4.0-r0')])]:
            data = text(items).encode()
            with tarfile.open(path,'w:gz') as archive:
                item = tarfile.TarInfo(member); item.size = len(data)
                archive.addfile(item,io.BytesIO(data))
        return {'path':str(index),'digest':sha(index)}, {'path':str(base),'digest':sha(base)}

    def test_base_versions_preferred_and_immutable_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); index, base = self.fixture(root)
            with patch('subprocess.run',side_effect=AssertionError('must not execute packages')):
                receipt = plan(index,base,['tool'],root/'output')
            self.assertEqual(receipt['packages']['lib']['origin'],'base')
            self.assertEqual(receipt['packages']['lib']['version'],'2.4.0-r0')
            self.assertEqual(receipt['packages']['tool']['filename'],'tool-1.0.0-r0.apk')
            self.assertFalse(receipt['runtime_verified']); self.assertFalse(receipt['publisher_signature_verified'])
            self.assertEqual(json.loads((root/'output/closure.json').read_text()),receipt)
            self.assertEqual((root/'output/closure.json').stat().st_mode & 0o777,0o400)

    def test_ambiguity_requires_explicit_provider(self):
        index = {'tool':package('tool',depends='so:libx.so.1'),
                 'one':package('one',provides='so:libx.so.1=1'),
                 'two':package('two',provides='so:libx.so.1=1')}
        with self.assertRaises(ValueError): resolve(index,{},['tool'])
        selected, edges = resolve(index,{},['tool'],{'so:libx.so.1':'two'})
        self.assertEqual(selected,{'tool':'index','two':'index'})
        self.assertTrue(any(edge['provider']=='two' for edge in edges))

    def test_circular_dependencies_bounded_without_reexecution(self):
        index = {'one':package('one',depends='two=1.0.0-r0'),
                 'two':package('two',depends='one=1.0.0-r0')}
        selected, _ = resolve(index,{},['one'])
        self.assertEqual(set(selected),{'one','two'})
        with patch('plan_factory_alpine.MAX_PACKAGES',1), self.assertRaises(ValueError):resolve(index,{},['one'])

    def test_incompatible_base_and_exact_versions_fail(self):
        index = {'tool':package('tool',depends='lib>=2.3.0'),'lib':package('lib','2.5.0-r0')}
        with self.assertRaises(ValueError):resolve(index,{'lib':package('lib','2.0.0-r0')},['tool'])
        index['tool']['D'] = 'lib=1.0.0-r0'
        with self.assertRaises(ValueError):resolve(index,{},['tool'])

    def test_version_subset_and_unknown_constraints(self):
        self.assertTrue(satisfies('2.4.0-r1','>=','2.4'))
        self.assertFalse(satisfies('2.4.0-r0','>=','2.4.0-r1'))
        self.assertTrue(satisfies('6.5_p20251123-r0','=','6.5_p20251123-r0'))
        for token in ('lib<2','!conflict','lib~1','lib>=','lib>1'):
            with self.assertRaises(ValueError):dependency(token)
        with self.assertRaises(ValueError):satisfies('1.2_rc1','>=','1.2')

    def test_metadata_wrong_architecture_duplicates_and_unsafe_names(self):
        for text in ['P:../outside\nV:1.0-r0\nA:aarch64\n',
                     'P:tool\nV:1.0-r0\nA:x86_64\n',
                     'P:tool\nP:other\nV:1.0-r0\nA:aarch64\n']:
            with self.assertRaises(ValueError):records(text,index=False)

    def test_wrong_pin_removes_partial_output_and_preserves_existing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); index, base = self.fixture(root)
            bad = dict(index,digest='sha256:'+'0'*64)
            with self.assertRaises(ValueError):plan(bad,base,['tool'],root/'partial')
            self.assertFalse((root/'partial').exists())
            existing = root/'existing'; existing.mkdir(); (existing/'keep').write_text('preserve')
            with self.assertRaises(FileExistsError):plan(index,base,['tool'],existing)
            self.assertEqual((existing/'keep').read_text(),'preserve')


if __name__ == '__main__': unittest.main()
