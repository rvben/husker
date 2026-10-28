import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from export_factory_rust import COMPONENTS, TARGET, export, payload, pins
from export_factory_cargo import CONFIG
from prepare_factory_arm64 import sha


class RustExportTests(unittest.TestCase):
    def fixture(self, root, bad_elf=False):
        archives = root/'archives'; archives.mkdir()
        elf = bytearray(64); elf[:6] = b'\x7fELF\x02\x01'; elf[18:20] = (62 if bad_elf else 183).to_bytes(2,'little')
        binaries = {'rustc':['rustc','rustdoc'],'cargo':['cargo'],
                    'clippy-preview':['cargo-clippy','clippy-driver'],
                    'rustfmt-preview':['cargo-fmt','rustfmt'],'rust-std':[]}
        manifest = 'manifest-version = "2"\ndate = "2026-05-28"\n'
        for component, stem in COMPONENTS.items():
            name = stem+'-1.96.0-'+TARGET
            installed = 'rust-std-'+TARGET if component == 'rust-std' else component
            files = {'bin/'+binary:bytes(elf) for binary in binaries[component]}
            if component == 'rust-std': files['lib/rustlib/'+TARGET+'/lib/fixture.rlib'] = b'fixture library'
            contents = {'components':(installed+'\n').encode(),'rust-installer-version':b'3\n',
                        installed+'/manifest.in':(''.join('file:'+path+'\n' for path in files)).encode()}
            contents.update({installed+'/'+path:data for path,data in files.items()})
            path = archives/(name+'.tar.xz')
            with tarfile.open(path,'w:xz') as archive:
                for relative, data in contents.items():
                    item = tarfile.TarInfo(name+'/'+relative); item.size = len(data)
                    item.mode = 0o755 if '/bin/' in item.name else 0o644
                    archive.addfile(item,io.BytesIO(data))
            manifest += ('[pkg.'+component+']\nversion = "1.96.0 (fixture)"\n'
                         '[pkg.'+component+'.target.'+TARGET+']\navailable = true\n'
                         'xz_url = "https://static.rust-lang.org/dist/2026-05-28/'+path.name+'"\n'
                         'xz_hash = "'+sha(path)[7:]+'"\n')
        path = root/'channel.toml'; path.write_text(manifest)
        return path, archives

    def test_sealed_offline_layer_determinism_and_arm64_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest, archives = self.fixture(root)
            with patch('subprocess.run',side_effect=AssertionError('must not execute installers')):
                first = export(manifest,sha(manifest),archives,root/'one')
                second = export(manifest,sha(manifest),archives,root/'two')
            self.assertEqual(first,second)
            self.assertFalse(first['runtime_verified']); self.assertFalse(first['publisher_signature_verified'])
            self.assertEqual(len(first['binaries']),7)
            with tarfile.open(root/'one/tools.tar') as archive:
                self.assertTrue(all(item.uid == item.gid == item.mtime == 0 for item in archive))
                self.assertEqual(archive.getmember('opt/factory/rust/1.96.0/bin/rustc').mode,0o555)
                self.assertNotIn('install.sh','\n'.join(archive.getnames()))
            self.assertEqual((root/'one/export.json').stat().st_mode & 0o777,0o400)

    def test_wrong_pins_architecture_and_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest, archives = self.fixture(root,bad_elf=True)
            with self.assertRaises(ValueError): export(manifest,'sha256:'+'0'*64,archives,root/'bad-pin')
            with self.assertRaises(ValueError): export(manifest,sha(manifest),archives,root/'wrong-arch')
            output = root/'existing'; output.mkdir(); (output/'keep').write_text('preserve')
            with self.assertRaises(FileExistsError): export(manifest,sha(manifest),archives,output)
            self.assertEqual((output/'keep').read_text(),'preserve')
            self.assertFalse((root/'wrong-arch').exists())

    def test_unavailable_or_foreign_manifest_source(self):
        import tomllib
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest, _ = self.fixture(root)
            parsed = tomllib.loads(manifest.read_text())
            parsed['pkg']['rustc']['target'][TARGET]['xz_url'] = 'https://example.invalid/tool.tar.xz'
            with self.assertRaises(ValueError): pins(parsed,'1.96.0')
            parsed = tomllib.loads(manifest.read_text()); parsed['pkg']['cargo']['target'][TARGET]['available'] = False
            with self.assertRaises(ValueError): pins(parsed,'1.96.0')
            with self.assertRaises(ValueError): pins(tomllib.loads(manifest.read_text()),'1.97.0')

    def test_expansion_limit_applied_during_archive_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest, archives = self.fixture(root)
            with patch('export_factory_rust.MAX_EXPANDED',32), self.assertRaises(ValueError):
                export(manifest,sha(manifest),archives,root/'over-limit')
            self.assertFalse((root/'over-limit').exists())

    def test_installer_manifest_missing_undeclared_and_linked_payload(self):
        base = {'root/components':('file',0o644,b'rustc\n'),
                'root/rust-installer-version':('file',0o644,b'3\n'),
                'root/rustc/manifest.in':('file',0o644,b'file:bin/rustc\n'),
                'root/rustc/bin':('dir',0o755,b''),
                'root/rustc/bin/rustc':('file',0o755,b'fixture')}
        for modified in [dict(base,**{'root/rustc/bin/extra':('file',0o755,b'x')}),
                         {key:value for key,value in base.items() if not key.endswith('bin/rustc')},
                         dict(base,**{'root/rustc/bin/rustc':('link',0o755,'outside')}),
                         dict(base,**{'root/rustc/manifest.in':('file',0o644,b'file:../outside\n')})]:
            with self.assertRaises(ValueError): payload(modified,'root','rustc')

    def test_vendor_pin_and_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); manifest, archives = self.fixture(root)
            vendor = root/'vendor.tar'
            def layer(name):
                with tarfile.open(vendor,'w') as archive:
                    for parent in ('opt','opt/factory','opt/factory/cargo-home','opt/factory/vendor','opt/factory/vendor/example-1.0.0'):
                        item = tarfile.TarInfo(parent); item.type = tarfile.DIRTYPE
                        item.mode = 0o755 if parent in ('opt','opt/factory') else 0o555
                        archive.addfile(item)
                    config = tarfile.TarInfo('opt/factory/cargo-home/config.toml'); config.size = len(CONFIG); config.mode = 0o444
                    archive.addfile(config,io.BytesIO(CONFIG))
                    item = tarfile.TarInfo(name); item.size = 1; item.mode = 0o444
                    archive.addfile(item,io.BytesIO(b'x'))
            layer('opt/factory/vendor/example-1.0.0/Cargo.toml')
            receipt = export(manifest,sha(manifest),archives,root/'combined',vendor={'path':str(vendor),'digest':sha(vendor)})
            self.assertEqual(receipt['vendor_digest'],sha(vendor))
            layer('usr/bin/replacement')
            with self.assertRaises(ValueError): export(manifest,sha(manifest),archives,root/'bad-layer',vendor={'path':str(vendor),'digest':sha(vendor)})
            self.assertFalse((root/'bad-layer').exists())


if __name__ == '__main__': unittest.main()
