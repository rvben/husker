import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from export_factory_cargo import export, packages
from prepare_factory_arm64 import sha


class CargoExportTests(unittest.TestCase):
    def fixture(self, root, members=None):
        cache = root/'cache'/'registry'; cache.mkdir(parents=True)
        crate = cache/'example-1.0.0.crate'
        with tarfile.open(crate,'w:gz') as archive:
            for name, data, kind in members or [('example-1.0.0/Cargo.toml',b'[package]\nname="example"\nversion="1.0.0"\n',tarfile.REGTYPE),
                                                ('example-1.0.0/src/lib.rs',b'pub fn example() {}\n',tarfile.REGTYPE),
                                                ('example-1.0.0/tests/repr(u8)~snapshot.rs',b'// upstream fixture\n',tarfile.REGTYPE)]:
                item = tarfile.TarInfo(name); item.type = kind; item.size = len(data)
                if '~' in name: item.mode = 0o755
                item.linkname = '../outside' if kind == tarfile.SYMTYPE else ''
                archive.addfile(item,io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        lock = root/'Cargo.lock'
        lock.write_text('version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "'+sha(crate)[7:]+'"\n')
        return lock, cache.parent, crate

    def test_verified_deterministic_checksums_and_readonly_layer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock, cache, crate = self.fixture(root)
            first = export(lock,sha(lock),cache,root/'one')
            second = export(lock,sha(lock),cache,root/'two')
            self.assertEqual(first,second)
            self.assertFalse(first['runtime_verified'])
            with tarfile.open(root/'one/cargo-vendor.tar') as archive:
                items = archive.getmembers()
                self.assertTrue(all(item.uid == item.gid == item.mtime == 0 for item in items))
                self.assertTrue(all(not item.mode & 0o222 for item in items if item.isfile()))
                checksums = json.load(archive.extractfile('opt/factory/vendor/example-1.0.0/.cargo-checksum.json'))
                self.assertEqual(checksums['package'],sha(crate)[7:])
                self.assertEqual(checksums['files']['src/lib.rs'],hashlib.sha256(b'pub fn example() {}\n').hexdigest())
                self.assertIn(b'offline = true',archive.extractfile('opt/factory/cargo-home/config.toml').read())
                self.assertEqual(archive.getmember('opt/factory/vendor/example-1.0.0/tests/repr(u8)~snapshot.rs').mode,0o555)

    def test_corrupt_archive_and_lock_rejected_without_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock, cache, crate = self.fixture(root)
            with self.assertRaises(ValueError): export(lock,'sha256:'+'0'*64,cache,root/'bad-lock')
            crate.write_bytes(b'corrupt')
            with self.assertRaises(ValueError): export(lock,sha(lock),cache,root/'bad-crate')
            self.assertFalse((root/'bad-lock').exists()); self.assertFalse((root/'bad-crate').exists())

    def test_unsafe_archives_rejected(self):
        for name, kind in [('example-1.0.0/../outside',tarfile.REGTYPE),
                           ('example-1.0.0/.env',tarfile.REGTYPE),
                           ('example-1.0.0/link',tarfile.SYMTYPE),
                           ('other-1.0.0/src/lib.rs',tarfile.REGTYPE),
                           ('example-1.0.0/.cargo-checksum.json',tarfile.REGTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); lock, cache, _ = self.fixture(root,[(name,b'x',kind)])
                with self.assertRaises(ValueError): export(lock,sha(lock),cache,root/'output')
                self.assertFalse((root/'output').exists())

    def test_duplicate_and_file_parent_rejected(self):
        for members in [[('example-1.0.0/a',b'x',tarfile.REGTYPE)]*2,
                        [('example-1.0.0/a',b'x',tarfile.REGTYPE),('example-1.0.0/a/b',b'x',tarfile.REGTYPE)]]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); lock, cache, _ = self.fixture(root,members)
                with self.assertRaises(ValueError): export(lock,sha(lock),cache,root/'output')

    def test_custom_registry_and_existing_output_rejected(self):
        with self.assertRaises(ValueError): packages({'package':[{'source':'git+https://example.invalid/repo'}]})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock, cache, _ = self.fixture(root)
            output = root/'output'; output.mkdir(); (output/'keep').write_text('preserve')
            with self.assertRaises(FileExistsError): export(lock,sha(lock),cache,output)
            self.assertEqual((output/'keep').read_text(),'preserve')

    def test_symlink_archive_and_fifo_lock_rejected(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock, cache, crate = self.fixture(root)
            moved = root/'moved'; crate.rename(moved); crate.symlink_to(moved)
            with self.assertRaises(OSError): export(lock,sha(lock),cache,root/'linked')
            fifo = root/'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): export(fifo,sha(lock),cache,root/'fifo-output')

    def test_expansion_bound_and_ambiguous_cache_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock, cache, crate = self.fixture(root)
            with patch('export_factory_cargo.MAX_EXPANDED',1), self.assertRaises(ValueError):
                export(lock,sha(lock),cache,root/'large')
            second = cache/'second'; second.mkdir(); (second/crate.name).write_bytes(crate.read_bytes())
            with self.assertRaises(ValueError): export(lock,sha(lock),cache,root/'ambiguous')
            self.assertFalse((root/'large').exists()); self.assertFalse((root/'ambiguous').exists())


if __name__ == '__main__': unittest.main()
