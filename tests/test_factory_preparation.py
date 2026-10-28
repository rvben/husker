import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import os
import subprocess
import sys

spec=importlib.util.spec_from_file_location('prep',Path(__file__).parents[1]/'scripts/prepare_factory_arm64.py')
prep=importlib.util.module_from_spec(spec); spec.loader.exec_module(prep)

class PreparationTests(unittest.TestCase):
    def archive(self,path,entries):
        with tarfile.open(path,'w') as archive:
            for name,data in entries:
                info=tarfile.TarInfo(name); info.mode=0o755; info.size=len(data)
                archive.addfile(info,io.BytesIO(data))
    def fixture_plan(self, directory, tool):
        root=Path(directory)
        self.archive(root/'base.tar',[('bin/sh',b'fixture shell')])
        self.archive(root/'tools.tar',[('opt/tools/version.txt',b'fixture tools')])
        elf=bytearray(64); elf[:6]=b'\x7fELF\x02\x01'; elf[18:20]=(183).to_bytes(2,'little')
        for name in ('agent','runner'): (root/name).write_bytes(elf)
        kernel=bytearray(64); kernel[56:60]=b'ARM\x64'; (root/'kernel').write_bytes(kernel)
        options=('ARM64','CGROUPS','CGROUP_PIDS','VSOCKETS','VIRTIO_VSOCKETS','VIRTIO_BLK','EXT4_FS','DEVTMPFS','PROC_FS','SYSFS','VIRTIO_CONSOLE','TMPFS')
        (root/'config').write_text('\n'.join('CONFIG_'+value+'=y' for value in options))
        pin=lambda path: dict(path=str(path),digest=prep.sha(path))
        plan=dict(version=1,architecture='aarch64',base=pin(root/'base.tar'),tools=pin(root/'tools.tar'),
            kernel=pin(root/'kernel'),kernel_config=pin(root/'config'),agent=pin(root/'agent'),runner=pin(root/'runner'),
            mke2fs=pin(tool),mke2fs_config=pin(prep.ROOT/'guest/factory/mke2fs.conf'),
            rootfs_size_bytes=128*1024**2,tool_versions={'fixture':'not bootable'},source_revision='a'*40)
        return plan

    def test_real_mount_free_arm64_fixture_assembly_and_pins(self):
        tool=Path(os.environ.get('FACTORY_MKE2FS','/opt/homebrew/opt/e2fsprogs/sbin/mke2fs')).resolve()
        if not tool.exists(): self.skipTest('set FACTORY_MKE2FS to local tar-capable mke2fs')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            plan=self.fixture_plan(root,tool)
            try:
                manifest=prep.assemble(plan,root/'output')
            except RuntimeError as error:
                if 'without-libarchive' in str(error):
                    self.assertFalse((root/'output').exists())
                    self.skipTest('installed mke2fs lacks libarchive; tar population unverified')
                raise
            checker=tool.parent/'e2fsck'
            inspector=tool.parent/'debugfs'
            if not checker.exists() or not inspector.exists():
                self.fail('filesystem fixture requires sibling e2fsck and debugfs')
            checked=subprocess.run([str(checker),'-f','-n',str(root/'output/rootfs.ext4')],capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stdout+checked.stderr)
            inspected=subprocess.run([str(inspector),'-R','cat /sbin/init',str(root/'output/rootfs.ext4')],capture_output=True)
            self.assertEqual(inspected.returncode,0,inspected.stderr)
            self.assertEqual(inspected.stdout,(prep.ROOT/'guest/factory/init').read_bytes())
            for guest_path in ('/sbin/init','/usr/local/bin/husker-agent','/usr/local/bin/husker-job-runner'):
                metadata=subprocess.run([str(inspector),'-R','stat '+guest_path,str(root/'output/rootfs.ext4')],capture_output=True,text=True)
                self.assertEqual(metadata.returncode,0,metadata.stderr)
                self.assertRegex(metadata.stdout,r'Mode:\s+0755')
                self.assertRegex(metadata.stdout,r'User:\s+0\s+Group:\s+0')
            self.assertFalse(manifest['runtime_verified'])
            self.assertEqual(manifest['outputs']['rootfs.ext4']['digest'],prep.sha(root/'output/rootfs.ext4'))
            self.assertEqual((root/'output/preparation.json').stat().st_mode & 0o777,0o400)
            (root/'runner').write_bytes(b'changed')
            with self.assertRaises(ValueError): prep.assemble(plan,root/'bad-output')
            self.assertFalse((root/'bad-output').exists())
    def test_private_snapshots_survive_caller_mutation_and_seal_outputs(self):
        # This checks orchestration with a synthetic tool response, not an ext4
        # filesystem or boot proof. The real filesystem fixture is separate.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            tool=root/'mke2fs'; tool.write_bytes(b'fixture executable')
            plan=self.fixture_plan(root,tool)
            kernel=(root/'kernel').read_bytes()
            def build(command, **kwargs):
                stage=Path(command[0]).parent
                self.assertNotEqual(Path(command[0]),tool)
                self.assertEqual(Path(command[0]).read_bytes(),b'fixture executable')
                self.assertEqual(Path(command[0]).stat().st_mode & 0o777,0o500)
                self.assertEqual(kwargs['env']['MKE2FS_CONFIG'],str(stage/'mke2fs_config'))
                self.assertNotIn('HOME',kwargs['env'])
                (root/'kernel').write_bytes(b'replaced after snapshot')
                (root/'runner').write_bytes(b'replaced after snapshot')
                plan['tool_versions']['fixture']='caller changed plan'
                with tarfile.open(command[command.index('-d')+1]) as archive:
                    self.assertEqual(archive.getmember('sbin/init').uid,0)
                    self.assertEqual(archive.extractfile('usr/local/bin/husker-job-runner').read()[:4],b'\x7fELF')
                    self.assertNotIn('workspace',archive.getnames())
                with open(command[-1],'r+b') as image:
                    image.seek(1080); image.write(b'\x53\xef')
                return subprocess.CompletedProcess(command,0,b'',b'')
            with mock.patch.object(prep.subprocess,'run',side_effect=build):
                manifest=prep.assemble(plan,root/'output')
            self.assertEqual((root/'output/Image').read_bytes(),kernel)
            self.assertEqual(manifest['plan']['tool_versions']['fixture'],'not bootable')
            self.assertFalse(manifest['runtime_verified'])
            self.assertEqual(sorted(path.name for path in (root/'output').iterdir()),['Image','preparation.json','rootfs.ext4'])
            for path in (root/'output').iterdir():
                self.assertEqual(path.stat().st_mode & 0o777,0o400)

    def test_snapshot_rejects_links_digest_mismatch_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/'source'; source.write_bytes(b'pinned')
            pin=dict(path=str(source),digest=prep.sha(source))
            with self.assertRaises(ValueError): prep.snapshot(pin,3,root/'too-big')
            wrong=dict(pin,digest='sha256:'+'0'*64)
            with self.assertRaises(ValueError): prep.snapshot(wrong,100,root/'wrong')
            link=root/'symlink'; link.symlink_to(source)
            with self.assertRaises(OSError): prep.snapshot(dict(pin,path=str(link)),100,root/'from-link')
            os.link(source,root/'hardlink')
            with self.assertRaises(ValueError): prep.snapshot(pin,100,root/'from-hardlink')

    def test_declared_kernel_without_factory_tmpfs_fails_before_filesystem_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); tool=root/'mke2fs'; tool.write_bytes(b'fixture executable')
            plan=self.fixture_plan(root,tool)
            config=root/'config'; config.write_text(config.read_text().replace('CONFIG_TMPFS=y',''))
            plan['kernel_config']['digest']=prep.sha(config)
            with mock.patch.object(prep.subprocess,'run') as execute:
                with self.assertRaisesRegex(ValueError,'built-in factory features'):
                    prep.assemble(plan,root/'output')
                execute.assert_not_called()
            self.assertFalse((root/'output').exists())

    def test_failed_tool_removes_private_snapshots_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); tool=root/'mke2fs'; tool.write_bytes(b'fixture executable')
            plan=self.fixture_plan(root,tool)
            with mock.patch.object(prep.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'fixture failure')):
                with self.assertRaisesRegex(RuntimeError,'fixture failure'):
                    prep.assemble(plan,root/'output')
            self.assertFalse((root/'output').exists())
            existing=root/'existing'; existing.mkdir(); (existing/'keep').write_bytes(b'preserved')
            with self.assertRaises(FileExistsError): prep.assemble(plan,existing)
            self.assertEqual((existing/'keep').read_bytes(),b'preserved')

    def test_filesystem_tool_builder_rejects_unpinned_source_without_retaining_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            prefix=root/'archive'; (prefix/'lib/pkgconfig').mkdir(parents=True)
            (prefix/'lib/pkgconfig/libarchive.pc').write_text('fixture metadata')
            source=root/'wrong-source.tar.gz'; source.write_bytes(b'unapproved upstream archive')
            command=[sys.executable,str(prep.ROOT/'scripts/build_factory_filesystem_tools.py'),
                     '--source',str(source),'--libarchive-prefix',str(prefix),
                     '--pkg-config',sys.executable,'--output',str(root/'output')]
            result=subprocess.run(command,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('digest mismatch',result.stderr)
            self.assertFalse((root/'output').exists())
            (root/'output').mkdir(); (root/'output/keep').write_bytes(b'existing tools')
            result=subprocess.run(command,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((root/'output/keep').read_bytes(),b'existing tools')

    def test_dangerous_image_paths_and_special_entries_fail(self):
        # BusyBox's [ and [[ applets are literal tar names, never shell input.
        self.assertEqual(prep.guest_path('./usr/bin/['),'usr/bin/[')
        self.assertEqual(prep.guest_path('./usr/bin/[['),'usr/bin/[[')
        self.assertEqual(prep.guest_path('usr/share/cmake/Help/Unix Makefiles.rst'),'usr/share/cmake/Help/Unix Makefiles.rst')
        for name in ('/absolute','../escape','root/.ssh/key','opt/.codex/auth.json',' name','name ','a\tname','a//b','a;touch','a\\b','a\nname'):
            with self.assertRaises(ValueError): prep.guest_path(name)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'base.tar'
            with tarfile.open(path,'w') as archive:
                info=tarfile.TarInfo('device'); info.type=tarfile.CHRTYPE; archive.addfile(info)
            with self.assertRaises(ValueError): prep.members([path])
    def test_arm64_binary_validation_and_layer_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'binary').write_bytes(b'host executable')
            with self.assertRaises(ValueError): prep.elf_arm64(root/'binary')
            self.archive(root/'one.tar',[('bin/tool',b'one')]); self.archive(root/'two.tar',[('bin/tool',b'two')])
            with self.assertRaises(ValueError): prep.members([root/'one.tar',root/'two.tar'])

if __name__=='__main__': unittest.main()
