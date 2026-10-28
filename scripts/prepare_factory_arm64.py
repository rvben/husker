#!/usr/bin/env python3
"""Offline, mount-free ARM64 factory image assembly from explicit pinned inputs.

No downloads, package resolution, login collection, daemon startup or VM boot.
Tool versions in the plan are preparation provenance, not live runtime proofs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import io
import stat

MAX_ARCHIVE = 2 * 1024**3
MAX_FILE = 256 * 1024**2
MAX_MEMBER = 512 * 1024**2  # Rust's pinned ARM64 compiler driver exceeds 256 MiB.
MAX_EXPANDED = 4 * 1024**3
MAX_FILES = 200000
FORBIDDEN = {'.ssh', '.aws', '.azure', '.codex', '.claude', '.gnupg', '.kube',
             '.docker', '.netrc', '.git-credentials', 'credentials.json', 'auth.json',
             'credentials.toml'}
ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        while True:
            block = source.read(1024 * 1024)
            if not block: break
            digest.update(block)
    return 'sha256:' + digest.hexdigest()


def snapshot(value, maximum, destination, executable=False):
    if (not isinstance(value, dict) or set(value) != {'path', 'digest'}
            or not isinstance(value['path'], str) or not isinstance(value['digest'], str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['digest'])):
        raise ValueError('explicit file path and lowercase SHA256 required')
    descriptor = os.open(value['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ValueError('pinned input must be a bounded, unlinked regular file')
        digest, copied = hashlib.sha256(), 0
        with os.fdopen(os.dup(descriptor), 'rb') as source, open(destination, 'xb') as target:
            while True:
                block = source.read(min(1024 * 1024, maximum - copied + 1))
                if not block:
                    break
                copied += len(block)
                if copied > maximum:
                    raise ValueError('pinned input grew beyond bound')
                digest.update(block)
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (identity(before) != identity(after) or copied != before.st_size
                or 'sha256:' + digest.hexdigest() != value['digest']):
            raise ValueError('pinned input changed or digest mismatch')
        os.chmod(destination, 0o500 if executable else 0o400)
        return destination
    finally:
        os.close(descriptor)


def guest_path(name):
    name = name.removeprefix('./') if hasattr(name, 'removeprefix') else (name[2:] if name.startswith('./') else name)
    name = name.rstrip('/')
    if name in ('', '.'):
        return None
    path = PurePosixPath(name)
    if (path.is_absolute() or len(name.encode()) > 255
            or any(part in ('', '.', '..') or part.strip() != part
                   or not re.fullmatch(r'[A-Za-z0-9 ._+@\[\]()~-]+', part) for part in name.split('/'))
            or any(part in FORBIDDEN or part == '.env' or part.startswith('.env.') for part in path.parts)):
        raise ValueError('unsafe or credential-bearing image path')
    return name


def members(archives, maximum_expanded=None, maximum_files=None):
    maximum_expanded = MAX_EXPANDED if maximum_expanded is None else maximum_expanded
    maximum_files = MAX_FILES if maximum_files is None else maximum_files
    if (type(maximum_expanded) is not int or not 0 < maximum_expanded <= MAX_EXPANDED
            or type(maximum_files) is not int or not 0 < maximum_files <= MAX_FILES):
        raise ValueError('archive bounds must be positive and within image limits')
    entries, expanded = {}, 0
    for archive in archives:
        with tarfile.open(archive, 'r:*') as source:
            seen = set()
            for item in source:
                name = guest_path(item.name)
                if name is None: continue
                if name in seen:
                    raise ValueError('duplicate archive path')
                seen.add(name)
                if not (item.isdir() or item.isfile() or item.issym()) or item.mode & 0o6000 or (item.mode & 0o1000 and not item.isdir()):
                    raise ValueError('special files, hardlinks and privileged modes are unsupported')
                if item.isfile():
                    if not 0 <= item.size <= MAX_MEMBER:
                        raise ValueError('image member exceeds bound')
                    expanded += item.size
                    if expanded > maximum_expanded:
                        raise ValueError('expanded image exceeds bound')
                    stream = source.extractfile(item)
                    data = stream.read(item.size + 1)
                    if len(data) != item.size:
                        raise ValueError('short archive member')
                    value = ('file', item.mode & 0o777, data)
                elif item.isdir():
                    value = ('dir', item.mode & 0o1777, b'')
                else:
                    target = item.linkname
                    if not target or '\0' in target or len(target.encode()) > 255:
                        raise ValueError('invalid guest symlink')
                    # Absolute links refer to guest paths only; no host extraction.
                    pieces = list(PurePosixPath(name).parent.parts) if not target.startswith('/') else []
                    for part in target.split('/'):
                        if part in ('', '.'): continue
                        if part == '..':
                            if not pieces: raise ValueError('symlink escapes guest root')
                            pieces.pop()
                        else: pieces.append(part)
                    value = ('link', 0o777, target)
                if name in entries and entries[name] != value:
                    raise ValueError('layers overlap with different contents')
                entries[name] = value
                if len(entries) > maximum_files:
                    raise ValueError('image path quota exceeded')
    for name in list(entries):
        parent = PurePosixPath(name).parent
        while str(parent) != '.':
            old = entries.get(str(parent))
            if old is not None and old[0] != 'dir':
                raise ValueError('image path descends through a file or link')
            entries.setdefault(str(parent), ('dir', 0o755, b''))
            if len(entries) > maximum_files:
                raise ValueError('image path quota exceeded')
            parent = parent.parent
    return entries


def elf_arm64(path):
    with open(path, 'rb') as source: header = source.read(64)
    if len(header) < 64 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 183:
        raise ValueError('guest binary must be little-endian AArch64 ELF64')


def write_tar(path, entries):
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(entries):
            kind, mode, data = entries[name]
            item = tarfile.TarInfo(name)
            item.uid = item.gid = item.mtime = 0
            item.mode = mode
            if kind == 'dir': item.type = tarfile.DIRTYPE
            elif kind == 'link': item.type, item.linkname = tarfile.SYMTYPE, data
            else: item.size = len(data)
            archive.addfile(item, io.BytesIO(data) if kind == 'file' else None)


def assemble(plan, output):
    required = {'version', 'architecture', 'base', 'tools', 'kernel', 'kernel_config',
                'agent', 'runner', 'mke2fs', 'mke2fs_config', 'rootfs_size_bytes',
                'tool_versions', 'source_revision'}
    if (not isinstance(plan, dict) or len(json.dumps(plan).encode()) > 65536
            or set(plan) != required or type(plan['version']) is not int or plan['version'] != 1 or plan['architecture'] != 'aarch64'):
        raise ValueError('exact version-one ARM64 preparation plan required')
    if (not isinstance(plan['tool_versions'], dict) or not plan['tool_versions']
            or any(not isinstance(key, str) or not isinstance(value, str) or not key or not value
                   or len(key) > 128 or len(value) > 256 for key, value in plan['tool_versions'].items())
            or not isinstance(plan['source_revision'], str)
            or not re.fullmatch(r'[0-9a-f]{40}', plan['source_revision'])):
        raise ValueError('resolved tool versions and source revision required')
    size = plan['rootfs_size_bytes']
    if type(size) is not int or not 128*1024**2 <= size <= 32*1024**3 or size % 4096:
        raise ValueError('rootfs size must be aligned and bounded')
    # Copy all inputs before parsing or invoking any of them. Assembly reads only
    # these sealed files, never a caller-owned path that could change mid-build.
    plan = json.loads(json.dumps(plan))
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            stage = Path(temporary)
            paths = {key: snapshot(plan[key], MAX_ARCHIVE if key in ('base', 'tools') else MAX_FILE,
                                   stage / key, executable=key == 'mke2fs')
                     for key in ('base', 'tools', 'kernel', 'kernel_config', 'agent', 'runner',
                                 'mke2fs', 'mke2fs_config')}
            return assemble_staged(plan, output, paths, stage)
    except BaseException:
        shutil.rmtree(output)
        raise


def assemble_staged(plan, output, paths, stage):
    size = plan['rootfs_size_bytes']
    for key in ('agent', 'runner'): elf_arm64(paths[key])
    with open(paths['kernel'], 'rb') as source: header = source.read(64)
    if len(header) < 64 or header[56:60] != b'ARM\x64':
        raise ValueError('uncompressed ARM64 Linux Image required')
    config = paths['kernel_config'].read_text()
    options = ('ARM64','CGROUPS','CGROUP_PIDS','VSOCKETS','VIRTIO_VSOCKETS','VIRTIO_BLK',
               'EXT4_FS','DEVTMPFS','PROC_FS','SYSFS','VIRTIO_CONSOLE','TMPFS')
    if any('CONFIG_'+option+'=y' not in config.splitlines() for option in options):
        raise ValueError('declared kernel config lacks required built-in factory features')
    entries = members([paths['base'], paths['tools']])
    if any(name in entries or any(path.startswith(name+'/') for path in entries) for name in ('workspace','acceptance','run/husker-job')):
        raise ValueError('prepared image must leave job input/identity paths absent')
    init = (ROOT/'guest/factory/init').read_bytes()
    for name, data in (('sbin/init',init),('usr/local/bin/husker-agent',paths['agent'].read_bytes()),
                       ('usr/local/bin/husker-job-runner',paths['runner'].read_bytes())):
        for parent in PurePosixPath(name).parents:
            if str(parent)=='.': continue
            if str(parent) in entries and entries[str(parent)][0] != 'dir':
                raise ValueError('factory executable parent must be a real directory')
            entries.setdefault(str(parent),('dir',0o755,b''))
        entries[name]=('file',0o755,data)
    if 'bin/sh' not in entries:
        raise ValueError('base image must include /bin/sh')
    archive=stage/'root.tar'
    write_tar(archive,entries)
    image=stage/'rootfs.ext4'
    with open(image,'xb') as target: target.truncate(size)
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','MKE2FS_CONFIG':str(paths['mke2fs_config'].resolve())}
    command=[str(paths['mke2fs'].resolve()),'-q','-F','-t','ext4','-b','4096','-m','0',
             '-E','root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0',
             '-L','husker-factory','-d',str(archive.resolve()),str(image.resolve())]
    completed=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
    if completed.returncode:
        raise RuntimeError('mke2fs failed: '+completed.stderr.decode(errors='replace')[-2048:])
    with open(image,'rb') as source:
        source.seek(1024+56)
        if source.read(2)!=b'\x53\xef': raise RuntimeError('assembler did not produce ext4')
    for key,path in paths.items():
        if sha(path)!=plan[key]['digest']: raise ValueError('preparation input changed during assembly')
    shutil.copyfile(paths['kernel'],output/'Image')
    if sha(output/'Image') != plan['kernel']['digest']:
        raise ValueError('copied kernel differs from pinned input')
    shutil.move(image,output/'rootfs.ext4')
    manifest={'version':1,'architecture':'aarch64','plan':plan,
              'factory_init_digest':'sha256:'+hashlib.sha256(init).hexdigest(),
              'outputs':{name:{'digest':sha(output/name),'size_bytes':(output/name).stat().st_size}
                         for name in ('Image','rootfs.ext4')},
              'runtime_verified':False,'hermetic_build':False}
    receipt = json.dumps(manifest,sort_keys=True,indent=2)+'\n'
    if len(receipt.encode()) > 65536:
        raise ValueError('preparation manifest exceeds 64 KiB')
    (output/'preparation.json').write_text(receipt)
    for name in ('Image','rootfs.ext4','preparation.json'):
        os.chmod(output/name,0o400)
        with open(output/name,'rb') as file: os.fsync(file.fileno())
    directory=os.open(output,os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.plan.stat().st_size>65536: parser.error('plan exceeds 64 KiB')
    manifest=assemble(json.loads(args.plan.read_text()),args.output)
    print(json.dumps(manifest['outputs'],sort_keys=True))

if __name__=='__main__': main()
