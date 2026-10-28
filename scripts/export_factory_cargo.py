#!/usr/bin/env python3
"""Export verified registry archives as an offline, credential-free guest layer.

Python >=3.11 required. Never runs Cargo, build scripts, downloads or guest code.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import tomllib

from prepare_factory_arm64 import guest_path, sha, snapshot

REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
MAX_PACKAGES = 2048
MAX_FILES = 180000
MAX_EXPANDED = 2 * 1024**3
MAX_MEMBER = 128 * 1024**2
CONFIG = b'''[source.crates-io]
replace-with = "factory-vendor"
[source.factory-vendor]
directory = "/opt/factory/vendor"
[net]
offline = true
'''


def packages(lock):
    result = {}
    for package in lock.get('package', []):
        if 'source' not in package:
            continue
        if package['source'] != REGISTRY:
            raise ValueError('only the public crates.io registry is supported')
        name, version, checksum = (package.get(key) for key in ('name', 'version', 'checksum'))
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name)
                or not isinstance(version, str) or not re.fullmatch(r'[0-9A-Za-z.+-]+', version)
                or not isinstance(checksum, str) or not re.fullmatch(r'[0-9a-f]{64}', checksum)):
            raise ValueError('invalid locked registry package')
        identity = name + '-' + version
        if identity in result:
            raise ValueError('duplicate locked package identity')
        result[identity] = checksum
    if not 0 < len(result) <= MAX_PACKAGES:
        raise ValueError('registry package count outside bound')
    return result


def add(archive, name, data=None, mode=0o444):
    guest_path(name)
    item = tarfile.TarInfo(name)
    item.uid = item.gid = item.mtime = 0
    item.mode = mode
    if data is None:
        item.type = tarfile.DIRTYPE
    else:
        item.size = len(data)
    archive.addfile(item, None if data is None else io.BytesIO(data))


def export(lockfile, lock_digest, cache, output):
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            stage = Path(temporary)
            locked = snapshot({'path':str(lockfile), 'digest':lock_digest},
                              4*1024**2, stage/'Cargo.lock')
            selected = packages(tomllib.loads(locked.read_text()))
            expanded = count = 0
            output_count = 5
            with tarfile.open(output/'cargo-vendor.tar', 'w', format=tarfile.USTAR_FORMAT) as target:
                for parent in ('opt', 'opt/factory'):
                    add(target, parent, mode=0o755)
                for parent in ('opt/factory/cargo-home', 'opt/factory/vendor'):
                    add(target, parent, mode=0o555)
                add(target, 'opt/factory/cargo-home/config.toml', CONFIG)
                for identity, checksum in sorted(selected.items()):
                    matches = list(Path(cache).glob('*/'+identity+'.crate'))
                    if len(matches) != 1:
                        raise ValueError('exactly one archive required for '+identity)
                    pinned = snapshot({'path':str(matches[0]), 'digest':'sha256:'+checksum},
                                      128*1024**2, stage/'package.crate')
                    files, modes, directories, seen = {}, {}, set(), set()
                    with tarfile.open(pinned, 'r:*') as source:
                        for item in source:
                            path = guest_path(item.name)
                            if (path is None or path in seen or not (item.isdir() or item.isfile())
                                    or item.mode & 0o7000
                                    or not (path == identity and item.isdir() or path.startswith(identity+'/'))):
                                raise ValueError('unsafe or unexpected crate member')
                            seen.add(path)
                            count += 1
                            if count > MAX_FILES:
                                raise ValueError('vendor path count exceeds bound')
                            relative = path[len(identity)+1:]
                            if not relative:
                                continue
                            if relative == '.cargo-checksum.json':
                                raise ValueError('upstream checksum file would be overwritten')
                            if item.isdir():
                                directories.add(relative)
                                continue
                            if not 0 <= item.size <= MAX_MEMBER:
                                raise ValueError('crate member exceeds bound')
                            expanded += item.size
                            if expanded > MAX_EXPANDED:
                                raise ValueError('expanded dependencies exceed bound')
                            with source.extractfile(item) as stream:
                                data = stream.read(item.size+1)
                            if len(data) != item.size:
                                raise ValueError('short crate member')
                            files[relative] = data
                            modes[relative] = 0o555 if item.mode & 0o111 else 0o444
                    for path in set(files) | directories:
                        for parent in Path(path).parents:
                            if str(parent) != '.':
                                directories.add(parent.as_posix())
                    if set(files) & directories:
                        raise ValueError('crate file conflicts with directory')
                    output_count += len(files) + len(directories) + 2
                    if output_count > MAX_FILES:
                        raise ValueError('generated vendor path count exceeds bound')
                    prefix = 'opt/factory/vendor/'+identity
                    add(target, prefix, mode=0o555)
                    for path in sorted(directories):
                        add(target, prefix+'/'+path, mode=0o555)
                    for path, data in sorted(files.items()):
                        add(target, prefix+'/'+path, data, modes[path])
                    checksums = {'package':checksum, 'files':{
                        path:hashlib.sha256(data).hexdigest() for path, data in sorted(files.items())}}
                    add(target, prefix+'/.cargo-checksum.json',
                        (json.dumps(checksums, sort_keys=True, separators=(',', ':'))+'\n').encode())
                    pinned.unlink()
            manifest = {'version':1, 'lock_digest':lock_digest, 'registry':REGISTRY,
                        'packages':selected, 'package_count':len(selected),
                        'expanded_source_bytes':expanded, 'archive_digest':sha(output/'cargo-vendor.tar'),
                        'config_path':'/opt/factory/cargo-home/config.toml', 'runtime_verified':False}
            (output/'export.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
            for path in output.iterdir():
                if path.is_file():
                    os.chmod(path,0o400)
                    with open(path,'rb') as file: os.fsync(file.fileno())
        descriptor = os.open(output, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        return manifest
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lockfile',type=Path,required=True)
    parser.add_argument('--lock-digest',required=True)
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = export(args.lockfile,args.lock_digest,args.cache,args.output)
    print(json.dumps({key:result[key] for key in ('package_count','archive_digest','runtime_verified')},sort_keys=True))


if __name__ == '__main__': main()
