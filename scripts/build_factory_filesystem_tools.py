#!/usr/bin/env python3
"""Build local tar-capable filesystem tools offline; never install or boot a VM.

Requires Python >=3.12, a compiler, make, pkg-config and an existing libarchive.
The reviewed upstream source archive must already be downloaded locally.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from prepare_factory_arm64 import snapshot, sha

SOURCE_SHA256 = '2cec05f39c20ee621f14926195664e66e6017190ac8e4bbdb16d86082e43c5da'
SOURCE_VERSION = '1.47.4'


def build(source_archive, libarchive_prefix, output, compiler, make, pkg_config):
    if not hasattr(tarfile, 'data_filter'):
        raise RuntimeError('Python >=3.12 with safe archive extraction is required')
    prefix = Path(libarchive_prefix).resolve(strict=True)
    if not (prefix/'lib/pkgconfig/libarchive.pc').is_file():
        raise ValueError('explicit installed libarchive pkg-config metadata required')
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            stage = Path(temporary)
            archive = snapshot({'path':str(source_archive), 'digest':'sha256:'+SOURCE_SHA256},
                               16*1024**2, stage/'source.tar.gz')
            with tarfile.open(archive) as source:
                items = source.getmembers()
                if (len(items) > 10000 or sum(item.size for item in items) > 128*1024**2
                        or any(not (item.name.startswith('e2fsprogs-'+SOURCE_VERSION+'/')
                                    or item.name == 'e2fsprogs-'+SOURCE_VERSION and item.isdir())
                               or not (item.isfile() or item.isdir() or item.issym())
                               or item.mode & 0o6000 for item in items)):
                    raise ValueError('unexpected pinned source archive layout')
                source.extractall(stage, members=items, filter='data')
            source = stage/('e2fsprogs-'+SOURCE_VERSION)
            build_dir = stage/'build'; build_dir.mkdir()
            temp_dir = stage/'tmp'; temp_dir.mkdir(mode=0o700)
            # Executable paths are explicit, resolved before the scrubbed build.
            compiler = Path(compiler).resolve(strict=True)
            make = Path(make).resolve(strict=True)
            pkg_config = Path(pkg_config).resolve(strict=True)
            env = {'PATH':'/usr/bin:/bin', 'LC_ALL':'C', 'CC':str(compiler),
                   'TMPDIR':str(temp_dir), 'PKG_CONFIG':str(pkg_config),
                   'PKG_CONFIG_PATH':str(prefix/'lib/pkgconfig'),
                   'CPPFLAGS':'-I'+str(prefix/'include'), 'LDFLAGS':'-L'+str(prefix/'lib')}
            compiler_version = subprocess.run([str(compiler),'--version'], env=env,
                check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            archive_version = subprocess.run([str(pkg_config),'--modversion','libarchive'], env=env,
                check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            commands = [[str(source/'configure'), '--disable-nls', '--disable-e2initrd-helper',
                         '--disable-fuse2fs', '--with-libarchive=direct', 'MKDIR_P=mkdir -p'],
                        [str(make), '-j4']]
            logs = {}
            for name, command in zip(('configure','build'), commands):
                log_path = stage/(name+'.log')
                with open(log_path, 'wb') as log:
                    result = subprocess.run(command, cwd=build_dir, env=env,
                                            stdout=log, stderr=subprocess.STDOUT, timeout=300)
                with open(log_path, 'rb') as log:
                    log.seek(max(0, log_path.stat().st_size-65536))
                    logs[name] = log.read().decode(errors='replace')
                if result.returncode:
                    raise RuntimeError(name+' failed: '+logs[name][-4096:])
            config = (build_dir/'lib/config.h').read_text()
            if ('#define CONFIG_DISABLE_LIBARCHIVE 1' in config
                    or '#define HAVE_ARCHIVE_H 1' not in config
                    or '#define CONFIG_DLOPEN_LIBARCHIVE 1' in config):
                raise RuntimeError('build did not enable direct libarchive support')
            for name, relative in (('mke2fs','misc/mke2fs'), ('e2fsck','e2fsck/e2fsck'),
                                   ('debugfs','debugfs/debugfs')):
                shutil.copyfile(build_dir/relative, output/name)
                os.chmod(output/name, 0o500)
            manifest = {'version':1, 'source_version':SOURCE_VERSION,
                        'source_digest':'sha256:'+SOURCE_SHA256,
                        'compiler_version':compiler_version, 'compiler_digest':sha(compiler),
                        'libarchive_version':archive_version,
                        'libarchive_prefix':str(prefix), 'libarchive_direct':True,
                        'dynamic_dependencies_pinned':False, 'runtime_verified':False,
                        'outputs':{name:sha(output/name) for name in ('mke2fs','e2fsck','debugfs')}}
            (output/'build.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
            for name, content in logs.items():
                (output/(name+'.log')).write_text(content)
            for name in ('build.json','configure.log','build.log'):
                os.chmod(output/name,0o400)
            for path in output.iterdir():
                if path.is_file():
                    with open(path,'rb') as file: os.fsync(file.fileno())
        descriptor = os.open(output,os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        return manifest
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--libarchive-prefix',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--compiler',default='/usr/bin/clang',type=Path)
    parser.add_argument('--make',default='/usr/bin/make',type=Path)
    parser.add_argument('--pkg-config',required=True,type=Path)
    args=parser.parse_args()
    result=build(args.source,args.libarchive_prefix,args.output,args.compiler,args.make,args.pkg_config)
    print(json.dumps(result['outputs'],sort_keys=True))

if __name__ == '__main__': main()
