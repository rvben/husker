#!/usr/bin/env python3
"""Assemble an offline native-reaper bundle from explicit pinned local inputs.

Copies prebuilt artifacts; never downloads, builds, installs, starts a daemon,
boots a VM, or injects a fault. See docs/native-reaper-regression.md.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import prepare_factory_arm64 as common
sys.path.insert(0, str(Path(__file__).resolve().parent/'ci'))
import factory_native_reaper_e2e as native

ARTIFACTS = {'daemon': 'bin/husker', 'firecracker': 'bin/firecracker',
             'probe': 'bin/factory-lifecycle-probe', 'kernel': 'prepared/vmlinux',
             'rootfs': 'prepared/rootfs.ext4'}
SOURCE_FILES = native.SUPPORT+['scripts/prepare_factory_native_reaper.py', 'scripts/prepare_factory_arm64.py']


def source_identity():
    revision = subprocess.check_output(['git', 'rev-parse', '--verify', 'HEAD'], cwd=ROOT, text=True).strip()
    native.require(re.fullmatch('[0-9a-f]{40}', revision), 'Git source revision required')
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all', '--ignored=matching', '--',
                                     *SOURCE_FILES], cwd=ROOT)
    return dict(source_revision=revision, source_files_clean=not dirty,
                source_files={name: native.pin(ROOT/name, 1024**2) for name in SOURCE_FILES})


def validate_artifact_headers(bundle):
    # Format/architecture sanity only; these checks are not boot or provenance proofs.
    for name in ('daemon', 'firecracker', 'probe', 'kernel'):
        with (bundle/ARTIFACTS[name]).open('rb') as stream:
            header = stream.read(64)
        native.require(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01'
                       and int.from_bytes(header[18:20], 'little') == 62,
                       name+' must be a little-endian x86_64 ELF64 file')
    with (bundle/'prepared/rootfs.ext4').open('rb') as stream:
        stream.seek(1080)
        native.require(stream.read(2) == b'\x53\xef', 'rootfs must have an ext4 superblock')


def payload(path, probe=None):
    import factory_lifecycle_e2e as lifecycle
    with path.open('xb') as archive:
        archive.write(lifecycle.frozen_payload(None if probe is None else probe.read_bytes()))


def assemble(plan, output):
    native.require(isinstance(plan, dict) and set(plan) == {'version', 'daemon_build_revision', 'inputs'}
                   and type(plan['version']) is int and plan['version'] == 1,
                   'exact version-one preparation plan required')
    native.require(isinstance(plan['daemon_build_revision'], str)
                   and re.fullmatch('[0-9a-f]{40}', plan['daemon_build_revision']),
                   'declared daemon build revision must be a full Git commit')
    native.require(isinstance(plan['inputs'], dict) and set(plan['inputs']) == set(ARTIFACTS),
                   'exact pinned artifact inventory required')
    native.require(output.is_absolute() and output.parent.resolve() == output.parent,
                   'output must have an absolute canonical parent')
    before = source_identity()
    output.mkdir(mode=0o700)  # Exclusive; never adopt or delete a caller's existing output.
    try:
        for name in ('bin', 'prepared', 'inputs'):
            (output/name).mkdir(mode=0o700)
        for name, relative in ARTIFACTS.items():
            common.snapshot(plan['inputs'][name], native.INPUTS[relative], output/relative,
                            executable=name in ('daemon', 'firecracker', 'probe'))
        validate_artifact_headers(output)
        payload(output/'inputs/source.tar', output/'bin/factory-lifecycle-probe')
        payload(output/'inputs/acceptance.tar')
        # Use the real job parser before sealing; no SDK/API operation is performed.
        import factory_lifecycle_e2e as lifecycle
        lifecycle.validate_inputs((output/'inputs/source.tar').read_bytes(),
                                  (output/'inputs/acceptance.tar').read_bytes(),
                                  plan['inputs']['probe']['digest'])
        native.require(source_identity() == before, 'preparation source changed during assembly')
        provenance = dict(version=1, **before, daemon_build_revision=plan['daemon_build_revision'],
                          daemon_build_revision_verified=False, runtime_verified=False,
                          hermetic_build=False,
                          artifacts={name: native.pin(output/relative, native.INPUTS[relative])
                                     for name, relative in ARTIFACTS.items()})
        result = native.prepare(output, preparation=provenance)
        manifest = native.verify(output, result['sha256'])
        for relative in native.SUPPORT:
            native.require(manifest['files']['support/'+relative] == before['source_files'][relative],
                           'frozen support differs from source snapshot')
        native.require(source_identity() == before, 'preparation source changed before sealing')
        for path in output.rglob('*'):
            if path.is_file():
                path.chmod(0o500 if path.stat().st_mode & 0o111 else 0o400)
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
        for path in [*(p for p in output.rglob('*') if p.is_dir()), output]:
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return dict(result, source_revision=before['source_revision'], source_files_clean=before['source_files_clean'],
                    daemon_build_revision=plan['daemon_build_revision'], daemon_build_revision_verified=False)
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    descriptor = os.open(args.plan, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        native.require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'plan must be a regular file')
        raw = stream.read(65537)
    native.require(len(raw) <= 65536, 'plan exceeds 64 KiB')
    print(json.dumps(assemble(json.loads(raw), args.output), sort_keys=True))


if __name__ == '__main__':
    os.umask(0o077)
    sys.dont_write_bytecode = True
    main()
