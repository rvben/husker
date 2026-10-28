#!/usr/bin/env python3
"""Assemble a pinned Alpine base/tool closure offline without package hooks.

Converts package-local hardlinks to regular files. Base replacements require an
explicit path and are limited to aliases of /bin/busybox. Never extracts on host.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import shutil
import tarfile
import tempfile

from factory_apk import verify_apk
from fetch_factory_alpine import selected_packages
from prepare_factory_arm64 import guest_path, members, sha, snapshot, write_tar

MAX_EXPANDED = 1024**3
MAX_FILES = 50000
CORE = ('usr/bin/gcc','usr/bin/g++','usr/bin/python3','usr/bin/git','usr/bin/cmake',
        'usr/bin/make','usr/bin/pkgconf','usr/bin/perl','bin/bash','usr/lib/libgcc_s.so.1')


def package_members(data, maximum_expanded, maximum_files):
    result, links = {}, {}
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        for item in archive:
            path = guest_path(item.name)
            if path is None:
                continue
            if path in result or path in links or len(result)+len(links) >= maximum_files or item.mode & 0o7000:
                raise ValueError('duplicate, oversized or privileged package payload')
            if item.isfile():
                if not 0 <= item.size <= 256*1024**2:
                    raise ValueError('package file exceeds bound')
                expanded += item.size
                if expanded > maximum_expanded:
                    raise ValueError('expanded package exceeds bound')
                with archive.extractfile(item) as source:
                    content = source.read(item.size+1)
                if len(content) != item.size:
                    raise ValueError('short package payload')
                result[path] = ('file',0o755 if item.mode & 0o111 else 0o644,content)
            elif item.isdir():
                result[path] = ('dir',0o755,b'')
            elif item.issym():
                result[path] = ('link',0o777,item.linkname)
            elif item.islnk():
                target = guest_path(item.linkname)
                if target is None:
                    raise ValueError('invalid package-local hardlink target')
                links[path] = target
            else:
                raise ValueError('special package payload is unsupported')
    for path, target in links.items():
        seen = {path}
        while target in links:
            if target in seen:
                raise ValueError('cyclic package hardlink')
            seen.add(target); target = links[target]
        if target not in result or result[target][0] != 'file':
            raise ValueError('hardlink must name a regular file in the same package')
        expanded += len(result[target][2])
        if expanded > maximum_expanded:
            raise ValueError('materialized package hardlinks exceed bound')
        result[path] = result[target]
    return result


def target_path(path, target):
    resolved = posixpath.normpath(target.lstrip('/') if target.startswith('/')
                                  else posixpath.join(posixpath.dirname(path),target))
    if resolved == '..' or resolved.startswith('../') or guest_path(resolved) != resolved:
        raise ValueError('guest link escapes root or is unsafe')
    return resolved


def resolve_file(entries, path):
    seen = set()
    while path in entries and entries[path][0] == 'link':
        if path in seen or len(seen) >= 32:
            raise ValueError('cyclic or excessive guest symlink chain')
        seen.add(path); path = target_path(path,entries[path][2])
    if path not in entries or entries[path][0] != 'file':
        raise ValueError('required guest file missing')
    return entries[path]


def export(closure_pin, downloads_pin, base_pin, packages_dir, output, replacements=None):
    replacements = set() if replacements is None else set(replacements)
    if any(guest_path(path) != path for path in replacements):
        raise ValueError('explicit canonical replacement paths required')
    output = Path(output); output.mkdir(mode=0o700,exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            stage = Path(temporary)
            closure_file = snapshot(closure_pin,1024*1024,stage/'closure.json')
            downloads_file = snapshot(downloads_pin,1024*1024,stage/'downloads.json')
            base_file = snapshot(base_pin,256*1024**2,stage/'base.tar.gz')
            closure, downloads = json.loads(closure_file.read_text()),json.loads(downloads_file.read_text())
            selected = selected_packages(closure)
            if (closure.get('base_digest') != base_pin['digest']
                    or type(downloads.get('version')) is not int or downloads['version'] != 1
                    or downloads.get('closure_digest') != closure_pin['digest']
                    or not isinstance(downloads.get('packages'),dict)
                    or set(downloads['packages']) != set(selected)):
                raise ValueError('base, closure and download receipts must agree')
            entries = members([base_file],maximum_expanded=MAX_EXPANDED,maximum_files=MAX_FILES)
            changed, receipts = [], {}
            for name, package in sorted(selected.items()):
                receipt = downloads['packages'][name]
                if receipt.get('filename') != package['filename']:
                    raise ValueError('download receipt filename changed')
                pinned = snapshot({'path':str(Path(packages_dir)/package['filename']),
                                   'digest':receipt['archive_digest']},128*1024**2,stage/'package.apk')
                verified, data = verify_apk(pinned.read_bytes(),package,name)
                if any(verified[key] != receipt.get(key) for key in verified):
                    raise ValueError('download receipt integrity fields changed')
                remaining = MAX_EXPANDED-sum(len(value[2]) for value in entries.values())
                paths_remaining = MAX_FILES-len(entries)
                payload = package_members(data,remaining,paths_remaining)
                normalized = stage/'package.tar'
                write_tar(normalized,payload)
                # Reuse the image reader's parent/link checks. No host extraction
                # happens even for symlinks or package-local hardlink materialization.
                normalized_entries = members([normalized],maximum_expanded=remaining,maximum_files=paths_remaining)
                for path, value in normalized_entries.items():
                    previous = entries.get(path)
                    if previous is not None and previous != value:
                        if (path not in replacements or previous[0] != 'link' or value[0] != 'file'
                                or target_path(path,previous[2]) != 'bin/busybox'):
                            raise ValueError('package would overwrite a different base/package path: '+path)
                        changed.append({'path':path,'package':name,'previous_target':previous[2],
                                        'new_digest':'sha256:'+hashlib.sha256(value[2]).hexdigest()})
                    entries[path] = value
                receipts[name] = verified
                pinned.unlink(); normalized.unlink()
            if {item['path'] for item in changed} != replacements:
                raise ValueError('every declared replacement must be exercised exactly')
            # Check parent/link consistency across the complete merged namespace,
            # not just within individual package archives.
            write_tar(output/'base.tar',entries)
            merged = members([output/'base.tar'],maximum_expanded=MAX_EXPANDED,maximum_files=MAX_FILES)
            binaries = {}
            for path in CORE:
                kind, mode, data = resolve_file(merged,path)
                if (len(data) < 64 or data[:6] != b'\x7fELF\x02\x01'
                        or int.from_bytes(data[18:20],'little') != 183):
                    raise ValueError('required core tool/library is not ARM64 ELF: '+path)
                binaries[path] = 'sha256:'+hashlib.sha256(data).hexdigest()
            manifest = {'version':1,'architecture':'aarch64','closure_digest':closure_pin['digest'],
                        'downloads_digest':downloads_pin['digest'],'original_base_digest':base_pin['digest'],
                        'base_digest':sha(output/'base.tar'),'packages':receipts,'core_binaries':binaries,
                        'replacements':changed,'package_hooks_executed':False,
                        'package_database_updated':False,'publisher_signature_verified':False,'runtime_verified':False}
            (output/'export.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
            for path in output.iterdir():
                if path.is_file():
                    path.chmod(0o400)
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
    for name in ('closure','downloads','base'):
        parser.add_argument('--'+name,type=Path,required=True)
        parser.add_argument('--'+name+'-digest',required=True)
    parser.add_argument('--packages',type=Path,required=True)
    parser.add_argument('--replace-busybox-applet',action='append',default=[])
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    pin = lambda name:{'path':str(getattr(args,name)),'digest':getattr(args,name+'_digest')}
    result = export(pin('closure'),pin('downloads'),pin('base'),args.packages,args.output,args.replace_busybox_applet)
    print(json.dumps({'base_digest':result['base_digest'],'package_count':len(result['packages']),
                      'runtime_verified':False},sort_keys=True))


if __name__ == '__main__': main()
