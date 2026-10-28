#!/usr/bin/env python3
"""Assemble pinned ARM64 musl Rust components offline, without running installers.

Python >=3.11 required. Inputs must already exist; no downloads or target execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import tomllib

from prepare_factory_arm64 import guest_path, members, sha, snapshot, write_tar
from export_factory_cargo import CONFIG

TARGET = 'aarch64-unknown-linux-musl'
COMPONENTS = {'rustc':'rustc', 'rust-std':'rust-std', 'cargo':'cargo',
              'clippy-preview':'clippy', 'rustfmt-preview':'rustfmt'}
BINARIES = ('rustc','rustdoc','cargo','cargo-clippy','clippy-driver','cargo-fmt','rustfmt')
MAX_EXPANDED = 2 * 1024**3
MAX_FILES = 200000


def pins(manifest, version):
    if (manifest.get('manifest-version') != '2'
            or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', manifest.get('date',''))
            or not re.fullmatch(r'\d+\.\d+\.\d+', version)):
        raise ValueError('version-two dated Rust manifest and release version required')
    result = {}
    for component, stem in COMPONENTS.items():
        package = manifest['pkg'][component]
        if component in ('rustc','rust-std') and not package['version'].startswith(version+' '):
            raise ValueError('component release does not match requested version')
        target = package['target'][TARGET]
        filename = stem+'-'+version+'-'+TARGET+'.tar.xz'
        expected = 'https://static.rust-lang.org/dist/'+manifest['date']+'/'+filename
        if (target.get('available') is not True or target.get('xz_url') != expected
                or not re.fullmatch(r'[0-9a-f]{64}',target.get('xz_hash',''))):
            raise ValueError('unexpected or unavailable pinned Rust component')
        result[component] = {'filename':filename,'digest':'sha256:'+target['xz_hash'],
                             'version':package['version']}
    return result


def payload(entries, prefix, component):
    def text(path):
        item = entries.get(prefix+'/'+path)
        if item is None or item[0] != 'file' or len(item[2]) > 1024*1024:
            raise ValueError('missing or oversized Rust installer metadata')
        return item[2].decode('utf-8')
    if any(path != prefix and not path.startswith(prefix+'/') for path in entries):
        raise ValueError('unexpected Rust archive root')
    if text('rust-installer-version').strip() != '3' or text('components').strip() != component:
        raise ValueError('unsupported Rust installer/component format')
    declared = {}
    for line in text(component+'/manifest.in').splitlines():
        kind, separator, path = line.partition(':')
        if (separator != ':' or kind not in ('file','dir') or guest_path(path) != path
                or path in declared or path == 'manifest.in'):
            raise ValueError('invalid installer manifest entry')
        declared[path] = kind
    if not declared:
        raise ValueError('empty installer manifest')
    root = prefix+'/'+component+'/'
    result = {path[len(root):]:value for path,value in entries.items()
              if path.startswith(root) and path != root+'manifest.in'}
    for path, kind in declared.items():
        if path not in result or result[path][0] != kind:
            raise ValueError('installer manifest references absent or different payload')
    for path, (kind, mode, data) in result.items():
        permitted = (path in declared or any(value == 'dir' and path.startswith(parent+'/')
                     for parent,value in declared.items())
                     or kind == 'dir' and any(child.startswith(path+'/') for child in declared))
        if not permitted or kind not in ('file','dir'):
            raise ValueError('undeclared or linked Rust payload')
        result[path] = (kind, 0o555 if kind == 'dir' or mode & 0o111 else 0o444, data)
    return result


def export(manifest_path, manifest_digest, archives, output, version='1.96.0', vendor=None):
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            stage = Path(temporary)
            manifest_file = snapshot({'path':str(manifest_path),'digest':manifest_digest},
                                     2*1024**2,stage/'channel.toml')
            manifest = tomllib.loads(manifest_file.read_text())
            selected = pins(manifest,version)
            root = 'opt/factory/rust/'+version
            entries = {'opt':('dir',0o755,b''),'opt/factory':('dir',0o755,b''),
                       'opt/factory/rust':('dir',0o555,b''),root:('dir',0o555,b'')}
            def bounded_members(path):
                remaining = MAX_EXPANDED - sum(len(value[2]) for value in entries.values())
                return members([path],maximum_expanded=remaining,
                               maximum_files=MAX_FILES-len(entries))
            for component, pin in selected.items():
                pinned = snapshot({'path':str(Path(archives)/pin['filename']),'digest':pin['digest']},
                                  256*1024**2,stage/'component.tar.xz')
                installer_component = 'rust-std-'+TARGET if component == 'rust-std' else component
                component_entries = payload(bounded_members(pinned),pin['filename'][:-7],installer_component)
                for path, value in component_entries.items():
                    destination = root+'/'+path
                    if destination in entries and entries[destination] != value:
                        raise ValueError('Rust components conflict')
                    entries[destination] = value
                pinned.unlink()
            binary_digests = {}
            for binary in BINARIES:
                value = entries.get(root+'/bin/'+binary)
                if value is None or value[0] != 'file' or value[1] != 0o555:
                    raise ValueError('missing executable Rust tool')
                data = value[2]
                if (len(data) < 64 or data[:6] != b'\x7fELF\x02\x01'
                        or int.from_bytes(data[18:20],'little') != 183):
                    raise ValueError('Rust tool is not little-endian ARM64 ELF')
                binary_digests[binary] = 'sha256:'+hashlib.sha256(data).hexdigest()
            if vendor is not None:
                pinned = snapshot(vendor,1024**3,stage/'vendor.tar')
                vendor_entries = bounded_members(pinned)
                if vendor_entries.get('opt/factory/cargo-home/config.toml') != ('file',0o444,CONFIG):
                    raise ValueError('verified offline vendor configuration required')
                for path, value in vendor_entries.items():
                    if not (path in ('opt','opt/factory','opt/factory/vendor','opt/factory/cargo-home')
                            or path.startswith('opt/factory/vendor/')
                            or path == 'opt/factory/cargo-home/config.toml') or value[0] == 'link':
                        raise ValueError('unexpected vendor layer path')
                    if path not in ('opt','opt/factory') and value[1] & 0o222:
                        raise ValueError('vendor layer must be read-only')
                    if path in entries and entries[path] != value:
                        raise ValueError('vendor and Rust layers conflict')
                    entries[path] = value
            if len(entries) > MAX_FILES or sum(len(value[2]) for value in entries.values()) > MAX_EXPANDED:
                raise ValueError('combined tool layer exceeds bound')
            write_tar(output/'tools.tar',entries)
            receipt = {'version':1,'target':TARGET,'rust_version':version,
                       'manifest_digest':manifest_digest,'manifest_date':manifest['date'],
                       'components':selected,'binaries':binary_digests,
                       'vendor_digest':None if vendor is None else vendor['digest'],
                       'tools_digest':sha(output/'tools.tar'),'rust_prefix':'/'+root,
                       'runtime_verified':False,'publisher_signature_verified':False}
            (output/'export.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
            for path in output.iterdir():
                if path.is_file():
                    os.chmod(path,0o400)
                    with open(path,'rb') as file: os.fsync(file.fileno())
        descriptor = os.open(output,os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        return receipt
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--manifest-digest',required=True)
    parser.add_argument('--archives',type=Path,required=True)
    parser.add_argument('--version',default='1.96.0')
    parser.add_argument('--vendor-layer',type=Path)
    parser.add_argument('--vendor-digest')
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if bool(args.vendor_layer) != bool(args.vendor_digest): parser.error('vendor path and digest must be supplied together')
    vendor = None if args.vendor_layer is None else {'path':str(args.vendor_layer),'digest':args.vendor_digest}
    result = export(args.manifest,args.manifest_digest,args.archives,args.output,args.version,vendor)
    print(json.dumps({key:result[key] for key in ('tools_digest','rust_prefix','runtime_verified')},sort_keys=True))


if __name__ == '__main__': main()
