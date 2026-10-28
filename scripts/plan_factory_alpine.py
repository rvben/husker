#!/usr/bin/env python3
"""Resolve a bounded Alpine ARM64 preparation closure from pinned local inputs.

This is not APK's general solver. Unsupported constraints/ambiguities fail closed.
No downloads, extraction to host paths, package installation or script execution.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

from prepare_factory_arm64 import snapshot

MAX_PACKAGES = 256
NAME = r'[A-Za-z0-9][A-Za-z0-9._+-]*'
VERSION = r'[0-9][A-Za-z0-9._~+-]*'
FIELDS = {'P','V','A','C','D','p','S','I'}


def records(text, index=True):
    if not isinstance(text,str) or len(text.encode()) > 32*1024**2:
        raise ValueError('package metadata exceeds bound')
    result = {}
    for section in text.strip().split('\n\n'):
        fields = {}
        for line in section.splitlines():
            if len(line) < 2 or line[1] != ':' or line[0] not in FIELDS:
                continue
            if line[0] in fields or len(line) > 32768:
                raise ValueError('duplicate or oversized package metadata field')
            fields[line[0]] = line[2:]
        if not fields:
            continue
        if (not re.fullmatch(NAME,fields.get('P','')) or not re.fullmatch(VERSION,fields.get('V',''))
                or fields.get('A') not in ('aarch64','noarch') or fields['P'] in result):
            raise ValueError('unexpected or duplicate package identity/architecture')
        if index and (not re.fullmatch(r'Q1[A-Za-z0-9+/]{27}=',fields.get('C',''))
                      or not fields.get('S','').isdigit() or not 0 < int(fields['S']) <= 2*1024**3):
            raise ValueError('bounded package size and APK v2 checksum required')
        result[fields['P']] = fields
        if len(result) > 20000:
            raise ValueError('package metadata count exceeds bound')
    if not result:
        raise ValueError('empty package metadata')
    return result


def metadata_member(path, name, maximum, ignore_zeros=False):
    found = None
    count = 0
    with tarfile.open(path,'r:*',ignore_zeros=ignore_zeros) as archive:
        for item in archive:
            count += 1
            if count > 200000:
                raise ValueError('archive member count exceeds bound')
            if item.name.removeprefix('./').rstrip('/') != name:
                continue
            if found is not None or not item.isfile() or not 0 < item.size <= maximum:
                raise ValueError('duplicate or unsafe package metadata member')
            with archive.extractfile(item) as source:
                found = source.read(item.size+1)
            if len(found) != item.size:
                raise ValueError('short metadata member')
    if found is None:
        raise ValueError('required package metadata absent')
    return found.decode('utf-8')


def dependency(token):
    match = re.fullmatch(r'([^<>=!~\s]+)(=|>=)?([^<>=!~\s]*)',token)
    if not match or (match[2] is None and match[3]) or (match[2] and not match[3]):
        raise ValueError('unsupported dependency constraint: '+token)
    return match[1], match[2], match[3]


def satisfies(actual, operator, expected):
    if operator is None:
        return True
    if actual is None:
        return False
    if operator == '=':
        return actual == expected
    # The closure currently needs only numeric >= comparisons. APK's suffix
    # ordering is deliberately not approximated: use APK elsewhere if needed.
    def numeric(value):
        match = re.fullmatch(r'(\d+(?:\.\d+)*)(?:-r(\d+))?',value)
        if match is None:
            raise ValueError('unsupported nonnumeric minimum version')
        return tuple(map(int,match[1].split('.'))), int(match[2] or 0)
    left, lr = numeric(actual); right, rr = numeric(expected)
    width = max(len(left),len(right))
    return (left+(0,)*(width-len(left)),lr) >= (right+(0,)*(width-len(right)),rr)


def offers(package):
    result = {package['P']:package['V']}
    for token in package.get('p','').split():
        key, separator, version = token.partition('=')
        if not key or key in result or any(char.isspace() for char in token):
            raise ValueError('duplicate or invalid package capability')
        result[key] = version if separator else None
    return result


def resolve(index, installed, roots, preferred=None):
    preferred = {} if preferred is None else preferred
    if (not isinstance(roots,list) or not 0 < len(roots) <= 64 or len(set(roots)) != len(roots)
            or any(not isinstance(name,str) or not re.fullmatch(NAME,name) for name in roots)):
        raise ValueError('unique explicit root package names required')
    capabilities = {origin:{name:offers(package) for name,package in packages.items()}
                    for origin,packages in (('base',installed),('index',index))}
    selected = {}
    pending = list(roots)
    edges = []
    while pending:
        token = pending.pop()
        key, operator, version = dependency(token)
        candidates = []
        for origin, packages in capabilities.items():
            for name, provides in packages.items():
                if key in provides and satisfies(provides[key],operator,version):
                    candidates.append((origin,name))
        chosen = [candidate for candidate in candidates if candidate[0] == 'base']
        if not chosen:
            chosen = [candidate for candidate in candidates if selected.get(candidate[1]) == candidate[0]]
        if not chosen:
            choice = preferred.get(key)
            chosen = [candidate for candidate in candidates if candidate[1] == choice] if choice else candidates
        if len(chosen) != 1:
            raise ValueError('dependency requires one explicit compatible provider: '+token)
        origin, name = chosen[0]
        if origin == 'index' and name in installed:
            raise ValueError('base package upgrade is not supported: '+name)
        if name in selected and selected[name] != origin:
            raise ValueError('base package upgrade is not supported: '+name)
        edges.append({'dependency':token,'provider':name,'origin':origin})
        if name in selected:
            continue
        selected[name] = origin
        if len(selected) > MAX_PACKAGES:
            raise ValueError('resolved package count exceeds bound')
        # All installed packages are already part of the pinned base. Validate
        # their dependencies too, instead of inferring compatibility from names.
        package = installed[name] if origin == 'base' else index[name]
        pending.extend(package.get('D','').split())
    # Validate all requirements again against the final selected set. No source
    # or base package may get a second incompatible provider after resolution.
    for edge in edges:
        key, operator, version = dependency(edge['dependency'])
        name, origin = edge['provider'],edge['origin']
        if selected.get(name) != origin or not satisfies(capabilities[origin][name][key],operator,version):
            raise ValueError('inconsistent resolved dependency')
    return selected, sorted(edges,key=lambda value:(value['dependency'],value['provider']))


def plan(index_pin, base_pin, roots, output, preferred=None):
    output = Path(output)
    output.mkdir(mode=0o700,exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            stage = Path(temporary)
            index_path = snapshot(index_pin,4*1024**2,stage/'index.tar.gz')
            base_path = snapshot(base_pin,256*1024**2,stage/'base.tar.gz')
            index = records(metadata_member(index_path,'APKINDEX',32*1024**2,True))
            installed = records(metadata_member(base_path,'lib/apk/db/installed',4*1024**2),index=False)
            selected, edges = resolve(index,installed,roots,preferred)
            packages = {}
            for name, origin in sorted(selected.items()):
                record = (installed if origin == 'base' else index)[name]
                if origin == 'index' and int(record['S']) > 128*1024**2:
                    raise ValueError('selected package archive exceeds preparation bound')
                packages[name] = {'version':record['V'],'architecture':record['A'],'origin':origin,
                                  'index_checksum':record.get('C'),
                                  'filename':None if origin == 'base' else name+'-'+record['V']+'.apk',
                                  'archive_size':None if origin == 'base' else int(record['S']),
                                  'dependencies':record.get('D','').split(),
                                  'provides':record.get('p','').split()}
            if sum(package['archive_size'] or 0 for package in packages.values()) > 256*1024**2:
                raise ValueError('combined package downloads exceed preparation bound')
            receipt = {'version':1,'architecture':'aarch64','index_digest':index_pin['digest'],
                       'base_digest':base_pin['digest'],'roots':roots,'preferred_providers':preferred or {},
                       'packages':packages,'dependency_edges':edges,
                       'publisher_signature_verified':False,'runtime_verified':False}
            (output/'closure.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
            os.chmod(output/'closure.json',0o400)
            with open(output/'closure.json','rb') as file: os.fsync(file.fileno())
        descriptor = os.open(output,os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        return receipt
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index',type=Path,required=True)
    parser.add_argument('--index-digest',required=True)
    parser.add_argument('--base',type=Path,required=True)
    parser.add_argument('--base-digest',required=True)
    parser.add_argument('--package',action='append',required=True)
    parser.add_argument('--provider',action='append',default=[],help='capability=package for ambiguous providers')
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    preferred = {}
    for item in args.provider:
        key, separator, value = item.partition('=')
        if not separator or not key or not re.fullmatch(NAME,value) or key in preferred:
            parser.error('unique capability=package provider choices required')
        preferred[key] = value
    result = plan({'path':str(args.index),'digest':args.index_digest},
                  {'path':str(args.base),'digest':args.base_digest},args.package,args.output,preferred)
    print(json.dumps({'package_count':len(result['packages']),
                      'downloads':sum(package['origin'] == 'index' for package in result['packages'].values()),
                      'runtime_verified':False},sort_keys=True))


if __name__ == '__main__': main()
