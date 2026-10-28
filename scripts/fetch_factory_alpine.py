#!/usr/bin/env python3
"""Explicit public-package preparation step; never install or execute packages.

Downloads only the bounded packages from a digest-pinned offline closure plan.
Use separately from the network-free image assembler and source execution.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
import urllib.request

from factory_apk import verify_apk
from plan_factory_alpine import NAME, VERSION, MAX_PACKAGES
from prepare_factory_arm64 import snapshot

REPOSITORY = 'https://dl-cdn.alpinelinux.org/alpine/v3.23/main/aarch64/'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def selected_packages(plan):
    if (not isinstance(plan,dict) or type(plan.get('version')) is not int or plan['version'] != 1
            or plan.get('architecture') != 'aarch64' or not isinstance(plan.get('packages'),dict)
            or not 0 < len(plan['packages']) <= MAX_PACKAGES):
        raise ValueError('bounded version-one ARM64 closure plan required')
    selected = {}
    for name, package in plan['packages'].items():
        if not isinstance(package,dict) or package.get('origin') not in ('base','index'):
            raise ValueError('unexpected package origin')
        if package['origin'] == 'base':
            continue
        if (not re.fullmatch(NAME,name) or not isinstance(package.get('version'),str)
                or not re.fullmatch(VERSION,package['version'])
                or package.get('filename') != name+'-'+package['version']+'.apk'
                or package.get('architecture') not in ('aarch64','noarch')
                or type(package.get('archive_size')) is not int
                or not 0 < package['archive_size'] <= 128*1024**2
                or not isinstance(package.get('index_checksum'),str)
                or not re.fullmatch(r'Q1[A-Za-z0-9+/]{27}=',package['index_checksum'])
                or any(not isinstance(package.get(key),list)
                       or len(package[key]) > 4096 or any(not isinstance(value,str) or len(value)>1024 for value in package[key])
                       for key in ('dependencies','provides'))):
            raise ValueError('unexpected or unbounded downloadable package')
        selected[name] = package
    if not selected or sum(package['archive_size'] for package in selected.values()) > 256*1024**2:
        raise ValueError('download closure outside bounds')
    return selected


def download(name, package, output):
    url = REPOSITORY+package['filename']
    request = urllib.request.Request(url,headers={'User-Agent':'factory-preparation/1'})
    destination = output/package['filename']
    copied = 0
    started = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(request,timeout=30) as response, open(destination,'xb') as target:
        if response.url != url:
            raise ValueError('unexpected package redirect')
        while True:
            block = response.read(min(1024*1024,package['archive_size']-copied+1))
            if not block:
                break
            copied += len(block)
            if copied > package['archive_size'] or time.monotonic()-started > 180:
                raise ValueError('package download exceeds size/time bound')
            target.write(block)
        target.flush(); os.fsync(target.fileno())
    try:
        receipt, _ = verify_apk(destination.read_bytes(),package,name)
    except ValueError as error:
        raise ValueError(name+': '+str(error)) from error
    destination.chmod(0o400)
    return name,dict(receipt,filename=package['filename'],version=package['version'],archive_size=copied)


def fetch(plan_pin, output):
    output = Path(output)
    output.mkdir(mode=0o700,exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            pinned = snapshot(plan_pin,1024*1024,Path(temporary)/'closure.json')
            plan = json.loads(pinned.read_text())
            packages = selected_packages(plan)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(download,name,package,output) for name,package in sorted(packages.items())]
                results = {}
                try:
                    for future in concurrent.futures.as_completed(futures):
                        name, receipt = future.result()
                        results[name] = receipt
                except BaseException:
                    for future in futures: future.cancel()
                    raise
            receipt = {'version':1,'closure_digest':plan_pin['digest'],'repository':REPOSITORY,
                       'packages':results,'publisher_signature_verified':False,'runtime_verified':False}
            (output/'downloads.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
            os.chmod(output/'downloads.json',0o400)
            with open(output/'downloads.json','rb') as file: os.fsync(file.fileno())
        descriptor = os.open(output,os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        return receipt
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-digest',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = fetch({'path':str(args.plan),'digest':args.plan_digest},args.output)
    print(json.dumps({'package_count':len(result['packages']),
                      'downloaded_bytes':sum(package['archive_size'] for package in result['packages'].values()),
                      'runtime_verified':False},sort_keys=True))


if __name__ == '__main__': main()
