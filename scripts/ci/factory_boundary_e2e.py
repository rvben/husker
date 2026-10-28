#!/usr/bin/env python3
"""Opt-in offline factory-job boundary subset on an approved isolated daemon.

No installation, daemon restart, image import, model invocation or remote shell.
An uncertain submission is inspected read-only; rerunning its key is prohibited.
"""
import argparse
import io
import json
import os
import stat
from pathlib import Path
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from husker import Client  # noqa: E402
from examples.factory_checks_v1 import FactoryChecksV1, Journal, canonical, digest, submission_for_stage, utc  # noqa: E402

NAMES = {'uid-gid-groups', 'capabilities-and-no-new-privileges',
         'no-external-network-interfaces', 'no-shared-filesystem-types',
         'credential-environment-absent', 'frozen-source-not-writable',
         'acceptance-not-writable', 'management-identity-not-readable',
         'ipv4-kernel-route-denied', 'ipv6-kernel-route-denied', 'dns-udp-kernel-route-denied'}
SENTINEL = b'factory-boundary-sentinel-v1\n'


def proof_resources(disk_size_bytes):
    if (type(disk_size_bytes) is not int
            or not 1024**3 <= disk_size_bytes <= 32*1024**3
            or disk_size_bytes % 4096):
        raise ValueError('proof disk must be 4 KiB aligned and between 1 and 32 GiB')
    return dict(vcpu_count=1,mem_size_mib=512,disk_size_bytes=disk_size_bytes,pids_limit=64)


def validate_specification(spec):
    resources = spec.get('resources', {})
    if (not isinstance(resources, dict)
            or resources != proof_resources(resources.get('disk_size_bytes'))
            or any(type(value) is not int for value in resources.values())
            or spec.get('commands') != [dict(argv=['/workspace/factory-boundary-probe','--factory-boundary'],timeout_secs=30)]
            or spec.get('correlation') != dict(job='offline-boundary-proof',stage='baseline',round=0)
            or spec.get('network') != {'mode':'none'} or spec.get('uid') != 1000 or spec.get('gid') != 1000
            or spec.get('working_directory') != '/workspace'
            or spec.get('environment') != {} or spec.get('writable_directories') != []
            or spec.get('artifacts') != []):
        raise ValueError('journaled job is not this boundary proof')


def bounded(path, limit):
    descriptor = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as file:
        metadata = os.fstat(file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
            raise ValueError('proof input must be a bounded unlinked regular file')
        data = file.read(limit + 1)
    if len(data) > limit or len(data) != metadata.st_size:
        raise ValueError('proof input changed or exceeds bound')
    return data


def validate_inputs(source, acceptance, probe_digest):
    for data, names in ((source, {'factory-boundary-probe', 'frozen-sentinel'}),
                        (acceptance, {'frozen-sentinel'})):
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            items = archive.getmembers()
            if (len(items) != len(names) or {item.name for item in items} != names
                    or any(not item.isfile() or item.size > 4*1024*1024 for item in items)):
                raise ValueError('proof requires only the pinned binary and fixed sentinel files')
            if archive.extractfile('frozen-sentinel').read() != SENTINEL:
                raise ValueError('proof sentinel mismatch')
            if 'factory-boundary-probe' in names:
                item = archive.getmember('factory-boundary-probe')
                if item.mode != 0o755 or digest(archive.extractfile(item).read()) != probe_digest:
                    raise ValueError('reviewed executable probe pin mismatch')


def validate_output(stdout, stderr):
    if stderr or len(stdout) > 65536:
        raise ValueError('unexpected stderr or oversized probe evidence')
    records = [json.loads(line) for line in stdout.decode('utf-8').splitlines()]
    checks, summaries = {}, []
    for record in records:
        if record.get('type') == 'check':
            if (set(record) != {'type','name','ok','errno'} or record['name'] not in NAMES
                    or record['name'] in checks or record['ok'] is not True
                    or type(record['errno']) is not int or not 0 <= record['errno'] <= 4095):
                raise ValueError('failed, repeated or unknown boundary check')
            checks[record['name']] = record
        elif record.get('type') == 'summary':
            summaries.append(record)
        else:
            raise ValueError('unknown probe evidence record')
    if (set(checks) != NAMES or len(summaries) != 1
            or summaries[0] != dict(type='summary',scope='offline-job-subset-v1',checks=len(NAMES),failed=0)
            or type(summaries[0]['checks']) is not int or type(summaries[0]['failed']) is not int):
        raise ValueError('incomplete boundary evidence')
    return list(checks.values())


def collect_logs(job):
    cursor, stdout, stderr = 0, bytearray(), bytearray()
    for _ in range(33):
        page = job.events(after=cursor)
        if page.output_truncated:
            raise ValueError('truncated probe evidence')
        for event in page.events:
            (stdout if event.stream == 'stdout' else stderr).extend(event.data)
        if len(stdout) + len(stderr) > 65536:
            raise ValueError('oversized probe evidence')
        cursor = page.next_cursor
        if not page.has_more:
            return bytes(stdout), bytes(stderr)
    raise ValueError('probe event pagination exceeded bound')


def main():
    if os.environ.get('HUSKER_RUN_FACTORY_BOUNDARY_E2E') != '1':
        print(json.dumps({'status':'skipped','reason':'approved isolated daemon and explicit opt-in required'}))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',required=True)
    parser.add_argument('--journal',required=True,type=Path)
    parser.add_argument('--key',required=True)
    parser.add_argument('--inspect',action='store_true')
    parser.add_argument('--image',type=Path)
    parser.add_argument('--source',type=Path)
    parser.add_argument('--acceptance',type=Path)
    parser.add_argument('--probe-digest',required=True)
    parser.add_argument('--disk-size-bytes',type=int,default=2*1024**3,
                        help='new proof disk capacity; must cover the pinned image (default: 2 GiB)')
    args = parser.parse_args()
    token = os.environ.get('HUSKER_FACTORY_BOUNDARY_E2E_TOKEN')
    if not token:
        parser.error('explicit bearer token required in HUSKER_FACTORY_BOUNDARY_E2E_TOKEN')
    client = Client(args.url,token=token,timeout=30)
    journal = Journal(args.journal)
    try:
        adapter = FactoryChecksV1(client,journal)
        if args.inspect:
            row = journal.get(args.key)
            validate_inputs(row['source'],row['acceptance'],args.probe_digest)
            spec = json.loads(row['submission'])['specification']
            validate_specification(spec)
            evidence = adapter.collect(args.key) # GET lookup; never POST or execute.
        else:
            if any(value is None for value in (args.image,args.source,args.acceptance,args.probe_digest)):
                parser.error('new proof requires image, frozen bundles and reviewed probe digest')
            source, acceptance = bounded(args.source,32*1024**2), bounded(args.acceptance,32*1024**2)
            validate_inputs(source,acceptance,args.probe_digest)
            image = json.loads(bounded(args.image,4096))
            now = int(time.time()); claim_deadline = now+601
            submission = submission_for_stage(args.key,image,source,acceptance,
                [['/workspace/factory-boundary-probe','--factory-boundary']],
                correlation=dict(job='offline-boundary-proof',stage='baseline',round=0),
                claim_deadline=claim_deadline,stage='baseline',now=now,
                resources=proof_resources(args.disk_size_bytes))
            submission['specification']['commands'][0]['timeout_secs']=30
            validate_specification(submission['specification'])
            submission['execution_specification_digest']=digest(canonical(submission['specification']).encode())
            evidence = adapter.run_checks(submission,source,acceptance,
                retention_until=utc(now+86400),claim_deadline=claim_deadline)
        identity = evidence['executionIdentity']
        job = client.job(identity['jobId'],specification_digest=identity['specificationDigest'])
        stdout, stderr = collect_logs(job) # Retained host logs, after confirmed VM destruction.
        checks = validate_output(stdout,stderr)
        if len(evidence['results']) != 1 or evidence['results'][0]['exitCode'] != 0:
            raise ValueError('probe command did not succeed')
        print(json.dumps(dict(status='passed',scope='offline-job-subset-v1',
                              promotion_proven=False,checks=checks,executionIdentity=identity)))
    finally:
        journal.close()

if __name__ == '__main__': main()
