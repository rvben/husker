#!/usr/bin/env python3
"""Prepare, then opt in to 50 sequential and four concurrent boundary jobs.

This does not start a daemon, import an image, inject faults or prove promotion.
Execution needs separately approved capacity for four VMs. Recovery is GET-only.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import factory_boundary_e2e as boundary
from examples.factory_checks_v1 import FactoryChecksV1, Journal, canonical, digest, submission_for_stage, utc
from husker import Client

COUNT = 54


def private_directory(path):
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError('run directory must be owned, private 0700 and not a symlink')


def write_once(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def prepare(path, image_path, source_path, acceptance_path, probe_digest, disk_size):
    resources = boundary.proof_resources(disk_size)
    image = boundary.bounded(image_path, 4096)
    json.loads(image)
    source = boundary.bounded(source_path, 32*1024**2)
    acceptance = boundary.bounded(acceptance_path, 32*1024**2)
    boundary.validate_inputs(source, acceptance, probe_digest)
    path.mkdir(mode=0o700)  # Exclusive namespace: never reuse an old run.
    private_directory(path)
    for name, data in [('image.json', image), ('source.tar', source), ('acceptance.tar', acceptance)]:
        write_once(path/name, data)
    plan = dict(version=1, run_id=str(uuid.uuid4()), sequential=50, concurrent=4, probe_digest=probe_digest,
                resources=resources, pins={name: digest(data) for name, data in
                    [('image.json', image), ('source.tar', source), ('acceptance.tar', acceptance)]})
    write_once(path/'plan.json', canonical(plan).encode())
    return plan


def load(path):
    private_directory(path)
    plan = json.loads(boundary.bounded(path/'plan.json', 4096))
    if (set(plan) != {'version','run_id','sequential','concurrent','probe_digest','resources','pins'}
            or str(uuid.UUID(plan['run_id'])) != plan['run_id'] or uuid.UUID(plan['run_id']).int == 0
            or type(plan['version']) is not int or plan['version'] != 1
            or type(plan['sequential']) is not int or plan['sequential'] != 50
            or type(plan['concurrent']) is not int or plan['concurrent'] != 4
            or plan['resources'] != boundary.proof_resources(plan['resources']['disk_size_bytes'])
            or any(type(value) is not int for value in plan['resources'].values())
            or set(plan['pins']) != {'image.json','source.tar','acceptance.tar'}):
        raise ValueError('unsupported or altered soak plan')
    inputs = {name: boundary.bounded(path/name, 4096 if name == 'image.json' else 32*1024**2)
              for name in plan['pins']}
    if any(digest(data) != plan['pins'][name] for name, data in inputs.items()):
        raise ValueError('prepared soak input changed')
    boundary.validate_inputs(inputs['source.tar'], inputs['acceptance.tar'], plan['probe_digest'])
    return plan, inputs


def observe_case(path, index, plan, inputs, client_factory, inspect=False):
    key = 'factory-soak-v1-' + plan['run_id'] + '-' + str(index)
    journal_path = path/f'case-{index:02d}.sqlite'
    if inspect and not journal_path.exists():
        return dict(index=index, status='not_started')
    journal = Journal(journal_path)
    try:
        client = client_factory()  # Each thread owns its client and SQLite connection.
        adapter = FactoryChecksV1(client, journal)
        if inspect:
            row = journal.get(key)
            submission = json.loads(row['submission'])
            boundary.validate_specification(submission['specification'])
            if (row['source'] != inputs['source.tar'] or row['acceptance'] != inputs['acceptance.tar']
                    or submission['specification']['image'] != json.loads(inputs['image.json'])
                    or submission['specification']['resources'] != plan['resources']):
                raise ValueError('journal does not match prepared soak inputs')
            if row['acceptance_replayed'] == 1:
                raise ValueError('replayed acceptance cannot count as a fresh soak job')
            evidence = adapter.collect(key)
        else:
            now = int(time.time())
            submission = submission_for_stage(key, json.loads(inputs['image.json']),
                inputs['source.tar'], inputs['acceptance.tar'],
                [['/workspace/factory-boundary-probe','--factory-boundary']],
                correlation=dict(job='offline-boundary-proof',stage='baseline',round=0),
                claim_deadline=now+601, stage='baseline', now=now, resources=plan['resources'])
            submission['specification']['commands'][0]['timeout_secs'] = 30
            submission['execution_specification_digest'] = digest(canonical(submission['specification']).encode())
            boundary.validate_specification(submission['specification'])
            evidence = adapter.run_checks(submission, inputs['source.tar'], inputs['acceptance.tar'],
                retention_until=utc(now+86400), claim_deadline=now+601, require_fresh_receipt=True)
        identity = evidence['executionIdentity']
        stdout, stderr = boundary.collect_logs(client.job(identity['jobId'],
            specification_digest=identity['specificationDigest']))
        boundary.validate_output(stdout, stderr)
        if len(evidence['results']) != 1 or evidence['results'][0]['exitCode'] != 0:
            raise ValueError('boundary command failed')
        return dict(index=index, status='passed', executionIdentity=identity,
                    fresh_acceptance_proven=journal.get(key)['acceptance_replayed'] == 0)
    except Exception as error:
        # Do not expose transport bodies, bearer credentials or guest output.
        return dict(index=index, status='unresolved', error_type=type(error).__name__)
    finally:
        journal.close()


def run_cases(observe, inspect=False):
    results = []
    for index in range(50):
        result = observe(index)
        results.append(result)
        if not inspect and result['status'] != 'passed':
            return results  # Never extend a failed run with fresh executions.
    with ThreadPoolExecutor(max_workers=4) as executor:
        results.extend(executor.map(observe, range(50, COUNT)))
    return results


def summarize(results):
    identities = [item['executionIdentity'] for item in results if item['status'] == 'passed']
    unique = all(len({item[field] for item in identities}) == len(identities)
                 for field in ('jobId','sessionId','vmId'))
    passed = (len(results) == COUNT and len(identities) == COUNT and unique
              and [item['index'] for item in results] == list(range(COUNT))
              and all(item.get('fresh_acceptance_proven') is True for item in results))
    return dict(status='passed' if passed else 'incomplete', scope='boundary-soak-v1',
                promotion_proven=False, host_resource_cleanup_proven=False,
                fault_injection_proven=False, bounded_client_concurrency=4,
                overlapping_guest_execution_proven=False, distinct_identities=unique, cases=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare','execute','inspect'])
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--image', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--acceptance', type=Path)
    parser.add_argument('--probe-digest')
    parser.add_argument('--disk-size-bytes', type=int, default=8*1024**3)
    parser.add_argument('--url')
    args = parser.parse_args()
    if args.mode == 'prepare':
        if any(value is None for value in (args.image,args.source,args.acceptance,args.probe_digest)):
            parser.error('prepare requires pinned image, source, acceptance and probe digest')
        plan = prepare(args.run_dir,args.image,args.source,args.acceptance,args.probe_digest,args.disk_size_bytes)
        print(json.dumps(dict(status='prepared', activated=False, promotion_proven=False, plan=plan)))
        return
    if os.environ.get('HUSKER_RUN_FACTORY_SOAK') != '1':
        print(json.dumps(dict(status='skipped', activated=False, reason='explicit approved opt-in required')))
        return
    token = os.environ.get('HUSKER_FACTORY_SOAK_TOKEN')
    if not args.url or not token:
        parser.error('URL and HUSKER_FACTORY_SOAK_TOKEN required')
    plan, inputs = load(args.run_dir)
    if args.mode == 'execute':
        write_once(args.run_dir/'execution-attempted', b'GET-only recovery; never execute this run again\n')
    results = run_cases(lambda index: observe_case(args.run_dir,index,plan,inputs,
        lambda: Client(args.url,token=token,timeout=30), inspect=args.mode == 'inspect'),
        inspect=args.mode == 'inspect')
    result = summarize(results)
    print(json.dumps(result))
    if result['status'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
