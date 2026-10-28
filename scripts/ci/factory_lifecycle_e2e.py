#!/usr/bin/env python3
"""Opt-in command-failure, timeout and cancellation escaped-family probes.

Requires an approved isolated daemon and separately reviewed pinned bundles.
Does not restart services, import images or remove evidence. Recovery is GET-only.
"""
import argparse
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import factory_boundary_e2e as boundary
import factory_soak as soak
from examples.factory_checks_v1 import FactoryChecksV1, Journal, canonical, digest, submission_for_stage, utc
from husker import Client

CASES = ('command_failed', 'timed_out', 'cancelled')
ALL_CASES = CASES + ('pids_limit',)
PIDS = dict(type='limit',scope='pids-pressure-v1',spawned=63,pids_max=64,pids_current=64,
            limit_event_increased=True,fork_errno=11)

def outcome(case):
    return 'completed' if case == 'pids_limit' else case
READY = dict(type='ready',scope='escaped-family-v1',descendants=2,setsid=True,ignore_sigterm=True)


def validate_inputs(source, acceptance, probe_digest):
    for data, names in ((source, {'factory-lifecycle-probe','frozen-sentinel'}),
                        (acceptance, {'frozen-sentinel'})):
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            items = archive.getmembers()
            if (len(items) != len(names) or {item.name for item in items} != names
                    or any(not item.isfile() or item.size > 4*1024**2 for item in items)):
                raise ValueError('only the reviewed lifecycle probe and sentinel are allowed')
            if archive.extractfile('frozen-sentinel').read() != boundary.SENTINEL:
                raise ValueError('sentinel changed')
            if 'factory-lifecycle-probe' in names:
                item = archive.getmember('factory-lifecycle-probe')
                if item.mode != 0o755 or digest(archive.extractfile(item).read()) != probe_digest:
                    raise ValueError('reviewed lifecycle probe pin mismatch')


def command(case):
    if case not in ALL_CASES:
        raise ValueError('unknown fault case')
    if case == 'pids_limit':
        return dict(argv=['/workspace/factory-lifecycle-probe','--pids-pressure'],timeout_secs=30)
    return dict(argv=['/workspace/factory-lifecycle-probe',
        '--fail-family' if case == 'command_failed' else '--hold-family'],
        timeout_secs=2 if case == 'timed_out' else 120)


def validate_spec(spec, case):
    expected = json.loads(canonical(spec))
    expected['commands'] = [dict(argv=['/workspace/factory-boundary-probe','--factory-boundary'],timeout_secs=30)]
    expected['correlation'] = dict(job='offline-boundary-proof',stage='baseline',round=0)
    boundary.validate_specification(expected)
    if (spec['commands'] != [command(case)]
            or spec['correlation'] != dict(job='escaped-family-proof',stage='baseline',round=ALL_CASES.index(case))):
        raise ValueError('journaled job is not the requested fault case')


def ready(stdout, stderr, case=None):
    if stderr or len(stdout) > 4096:
        raise ValueError('unexpected lifecycle output')
    lines = stdout.splitlines()
    if len(lines) != 1:
        return False
    value = json.loads(lines[0])
    if case == 'pids_limit':
        return (value == PIDS and value.get('limit_event_increased') is True
                and all(type(value.get(name)) is int for name in ('spawned','pids_max','pids_current','fork_errno')))
    return (value == READY and type(value.get('descendants')) is int
            and value.get('setsid') is True and value.get('ignore_sigterm') is True)


def validate_result(snapshot, submission, case, stdout, stderr):
    record, spec = snapshot.record, submission['specification']
    if (not snapshot.terminal or snapshot.cleanup_pending or record['vm_destroyed'] is not True
            or not record['vm_id'] or record.get('vm_allocation_aborted',False)
            or record['specification_digest'] != submission['execution_specification_digest']
            or record['state'] != outcome(case) or record['output_truncated'] or not ready(stdout,stderr,case)):
        raise ValueError('fault lacks expected terminal outcome, ready marker and destruction receipt')
    if case != 'cancelled':
        manifest = json.loads(record['manifest'])
        if (record['collection'] != 'complete' or manifest['collection_status'] != 'complete'
                or type(manifest['version']) is not int or manifest['version'] != 1 or manifest['job_id'] != snapshot.id
                or manifest['execution_specification_digest'] != submission['execution_specification_digest']
                or any(manifest[name] != spec[name] for name in ('image','source','acceptance'))
                or manifest['source_changed'] is not False or manifest['source_verification_error'] is not None
                or manifest['outcome'] != outcome(case) or len(manifest['commands']) != 1):
            raise ValueError('missing input-bound guest termination manifest')
        result = manifest['commands'][0]
        expected_exit = 7 if case == 'command_failed' else 0 if case == 'pids_limit' else None
        if (type(result['command_index']) is not int or result['command_index'] != 0 or result['outcome'] != outcome(case)
                or result['exit_code'] != expected_exit
                or (case != 'timed_out' and type(result['exit_code']) is not int) or result['termination_confirmed'] is not True
                or result['termination_error'] is not None or result['logs_truncated'] is not False):
            raise ValueError('escaped command family termination is unconfirmed')
    return dict(case=case,status='passed',job_id=snapshot.id,session_id=record['session_id'],
                vm_id=record['vm_id'],specification_digest=record['specification_digest'],
                guest_cgroup_termination_proven=case != 'cancelled',vm_destruction_receipt=True,
                pids_limit_exercised=case == 'pids_limit')


def run_case(client, journal, key, case, image, source, acceptance, resources, inspect=False):
    if inspect:
        row = journal.get(key)
        if row['acceptance_replayed'] == 1:
            raise ValueError('replayed acceptance cannot count as a fresh fault job')
        submission = json.loads(row['submission'])
        validate_spec(submission['specification'],case)
        if (row['source'] != source or row['acceptance'] != acceptance
                or submission['specification']['image'] != image):
            raise ValueError('inspect inputs differ from original frozen request')
        snapshot = FactoryChecksV1(client,journal).inspect(key)
        job = client.job(snapshot.id,specification_digest=submission['execution_specification_digest'])
        # No cancellation, waiting for readiness, or POST fallback during recovery.
    else:
        now = int(time.time())
        submission = submission_for_stage(key,image,source,acceptance,[command(case)['argv']],
            correlation=dict(job='escaped-family-proof',stage='baseline',round=ALL_CASES.index(case)),
            claim_deadline=now+601,stage='baseline',now=now,resources=resources)
        submission['specification']['commands'] = [command(case)]
        submission['execution_specification_digest'] = digest(canonical(submission['specification']).encode())
        validate_spec(submission['specification'],case)
        journal.prepare(submission,source,acceptance,utc(now+86400))
        journal.requested(key)
        row = journal.get(key)
        job = client.submit_job(submission,source,acceptance,retention_until=row['retention'])
        journal.bind(key,job.receipt)
        if job.receipt.replayed is not False:
            raise ValueError("fault pilot requires fresh acceptance; inspect existing execution")
        if case == 'cancelled':
            observation_deadline = time.monotonic()+90
            while True:
                stdout, stderr = boundary.collect_logs(job)
                # A prefix may split the ready record. Only complete newline-terminated output counts.
                if stdout.endswith(b'\n') and ready(stdout,stderr):
                    job.cancel()
                    break
                if job.info().terminal or time.monotonic() >= observation_deadline:
                    raise TimeoutError('family readiness unconfirmed; inspect without resubmission')
                time.sleep(0.25)
        snapshot = job.wait(timeout=max(0.001,now+600-time.time()),cleanup=True)
    stdout, stderr = boundary.collect_logs(job)
    result = validate_result(snapshot,submission,case,stdout,stderr)
    result['fresh_acceptance_proven'] = journal.get(key)['acceptance_replayed'] == 0
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspect',action='store_true')
    parser.add_argument('--include-pids',action='store_true',
                        help='separately approved fourth case consumes the 64-task cgroup limit')
    parser.add_argument('--url',required=True)
    parser.add_argument('--journal',type=Path,required=True)
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--acceptance',type=Path,required=True)
    parser.add_argument('--probe-digest',required=True)
    parser.add_argument('--disk-size-bytes',type=int,default=8*1024**3)
    args = parser.parse_args()
    if os.environ.get('HUSKER_RUN_FACTORY_LIFECYCLE_E2E') != '1':
        print(json.dumps(dict(status='skipped',activated=False,reason='explicit approved opt-in required')))
        return
    if str(uuid.UUID(args.run_id)) != args.run_id or uuid.UUID(args.run_id).int == 0:
        parser.error('canonical nonnil UUID run identity required')
    token = os.environ.get('HUSKER_FACTORY_LIFECYCLE_E2E_TOKEN')
    if not token:
        parser.error('explicit bearer required in HUSKER_FACTORY_LIFECYCLE_E2E_TOKEN')
    source = boundary.bounded(args.source,32*1024**2)
    acceptance = boundary.bounded(args.acceptance,32*1024**2)
    validate_inputs(source,acceptance,args.probe_digest)
    image = json.loads(boundary.bounded(args.image,4096))
    resources = boundary.proof_resources(args.disk_size_bytes)
    cases = ALL_CASES if args.include_pids else CASES
    prefix = 'lifecycle-v2-pids-' if args.include_pids else 'lifecycle-v1-'
    if not args.inspect:
        if args.journal.exists() or args.journal.is_symlink():
            raise ValueError('existing journal must be inspected; never resume execution')
        soak.private_directory(args.journal.parent)
        soak.write_once(args.journal.with_name(args.journal.name+'.attempted'),b'GET-only recovery\n')
    if args.inspect and not args.journal.exists():
        raise ValueError('inspection requires the original journal')
    journal = Journal(args.journal)
    results = []
    try:
        client = Client(args.url,token=token,timeout=30)
        for case in cases:
            try:
                results.append(run_case(client,journal,prefix+args.run_id+'-'+case,
                    case,image,source,acceptance,resources,inspect=args.inspect))
            except Exception as error:
                results.append(dict(case=case,status='unresolved',error_type=type(error).__name__))
                if not args.inspect:
                    break
    finally:
        journal.close()
    passed = len(results) == len(cases) and all(item['status'] == 'passed' and item['fresh_acceptance_proven'] is True for item in results)
    if passed:
        passed = all(len({item[field] for item in results}) == len(cases) for field in ('job_id','session_id','vm_id'))
    print(json.dumps(dict(status='passed' if passed else 'incomplete',scope='lifecycle-resources-v2' if args.include_pids else 'escaped-family-v1',cases=results,
        promotion_proven=False,host_resource_cleanup_proven=False,restart_recovery_proven=False)))
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__': main()
