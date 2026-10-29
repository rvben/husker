#!/usr/bin/env python3
"""Arm one offline job, then inspect its original identity after an operator crash.

Never signals a process, restarts a service, imports an image or retries a POST.
The operator must use an isolated daemon and independently audit host resources.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import factory_lifecycle_e2e as lifecycle
from examples.factory_checks_v1 import FactoryChecksV1, Journal, canonical, digest, submission_for_stage, utc
from husker import Client

COMMAND = dict(argv=['/workspace/factory-lifecycle-probe', '--hold-family'], timeout_secs=300)
CORRELATION = dict(job='daemon-crash-proof', stage='baseline', round=0)
IDENTITY = ('id', 'session_id', 'vm_id', 'specification_digest')


def validate_spec(spec):
    expected = json.loads(canonical(spec))
    expected['commands'] = [lifecycle.command('cancelled')]
    expected['correlation'] = dict(job='escaped-family-proof', stage='baseline', round=2)
    lifecycle.validate_spec(expected, 'cancelled')
    if spec['commands'] != [COMMAND] or spec['correlation'] != CORRELATION:
        raise ValueError('journal is not this offline crash probe')


def arm(client, journal, key, image, source, acceptance, resources, before_path):
    now = int(time.time())
    submission = submission_for_stage(key, image, source, acceptance, [COMMAND['argv']],
        correlation=CORRELATION, claim_deadline=now+601, stage='baseline', now=now, resources=resources)
    submission['specification']['commands'] = [COMMAND]
    submission['execution_specification_digest'] = digest(canonical(submission['specification']).encode())
    validate_spec(submission['specification'])
    journal.prepare(submission, source, acceptance, utc(now+86400))
    journal.requested(key)
    job = client.submit_job(submission, source, acceptance, retention_until=journal.get(key)['retention'])
    journal.bind(key, job.receipt)
    if job.receipt.replayed is not False:
        raise ValueError('fresh acceptance required; inspect without resubmitting')
    # Cold pinned-image copies consume the same 600s stage budget. Allow them
    # to finish before deciding whether a running guest is safe to fault.
    deadline = time.monotonic()+300
    while True:
        snapshot = job.info()
        stdout, stderr = lifecycle.boundary.collect_logs(job)
        if (snapshot.record['state'] == 'running' and stdout.endswith(b'\n')
                and lifecycle.ready(stdout, stderr)):
            if not snapshot.record['vm_id'] or snapshot.record['specification_digest'] != submission['execution_specification_digest']:
                raise ValueError('running generation is unbound')
            before = {name: snapshot.record[name] for name in IDENTITY}
            before.update(key=key, stdout_digest=digest(stdout), stderr_digest=digest(stderr))
            lifecycle.soak.write_once(before_path, canonical(before).encode())
            return dict(status='armed', identity=before, crash_injected=False)
        if snapshot.terminal or time.monotonic() >= deadline:
            raise TimeoutError('readiness unconfirmed; do not inject a crash or resubmit')
        time.sleep(0.25)


def validate_after(snapshot, before, stdout, stderr):
    record = snapshot.record
    if ({name: record[name] for name in IDENTITY} != {name: before[name] for name in IDENTITY}
            or not snapshot.terminal or record['state'] != 'unknown' or record['collection'] != 'failed'
            or record['vm_allocation_aborted'] or record['output_truncated']
            or digest(stdout) != before['stdout_digest'] or digest(stderr) != before['stderr_digest']
            or not lifecycle.ready(stdout, stderr)):
        raise ValueError('crash observation changed identity, output or unknown outcome')
    manifest = json.loads(record['manifest'])
    if (manifest.get('collection') != 'failed'
            or not isinstance(manifest.get('host_error'), str)
            or 'daemon restarted; execution will not be resubmitted' not in manifest['host_error']):
        raise ValueError('restart failure envelope missing')
    cleanup = record['vm_destroyed'] is True and snapshot.cleanup_pending is False
    if not cleanup and (record['vm_destroyed'] is not False or snapshot.cleanup_pending is not True):
        raise ValueError('inconsistent destruction and ownership receipt')
    return dict(status='passed' if cleanup else 'incomplete', scope='post-crash-observation-v1',
        identity_preserved=True, journaled_output_preserved=True, terminal_unknown=True,
        vm_destruction_receipt=cleanup, cleanup_pending=snapshot.cleanup_pending,
        crash_injection_proven=False, host_resource_cleanup_proven=False, promotion_proven=False,
        job_id=snapshot.id, session_id=record['session_id'], vm_id=record['vm_id'])


def inspect(client, journal, key, before_path, image, source, acceptance):
    before = json.loads(lifecycle.boundary.bounded(before_path, 4096))
    row = journal.get(key)
    submission = json.loads(row['submission'])
    validate_spec(submission['specification'])
    if (before['key'] != key or row['acceptance_replayed'] != 0
            or row['source'] != source or row['acceptance'] != acceptance
            or submission['specification']['image'] != image
            or before['specification_digest'] != submission['execution_specification_digest']):
        raise ValueError('inspection inputs differ from the original fresh request')
    snapshot = FactoryChecksV1(client, journal).inspect(key)  # GET lookup, never POST/cancel.
    job = client.job(snapshot.id, specification_digest=before['specification_digest'])
    stdout, stderr = lifecycle.boundary.collect_logs(job)
    return validate_after(snapshot, before, stdout, stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['arm', 'inspect'])
    parser.add_argument('--url', required=True)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--acceptance', type=Path, required=True)
    parser.add_argument('--probe-digest', required=True)
    parser.add_argument('--disk-size-bytes', type=int, default=8*1024**3)
    args = parser.parse_args()
    if os.environ.get('HUSKER_RUN_FACTORY_RESTART_E2E') != '1':
        print(json.dumps(dict(status='skipped', activated=False, reason='approved isolated daemon required')))
        return
    token = os.environ.get('HUSKER_FACTORY_RESTART_E2E_TOKEN')
    if not token:
        parser.error('explicit bearer required in HUSKER_FACTORY_RESTART_E2E_TOKEN')
    source = lifecycle.boundary.bounded(args.source, 32*1024**2)
    acceptance = lifecycle.boundary.bounded(args.acceptance, 32*1024**2)
    lifecycle.validate_inputs(source, acceptance, args.probe_digest)
    image = json.loads(lifecycle.boundary.bounded(args.image, 4096))
    before_path = args.journal.with_name(args.journal.name+'.before-crash.json')
    if args.mode == 'arm':
        if args.journal.exists() or args.journal.is_symlink() or before_path.exists() or before_path.is_symlink():
            raise ValueError('existing crash run must be inspected, never armed again')
        lifecycle.soak.private_directory(args.journal.parent)
        lifecycle.soak.write_once(args.journal.with_name(args.journal.name+'.attempted'), b'GET-only recovery\n')
    elif not args.journal.exists():
        raise ValueError('inspection requires original journal and readiness evidence')
    journal = Journal(args.journal)
    try:
        client = Client(args.url, token=token, timeout=30)
        if args.mode == 'arm':
            result = arm(client, journal, args.key, image, source, acceptance,
                lifecycle.boundary.proof_resources(args.disk_size_bytes), before_path)
        else:
            result = inspect(client, journal, args.key, before_path, image, source, acceptance)
    finally:
        journal.close()
    print(json.dumps(result))
    if result['status'] == 'incomplete':
        raise SystemExit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Transport bodies and operator credentials never become probe output.
        print(json.dumps(dict(status='unresolved', error_type=type(error).__name__)))
        raise SystemExit(1)
