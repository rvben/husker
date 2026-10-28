#!/usr/bin/env python3
"""Collect paired factory evidence locally; never execute or promote a backend.

Capture envelopes wrap an existing Husker host record or Werkt Docker execution
manifest. Provenance/measurements must come from the approved live capture, not
from this collector. Raw files are hashed and all failed/missing cases retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

LIMIT = 4 * 1024 * 1024
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
METRICS = ('preparation_ms', 'transfer_ms', 'check_ms', 'wall_ms',
           'peak_host_rss_bytes', 'disk_allocated_bytes', 'operator_interventions')
TERMINAL = {'completed', 'command_failed', 'timed_out', 'cancelled',
            'infrastructure_failed', 'interrupted', 'unknown'}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False)


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read_record(directory, name, limit=LIMIT):
    # A flat reviewed bundle prevents path traversal and accidental broad reads.
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.json', name):
        raise ValueError('evidence filename must be a bounded JSON basename')
    fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > limit:
            raise ValueError('evidence must be a bounded regular file with one link')
        data = stream.read(limit + 1)
    if len(data) != meta.st_size or len(data) > limit:
        raise ValueError('evidence size changed during read')
    return data


def validate_case(case):
    if not isinstance(case, dict) or not isinstance(case.get('name'), str) or not re.fullmatch(r'[a-z0-9-]{1,64}', case['name']):
        raise ValueError('bounded unique case name required')
    if case.get('stage') not in ('baseline', 'candidate') or case.get('kind') not in ('checks', 'timeout', 'infrastructure'):
        raise ValueError('explicit stage and case kind required')
    for key in ('source_digest', 'acceptance_digest', 'toolchain_digest', 'candidate_patch_digest'):
        if not isinstance(case.get(key), str) or not DIGEST.fullmatch(case[key]):
            raise ValueError('frozen input/environment/patch digests required')
    commands = case.get('commands')
    if (not isinstance(commands, list) or not 1 <= len(commands) <= 32
            or any(not isinstance(argv, list) or not argv or len(argv) > 256
                   or any(not isinstance(arg, str) or '\0' in arg or len(arg.encode()) > 4096 for arg in argv)
                   for argv in commands)):
        raise ValueError('bounded literal trusted argv arrays required')
    indices = case.get('acceptance_command_indices')
    if (not isinstance(indices, list) or not indices or len(set(indices)) != len(indices)
            or any(type(index) is not int or not 0 <= index < len(commands) for index in indices)):
        raise ValueError('explicit acceptance command indices required')
    resources = case.get('resources')
    if (not isinstance(resources, dict) or set(resources) != {'vcpu_count', 'mem_size_mib', 'disk_size_bytes', 'pids_limit'}
            or any(type(value) is not int or value <= 0 for value in resources.values())
            or resources['vcpu_count'] > 32 or resources['mem_size_mib'] > 65536
            or resources['disk_size_bytes'] > 1024**4 or resources['pids_limit'] > 512):
        raise ValueError('equivalent explicit resource limits required')
    if type(case.get('stage_budget_secs')) is not int or not 1 <= case['stage_budget_secs'] <= (600 if case['stage'] == 'baseline' else 1800):
        raise ValueError('bounded stage budget required')
    if case.get('startup') not in ('cold', 'repeated'):
        raise ValueError('cold/repeated startup classification required')


def normalize(case, backend, capture):
    issues = []
    output = dict(backend=backend, outcome='unknown', command_decisions=[],
                  cleanup_confirmed=False, measurements={}, command_exit_codes=[])
    if not isinstance(capture, dict) or capture.get('backend') != backend:
        raise ValueError('capture backend mismatch')
    provenance = capture.get('provenance', {})
    for key in ('source_digest', 'acceptance_digest', 'toolchain_digest', 'candidate_patch_digest',
                'resources', 'stage_budget_secs', 'stage', 'startup'):
        if provenance.get(key) != case[key]:
            issues.append('missing or mismatched provenance: ' + key)
    if provenance.get('source_after_digest') != case['source_digest'] or provenance.get('acceptance_after_digest') != case['acceptance_digest']:
        issues.append('frozen inputs were not verified unchanged after execution')
    if provenance.get('network') != 'none' or provenance.get('disk_limit_enforced') is not True:
        issues.append('offline policy or equivalent enforced disk limit is unverified')
    host = provenance.get('host', {})
    if (not isinstance(host, dict) or host.get('cpu_model') != 'Apple M6'
            or host.get('architecture') != 'arm64' or not isinstance(host.get('os_version'), str)
            or not 1 <= len(host['os_version']) <= 128):
        issues.append('intended Apple M6 arm64 host identity is unverified')
    output['host'] = {key: value if isinstance(value, str) and len(value) <= 128 else None
                      for key in ('cpu_model', 'architecture', 'os_version')
                      for value in [host.get(key)]} if isinstance(host, dict) else {}
    versions = capture.get('versions', {})
    required = ('daemon', 'agent', 'kernel', 'image') if backend == 'husker' else ('docker', 'colima', 'image')
    if not isinstance(versions, dict) or any(not isinstance(versions.get(key), str) or not 1 <= len(versions[key]) <= 256 for key in required):
        issues.append('runtime versions are incomplete')
    output['versions'] = {key: value if isinstance(value, str) and len(value) <= 256 else None
                          for key in required for value in [versions.get(key)]} if isinstance(versions, dict) else {}
    for key in METRICS:
        value = capture.get('measurements', {}).get(key)
        if type(value) is not int or value < 0:
            issues.append('measurement missing: ' + key)
            value = None
        output['measurements'][key] = value
    if backend == 'husker':
        record = capture['job']
        spec = decode(record['specification'])
        if digest(record['specification'].encode()) != record['specification_digest']:
            raise ValueError('Husker specification digest mismatch')
        if (spec['source']['digest'] != case['source_digest'] or spec['acceptance']['digest'] != case['acceptance_digest']
                or spec['resources'] != case['resources'] or spec['correlation']['stage'] != case['stage']
                or [command['argv'] for command in spec['commands']] != case['commands']
                or spec['network'] != {'mode': 'none'}
                or any(type(command.get('timeout_secs')) is not int or not 1 <= command['timeout_secs'] <= min(1200, case['stage_budget_secs']) for command in spec['commands'])):
            raise ValueError('Husker immutable specification differs from comparison')
        uuid.UUID(record['id'])
        uuid.UUID(record['session_id'])
        output['execution_identity'] = dict(job=record['id'], session=record['session_id'], specification_digest=record['specification_digest'])
        state = record['state']
        if record.get('vm_id') is not None:
            uuid.UUID(record['vm_id'])
        if record.get('vm_allocation_aborted') is True and (record.get('vm_destroyed') is True or state in ('completed', 'command_failed')):
            raise ValueError('contradictory Husker allocation receipt')
        if state in ('completed', 'command_failed') and (record.get('vm_id') is None or record.get('vm_destroyed') is not True):
            raise ValueError('Husker command lacks confirmed VM destruction')
        output['outcome'] = state if state in TERMINAL else 'unknown'
        output['cleanup_confirmed'] = (record.get('cleanup_pending') is False
            and (record.get('vm_destroyed') is True or record.get('vm_allocation_aborted') is True))
        manifest = decode(record['manifest']) if record.get('manifest') else {}
        if state in ('completed', 'command_failed'):
            if (record.get('collection') != 'complete' or record.get('output_truncated') is not False
                    or manifest.get('job_id') != record['id'] or manifest.get('execution_specification_digest') != record['specification_digest']
                    or any(manifest.get(key) != spec[key] for key in ('image', 'source', 'acceptance'))
                    or manifest.get('source_changed') is not False or manifest.get('source_verification_error') is not None
                    or manifest.get('outcome') != state or manifest.get('collection_status') != 'complete'):
                raise ValueError('Husker sealed command evidence is incomplete or changed')
            commands = manifest['commands']
            if len(commands) != len(case['commands']):
                raise ValueError('Husker command inventory incomplete')
            for index, command in enumerate(commands):
                code = command['exit_code']
                if (type(code) is not int or not 0 <= code <= 255 or code in (125, 126, 127, 137, 143)
                        or type(command.get('command_index')) is not int or command['command_index'] != index
                        or command.get('termination_confirmed') is not True or command.get('termination_error') is not None
                        or command.get('logs_truncated') is not False
                        or command.get('outcome') != ('completed' if code == 0 else 'command_failed')):
                    raise ValueError('Husker command termination/evidence unconfirmed')
                output['command_decisions'].append('pass' if code == 0 else 'fail')
                output['command_exit_codes'].append(code)
            if (state == 'completed') != all(value == 'pass' for value in output['command_decisions']):
                raise ValueError('Husker outcome contradicts command decisions')
        elif not record.get('manifest'):
            issues.append('failure lacks retained terminal manifest')
    else:
        record = capture['execution']
        if record.get('backend') != 'docker' or record.get('dockerContext') != 'colima':
            raise ValueError('Docker record must explicitly select Colima')
        containers = record.get('containers', [])
        if (not isinstance(containers, list) or len(containers) > 32
                or any(not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', name) for name in containers)
                or len(set(containers)) != len(containers)):
            raise ValueError('invalid Docker execution identity')
        output['execution_identity'] = dict(containers=containers, image=record.get('image'))
        if (not isinstance(record.get('image'), str) or len(record['image']) > 512
                or not re.fullmatch(r'(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}', record['image'])):
            issues.append('Docker image is not digest-pinned')
            output['execution_identity']['image'] = None
        if record.get('memoryMiB') != case['resources']['mem_size_mib']:
            raise ValueError('Docker memory limit mismatch')
        output['cleanup_confirmed'] = record.get('cleanup') == 'confirmed'
        if record.get('phase') == 'completed':
            results = record.get('results', [])
            if len(results) != len(case['commands']) or len(record.get('containers', [])) != len(results):
                raise ValueError('Docker command/container inventory incomplete')
            for argv, result in zip(case['commands'], results):
                code = result.get('exitCode')
                if result.get('argv') != argv or type(code) is not int or not 0 <= code <= 255 or code in (125, 126, 127, 137, 143):
                    raise ValueError('Docker command or infrastructure result mismatch')
                output['command_decisions'].append('pass' if code == 0 else 'fail')
                output['command_exit_codes'].append(code)
            output['outcome'] = 'completed' if all(value == 'pass' for value in output['command_decisions']) else 'command_failed'
        else:
            # Current Werkt interrupted manifests do not say why. Never infer a
            # timeout/infra failure from an exception or fabricate passing commands.
            failure = record.get('failure', {})
            kind = failure.get('kind')
            if record.get('phase') == 'interrupted' and kind in ('timed_out', 'infrastructure_failed'):
                output['outcome'] = kind
            else:
                issues.append('Docker interruption has no classified failure evidence')
    if not output['cleanup_confirmed']:
        issues.append('resource cleanup is unconfirmed')
    if output['outcome'] in ('unknown', 'interrupted', 'cancelled'):
        issues.append('execution decision is unresolved or outside the comparison')
    output['issues'] = issues
    return output


def collect(plan, directory):
    if (not isinstance(plan, dict) or type(plan.get('version')) is not int or plan['version'] != 1
            or not isinstance(plan.get('cases'), list) or not 1 <= len(plan['cases']) <= 64):
        raise ValueError('comparison plan v1 requires one to sixty-four cases')
    names, files, rows = set(), set(), []
    remaining = 32 * 1024 * 1024
    executions = set()
    for case in plan['cases']:
        validate_case(case)
        if case['name'] in names:
            raise ValueError('duplicate case name')
        names.add(case['name'])
        row = dict(name=case['name'], stage=case['stage'], kind=case['kind'],
                   startup=case['startup'], case_digest=digest(canonical(case).encode()), captures={}, comparable=False,
                   pair_issues=[], measurement_delta_husker_minus_docker={},
                   decision_equivalent=False)
        for backend in ('husker', 'docker'):
            name = case[backend]
            if name in files:
                raise ValueError('one evidence file cannot represent multiple executions')
            files.add(name)
            evidence = {'raw_file': name, 'outcome': 'unknown', 'issues': []}
            try:
                data = read_record(directory, name, min(LIMIT, remaining))
                remaining -= len(data)
                evidence['raw_digest'] = digest(data)
                evidence.update(normalize(case, backend, decode(data)))
                identity = evidence['execution_identity']
                identifiers = [identity['job']] if backend == 'husker' else identity['containers']
                for identifier in identifiers:
                    token = (backend, identifier)
                    if token in executions:
                        evidence['issues'].append('execution identity reused across comparison cases')
                    executions.add(token)
            except (OSError, ValueError, KeyError, TypeError, RecursionError, AttributeError) as error:
                evidence['issues'] = ['invalid or missing capture: ' + str(error)]
            row['captures'][backend] = evidence
        left, right = row['captures']['husker'], row['captures']['docker']
        row['comparable'] = not left['issues'] and not right['issues'] and left.get('host') == right.get('host')
        if left.get('host') != right.get('host'):
            row['pair_issues'].append('host versions/identity differ')
        if row['comparable']:
            row['measurement_delta_husker_minus_docker'] = {key: left['measurements'][key] - right['measurements'][key] for key in METRICS}
        row['decision_equivalent'] = (row['comparable'] and left['outcome'] == right['outcome']
            and left['command_decisions'] == right['command_decisions'])
        expected = {'timeout': {'timed_out'}, 'infrastructure': {'infrastructure_failed'},
                    'checks': {'completed', 'command_failed'}}[case['kind']]
        if left['outcome'] not in expected or right['outcome'] not in expected:
            row['decision_equivalent'] = False
            row['pair_issues'].append('outcome differs from declared case kind')
        if case['kind'] == 'checks' and row['decision_equivalent']:
            acceptance = [left['command_decisions'][index] for index in case['acceptance_command_indices']]
            if (case['stage'] == 'baseline' and 'fail' not in acceptance) or (case['stage'] == 'candidate' and left['outcome'] != 'completed'):
                row['decision_equivalent'] = False
                row['pair_issues'].append('baseline must fail acceptance and candidate must pass checks')
        rows.append(row)
    coverage = {kind: any(row['kind'] == kind and row['decision_equivalent'] for row in rows)
                for kind in ('checks', 'timeout', 'infrastructure')}
    check_cases = [case for case in plan['cases'] if case['kind'] == 'checks']
    policy_keys = ('commands', 'acceptance_command_indices', 'acceptance_digest', 'toolchain_digest', 'candidate_patch_digest', 'resources')
    if any(any(case[key] != check_cases[0][key] for key in policy_keys) for case in check_cases):
        for row in rows:
            if row['kind'] == 'checks':
                row['decision_equivalent'] = False
                row['pair_issues'].append('baseline/candidate check policy or frozen suite differs')
    baseline_sources = {case['source_digest'] for case in check_cases if case['stage'] == 'baseline'}
    candidate_sources = {case['source_digest'] for case in check_cases if case['stage'] == 'candidate'}
    if baseline_sources & candidate_sources:
        for row in rows:
            if row['kind'] == 'checks':
                row['decision_equivalent'] = False
                row['pair_issues'].append('baseline and candidate use the same frozen source')
    coverage['checks'] = any(row['kind'] == 'checks' and row['decision_equivalent'] for row in rows)
    coverage.update({startup: any(row['startup'] == startup and row['decision_equivalent'] for row in rows) for startup in ('cold', 'repeated')})
    coverage.update({stage: any(row['stage'] == stage and row['kind'] == 'checks' and row['decision_equivalent'] for row in rows)
                     for stage in ('baseline', 'candidate')})
    # This collects declared capture evidence. It does not prove capture honesty,
    # boundary behavior, restart recovery, fifty jobs or negotiated performance.
    return dict(version=1, scope='paired-record-collection-v1', plan_digest=digest(canonical(plan).encode()),
                cases=rows, coverage=coverage, all_decisions_equivalent=all(row['decision_equivalent'] for row in rows),
                promotion_eligible=False,
                unverified_gates=['live capture provenance', 'offline boundary', 'restart recovery',
                                  'fifty sequential and bounded concurrent fault jobs', 'negotiated overhead targets'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--plan', default='comparison-plan.json')
    args = parser.parse_args()
    try:
        plan = decode(read_record(args.directory, args.plan))
        report = collect(plan, args.directory)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, AttributeError) as error:
        parser.exit(2, 'comparison rejected: ' + str(error) + '\n')
    print(canonical(report))
    return 0 if report['all_decisions_equivalent'] and all(report['coverage'].values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
