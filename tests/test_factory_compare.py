"""Paired-record collection only: no backend execution or hardware proof."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
import uuid

SPEC = importlib.util.spec_from_file_location('factory_compare', Path(__file__).parents[1] / 'scripts/ci/factory_compare.py')
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


def fixture(outcome='completed', name='candidate', stage='candidate', kind='checks', startup='cold'):
    case = dict(name=name, stage=stage, kind=kind, startup=startup,
                source_digest='sha256:'+('1' if stage == 'baseline' else '8')*64, acceptance_digest='sha256:'+'2'*64,
                toolchain_digest='sha256:'+'3'*64, candidate_patch_digest='sha256:'+'4'*64,
                commands=[['/opt/tool', '--offline']], acceptance_command_indices=[0], resources=dict(vcpu_count=2, mem_size_mib=4096,
                    disk_size_bytes=8*1024**3, pids_limit=128), stage_budget_secs=600,
                husker=name+'.husker.json', docker=name+'.docker.json')
    provenance = {key: copy.deepcopy(case[key]) for key in ('stage', 'startup', 'source_digest',
        'acceptance_digest', 'toolchain_digest', 'candidate_patch_digest', 'resources', 'stage_budget_secs')}
    provenance.update(source_after_digest=case['source_digest'], acceptance_after_digest=case['acceptance_digest'],
                      network='none', disk_limit_enforced=True,
                      host=dict(cpu_model='Apple M6', architecture='arm64', os_version='27.0.1'))
    job_id, session = str(uuid.uuid4()), str(uuid.uuid4())
    image = dict(rootfs_digest='sha256:'+'5'*64, kernel_digest='sha256:'+'6'*64)
    spec = dict(source=dict(digest=case['source_digest'], size_bytes=1024),
                acceptance=dict(digest=case['acceptance_digest'], size_bytes=1024), image=image,
                commands=[dict(argv=case['commands'][0], timeout_secs=600)], resources=case['resources'],
                correlation=dict(stage=stage), network=dict(mode='none'))
    encoded = compare.canonical(spec)
    spec_digest = compare.digest(encoded.encode())
    code = 0 if outcome == 'completed' else 1
    manifest = dict(job_id=job_id, execution_specification_digest=spec_digest,
                    image=image, source=spec['source'], acceptance=spec['acceptance'],
                    source_changed=False, source_verification_error=None,
                    outcome=outcome, collection_status='complete',
                    commands=[dict(command_index=0, exit_code=code, termination_confirmed=True,
                                   termination_error=None, logs_truncated=False, outcome=outcome)])
    metrics = dict.fromkeys(compare.METRICS, 10)
    husker = dict(backend='husker', provenance=copy.deepcopy(provenance), measurements=metrics,
                  versions=dict(daemon='test', agent='test', kernel='test', image='test'),
                  job=dict(id=job_id, session_id=session, specification=encoded, specification_digest=spec_digest,
                           vm_id=str(uuid.uuid4()), state=outcome, collection='complete', manifest=compare.canonical(manifest),
                           output_truncated=False, cleanup_pending=False, vm_destroyed=True))
    docker = dict(backend='docker', provenance=copy.deepcopy(provenance), measurements=metrics,
                  versions=dict(docker='test', colima='test', image='test'),
                  execution=dict(backend='docker', dockerContext='colima', memoryMiB=4096,
                      image='checks@sha256:'+'7'*64, phase='completed', cleanup='confirmed',
                      containers=['case-'+uuid.uuid4().hex], results=[dict(argv=case['commands'][0], exitCode=code)]))
    if outcome not in ('completed', 'command_failed'):
        husker['job']['collection'] = 'failed'
        manifest['collection_status'] = 'failed'
        manifest['commands'] = []
        husker['job']['manifest'] = compare.canonical(manifest)
        docker['execution'].update(phase='interrupted', results=[], failure=dict(kind=outcome))
    return case, husker, docker


class ComparisonTests(unittest.TestCase):
    def collect(self, *fixtures):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for case, husker, docker in fixtures:
                for backend, capture in (('husker', husker), ('docker', docker)):
                    (path/case[backend]).write_text(compare.canonical(capture))
            return compare.collect(dict(version=1, cases=[item[0] for item in fixtures]), path)

    def test_baseline_candidate_timeout_and_infrastructure_remain_distinct(self):
        report = self.collect(fixture('command_failed', 'baseline', 'baseline'), fixture(),
                              fixture('timed_out', 'timeout', kind='timeout'),
                              fixture('infrastructure_failed', 'infra', kind='infrastructure'),
                              fixture(name='repeated', startup='repeated'))
        self.assertTrue(report['all_decisions_equivalent'])
        self.assertTrue(all(report['coverage'].values()))
        self.assertFalse(report['promotion_eligible'])
        self.assertEqual(len(report['cases']), 5)
        self.assertEqual(report['cases'][0]['captures']['husker']['command_exit_codes'], [1])
        self.assertEqual(report['cases'][2]['captures']['docker']['outcome'], 'timed_out')

    def test_timeout_is_never_a_passing_command_and_unknown_docker_failure_is_retained(self):
        item = fixture('timed_out', 'timeout', kind='timeout')
        del item[2]['execution']['failure']
        report = self.collect(item)
        self.assertFalse(report['all_decisions_equivalent'])
        self.assertEqual(report['cases'][0]['captures']['husker']['outcome'], 'timed_out')
        self.assertEqual(report['cases'][0]['captures']['docker']['outcome'], 'unknown')
        self.assertFalse(report['coverage']['timeout'])
        self.assertEqual(len(report['cases']), 1)

    def test_mismatch_missing_metric_and_unconfirmed_cleanup_preclude_equivalence(self):
        for modify in (
            lambda h, d: d['provenance'].update(toolchain_digest='sha256:'+'8'*64),
            lambda h, d: d['provenance'].update(source_after_digest='sha256:'+'9'*64),
            lambda h, d: d['provenance'].update(disk_limit_enforced=False),
            lambda h, d: h['measurements'].update(peak_host_rss_bytes=None),
            lambda h, d: h['job'].update(cleanup_pending=True),
            lambda h, d: d['execution'].update(cleanup='unconfirmed'),
            lambda h, d: d['provenance']['host'].update(os_version='different'),
        ):
            case, husker, docker = fixture()
            # Measurements are separate despite fixture's shared initial dictionary.
            husker['measurements'] = dict(husker['measurements'])
            docker['measurements'] = dict(docker['measurements'])
            modify(husker, docker)
            with self.subTest(modify=modify):
                self.assertFalse(self.collect((case, husker, docker))['all_decisions_equivalent'])

    def test_changed_specification_forged_result_and_reserved_exit_fail_closed(self):
        for modify in (
            lambda h, d: h['job'].update(specification=h['job']['specification']+' '),
            lambda h, d: d['execution']['results'][0].update(argv=['different']),
            lambda h, d: d['execution']['results'][0].update(exitCode=137),
            lambda h, d: d['execution'].update(dockerContext='other'),
        ):
            case, husker, docker = fixture()
            modify(husker, docker)
            report = self.collect((case, husker, docker))
            self.assertFalse(report['all_decisions_equivalent'])
            self.assertEqual(len(report['cases']), 1)
            self.assertTrue(any(capture['issues'] for capture in report['cases'][0]['captures'].values()))

    def test_missing_duplicate_or_reused_evidence_cannot_be_dropped_or_counted_twice(self):
        first, second = fixture(), fixture(name='second')
        second[1]['job'] = copy.deepcopy(first[1]['job'])
        report = self.collect(first, second)
        self.assertFalse(report['cases'][1]['decision_equivalent'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            plan = dict(version=1, cases=[first[0]])
            report = compare.collect(plan, path)
            self.assertEqual(len(report['cases']), 1)
            self.assertFalse(report['all_decisions_equivalent'])
            duplicate = copy.deepcopy(first[0]); duplicate['name'] = 'duplicate'
            with self.assertRaisesRegex(ValueError, 'multiple executions'):
                compare.collect(dict(version=1, cases=[first[0], duplicate]), path)

    def test_baseline_must_fail_acceptance_and_shared_suite_cannot_change(self):
        report = self.collect(fixture(name='baseline', stage='baseline'), fixture())
        self.assertFalse(report['coverage']['baseline'])
        self.assertFalse(report['all_decisions_equivalent'])
        baseline, candidate = fixture('command_failed', 'baseline', 'baseline'), fixture()
        candidate[0]['toolchain_digest'] = 'sha256:'+'9'*64
        for capture in candidate[1:]:
            capture['provenance']['toolchain_digest'] = candidate[0]['toolchain_digest']
        report = self.collect(baseline, candidate)
        self.assertFalse(report['coverage']['baseline'])
        self.assertFalse(report['coverage']['candidate'])
        self.assertTrue(report['cases'][0]['pair_issues'])

    def test_observable_decisions_match_without_equal_timings_or_exit_codes(self):
        case, husker, docker = fixture('command_failed', stage='baseline')
        docker['execution']['results'][0]['exitCode'] = 2
        docker['measurements'] = dict(docker['measurements'], wall_ms=40)
        report = self.collect((case, husker, docker))
        self.assertTrue(report['all_decisions_equivalent'])
        self.assertEqual(report['cases'][0]['measurement_delta_husker_minus_docker']['wall_ms'], -30)
        self.assertFalse(report['coverage']['candidate'])
        self.assertFalse(report['promotion_eligible'])

    def test_cli_is_read_only_and_exit_zero_never_promotes(self):
        items = [fixture('command_failed', 'baseline', 'baseline'), fixture(),
                 fixture('timed_out', 'timeout', kind='timeout'),
                 fixture('infrastructure_failed', 'infra', kind='infrastructure'),
                 fixture(name='repeated', startup='repeated')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for case, husker, docker in items:
                (path/case['husker']).write_text(compare.canonical(husker))
                (path/case['docker']).write_text(compare.canonical(docker))
            (path/'comparison-plan.json').write_text(compare.canonical(dict(version=1, cases=[item[0] for item in items])))
            before = {file.name: file.read_bytes() for file in path.iterdir()}
            command = [sys.executable, SPEC.origin, '--directory', directory]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['promotion_eligible'])
            self.assertEqual(before, {file.name: file.read_bytes() for file in path.iterdir()})
            (path/'candidate.docker.json').unlink()
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(len(json.loads(result.stdout)['cases']), 5)
            result = subprocess.run(command+['--plan', 'missing.json'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)

    def test_safe_bounded_json_reads_refuse_links_traversal_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            file = path/'record.json'; file.write_text('{}')
            self.assertEqual(compare.read_record(path, file.name), b'{}')
            with self.assertRaises(ValueError): compare.read_record(path, '../record.json')
            (path/'link.json').symlink_to(file)
            with self.assertRaises(OSError): compare.read_record(path, 'link.json')
            with self.assertRaises(ValueError): compare.read_record(path, file.name, limit=1)
            with self.assertRaises(ValueError): compare.decode('{"x":1,"x":2}')
            with self.assertRaises(ValueError): compare.decode('{"x":NaN}')


if __name__ == '__main__':
    unittest.main()
