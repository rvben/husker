import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('soak', Path(__file__).parents[1]/'scripts/ci/factory_soak.py')
soak = importlib.util.module_from_spec(spec)
spec.loader.exec_module(soak)


class SoakTests(unittest.TestCase):
    def passed(self, index):
        return dict(index=index, status='passed', fresh_acceptance_proven=True, executionIdentity={
            'jobId': f'job-{index}', 'sessionId': f'session-{index}', 'vmId': f'vm-{index}'})

    def test_sequential_jobs_finish_before_bounded_concurrent_batch(self):
        barrier = threading.Barrier(4)
        lock = threading.Lock()
        sequential = []
        active = 0
        peak = 0

        def observe(index):
            nonlocal active, peak
            with lock:
                if index < 50:
                    self.assertEqual(index, len(sequential))
                    sequential.append(index)
                else:
                    self.assertEqual(len(sequential), 50)
                    active += 1
                    peak = max(peak, active)
            if index >= 50:
                barrier.wait(timeout=5)
                with lock:
                    active -= 1
            return self.passed(index)

        results = soak.run_cases(observe)
        self.assertEqual(peak, 4)
        self.assertEqual([item['index'] for item in results], list(range(54)))
        result = soak.summarize(results)
        self.assertEqual(result['status'], 'passed')
        for field in ('promotion_proven','host_resource_cleanup_proven',
                      'fault_injection_proven','overlapping_guest_execution_proven'):
            self.assertFalse(result[field])

    def test_failure_stops_new_execution_but_inspection_visits_every_case(self):
        visited = []
        def observe(index):
            visited.append(index)
            return dict(index=index,status='unresolved')
        self.assertEqual(len(soak.run_cases(observe)), 1)
        self.assertEqual(visited, [0])
        visited.clear()
        self.assertEqual(len(soak.run_cases(observe, inspect=True)), 54)
        self.assertEqual(set(visited), set(range(54)))

    def test_replayed_identities_cannot_count_as_distinct_executions(self):
        for field in ('jobId','sessionId','vmId'):
            results = [self.passed(index) for index in range(54)]
            results[-1]['executionIdentity'][field] = results[0]['executionIdentity'][field]
            self.assertEqual(soak.summarize(results)['status'], 'incomplete')
        self.assertEqual(soak.summarize([self.passed(0)])['status'], 'incomplete')
        results = [self.passed(index) for index in range(54)]
        results[-1]['fresh_acceptance_proven'] = False
        self.assertEqual(soak.summarize(results)['status'],'incomplete')

    def test_execution_marker_is_exclusive_and_missing_inspection_never_connects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            soak.write_once(root/'execution-attempted', b'attempted')
            with self.assertRaises(FileExistsError):
                soak.write_once(root/'execution-attempted', b'rerun')
            result = soak.observe_case(root,0,{'run_id':'run'}, {},
                lambda: self.fail('inspection must not contact daemon for an absent journal'), inspect=True)
            self.assertEqual(result, dict(index=0,status='not_started'))

    def test_preparation_freezes_inputs_and_unique_run_identity_without_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in [('image',b'{"id":"pinned"}'),('source',b'source'),('acceptance',b'acceptance')]:
                (root/name).write_bytes(data)
            with patch.object(soak.boundary,'validate_inputs'), patch.object(soak,'Client',side_effect=AssertionError):
                first = soak.prepare(root/'first',root/'image',root/'source',root/'acceptance','probe',8*1024**3)
                second = soak.prepare(root/'second',root/'image',root/'source',root/'acceptance','probe',8*1024**3)
                self.assertNotEqual(first['run_id'],second['run_id'])
                self.assertEqual(soak.load(root/'first')[0],first)
                with self.assertRaises(FileExistsError):
                    soak.prepare(root/'first',root/'image',root/'source',root/'acceptance','probe',8*1024**3)
                (root/'first'/'source.tar').write_bytes(b'changed')
                with self.assertRaises(ValueError): soak.load(root/'first')

    def test_inspection_collects_existing_request_without_submitting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            plan = dict(run_id='run', resources=soak.boundary.proof_resources(8*1024**3))
            inputs = {'source.tar':b'source', 'acceptance.tar':b'acceptance', 'image.json':b'{"id":"pinned"}'}
            submission = soak.submission_for_stage('factory-soak-v1-run-0', {'id':'pinned'},
                b'source', b'acceptance', [['/workspace/factory-boundary-probe','--factory-boundary']],
                correlation=dict(job='offline-boundary-proof',stage='baseline',round=0),
                claim_deadline=601,stage='baseline',now=0,resources=plan['resources'])
            submission['specification']['commands'][0]['timeout_secs'] = 30
            submission['execution_specification_digest'] = soak.digest(soak.canonical(submission['specification']).encode())
            journal = soak.Journal(root/'case-00.sqlite')
            journal.prepare(submission,b'source',b'acceptance',soak.utc(86400))
            journal.requested(submission['idempotency_key'])
            journal.close()
            with patch.object(soak,'FactoryChecksV1') as adapter, \
                    patch.object(soak.boundary,'collect_logs',return_value=(b'logs',b'')), \
                    patch.object(soak.boundary,'validate_output'):
                adapter.return_value.collect.return_value = dict(
                    executionIdentity=dict(jobId='job',sessionId='session',vmId='vm',specificationDigest='digest'),
                    results=[dict(exitCode=0)])
                client = unittest.mock.Mock()
                result = soak.observe_case(root,0,plan,inputs,lambda:client,inspect=True)
                self.assertEqual(result['status'],'passed')
                adapter.return_value.collect.assert_called_once_with('factory-soak-v1-run-0')
                adapter.return_value.run_checks.assert_not_called()
                client.submit_job.assert_not_called()
                adapter.return_value.collect.side_effect = TimeoutError('sensitive transport detail')
                result = soak.observe_case(root,0,plan,inputs,lambda:client,inspect=True)
                self.assertEqual(result,dict(index=0,status='unresolved',error_type='TimeoutError'))
                adapter.return_value.run_checks.assert_not_called()

    def test_default_execute_does_no_io_or_network(self):
        with patch.dict(os.environ, {'HUSKER_RUN_FACTORY_SOAK':'0'}), \
                patch('sys.argv',['factory_soak.py','execute','--run-dir','/missing']), \
                patch.object(soak,'load',side_effect=AssertionError), patch('builtins.print') as output:
            soak.main()
            self.assertEqual(json.loads(output.call_args.args[0])['status'],'skipped')


if __name__ == '__main__': unittest.main()
