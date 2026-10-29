import copy
import importlib.util
import io
import tarfile
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('lifecycle',Path(__file__).parents[1]/'scripts/ci/factory_lifecycle_e2e.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class LifecycleTests(unittest.TestCase):
    def test_payload_bytes_match_rust_frozen_bundle_fixtures(self):
        fixtures = Path(__file__).parent/'fixtures'
        source = (fixtures/'lifecycle-source.frozen.tar').read_bytes()
        acceptance = (fixtures/'lifecycle-acceptance.frozen.tar').read_bytes()
        self.assertEqual(probe.frozen_payload(b'probe\n'), source)
        self.assertEqual(probe.frozen_payload(), acceptance)
        probe.validate_inputs(source, acceptance, probe.digest(b'probe\n'))

    def test_readable_but_noncanonical_tar_is_rejected_before_submission(self):
        source = (Path(__file__).parent/'fixtures/lifecycle-source.frozen.tar').read_bytes()
        for mode in (0o444, 0o644):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                item = tarfile.TarInfo('frozen-sentinel')
                item.mode, item.size = mode, len(probe.boundary.SENTINEL)
                archive.addfile(item, io.BytesIO(probe.boundary.SENTINEL))
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'canonical FrozenBundle'):
                probe.validate_inputs(source, stream.getvalue(), probe.digest(b'probe\n'))

    def fixture(self, case):
        submission = probe.submission_for_stage('key',{'id':'image'},b'source',b'acceptance',
            [probe.command(case)['argv']],correlation=dict(job='escaped-family-proof',stage='baseline',round=probe.ALL_CASES.index(case)),
            claim_deadline=601,stage='baseline',now=0,resources=probe.boundary.proof_resources(8*1024**3))
        submission['specification']['commands'] = [probe.command(case)]
        submission['execution_specification_digest'] = probe.digest(probe.canonical(submission['specification']).encode())
        manifest = dict(version=1,job_id='job',execution_specification_digest=submission['execution_specification_digest'],
            **{name:submission['specification'][name] for name in ('image','source','acceptance')},
            source_changed=False,source_verification_error=None,outcome=probe.outcome(case),collection_status='complete',
            commands=[dict(command_index=0,outcome=probe.outcome(case),exit_code=7 if case == 'command_failed' else 0 if case == 'pids_limit' else None,
                termination_confirmed=True,termination_error=None,logs_truncated=False)])
        record = dict(vm_destroyed=True,vm_id='vm',session_id='session',state=probe.outcome(case),output_truncated=False,
            collection='complete',manifest=json.dumps(manifest),specification_digest=submission['execution_specification_digest'])
        return submission,SimpleNamespace(id='job',record=record,terminal=True,cleanup_pending=False,replayed=False),manifest

    def output(self):
        return json.dumps(probe.READY).encode()+b'\n'

    def test_fault_evidence_requires_family_ready_and_positive_termination(self):
        for case in probe.CASES:
            submission,snapshot,manifest = self.fixture(case)
            probe.validate_spec(submission['specification'],case)
            result = probe.validate_result(snapshot,submission,case,self.output(),b'')
            self.assertEqual(result['guest_cgroup_termination_proven'],case != 'cancelled')
            for field,value in [('state','completed'),('vm_destroyed',False),('vm_allocation_aborted',True),
                                ('output_truncated',True),('vm_id',None)]:
                changed=copy.deepcopy(snapshot); changed.record[field]=value
                with self.assertRaises(ValueError): probe.validate_result(changed,submission,case,self.output(),b'')
            snapshot.cleanup_pending=True
            with self.assertRaises(ValueError): probe.validate_result(snapshot,submission,case,self.output(),b'')
            snapshot.cleanup_pending=False
            for output in (b'',self.output()*2,b'not-json'):
                with self.assertRaises(ValueError): probe.validate_result(snapshot,submission,case,output,b'')
            if case != 'cancelled':
                for field,value in [('termination_confirmed',False),('termination_error','failed'),
                                    ('logs_truncated',True),('exit_code',0),('command_index',True)]:
                    changed=copy.deepcopy(manifest); changed['commands'][0][field]=value
                    snapshot.record['manifest']=json.dumps(changed)
                    with self.assertRaises(ValueError): probe.validate_result(snapshot,submission,case,self.output(),b'')

    def test_pids_pressure_requires_exact_population_and_kernel_limit_event(self):
        output=json.dumps(probe.PIDS).encode()+b'\n'
        submission,snapshot,_=self.fixture('pids_limit')
        probe.validate_spec(submission['specification'],'pids_limit')
        result=probe.validate_result(snapshot,submission,'pids_limit',output,b'')
        self.assertTrue(result['pids_limit_exercised'])
        self.assertTrue(result['guest_cgroup_termination_proven'])
        for field,value in [('spawned',62),('pids_max',65),('pids_current',63),
                            ('fork_errno',12),('limit_event_increased',False),
                            ('limit_event_increased',1),('fork_errno',True)]:
            altered=dict(probe.PIDS); altered[field]=value
            with self.assertRaises(ValueError):
                probe.validate_result(snapshot,submission,'pids_limit',json.dumps(altered).encode(),b'')
        with self.assertRaises(ValueError):
            probe.validate_result(snapshot,submission,'pids_limit',self.output(),b'')
        submission['specification']['resources']['pids_limit']=65
        with self.assertRaises(ValueError): probe.validate_spec(submission['specification'],'pids_limit')

    def test_inspect_only_looks_up_original_identity_never_cancels(self):
        submission,snapshot,_ = self.fixture('cancelled')
        journal = Mock()
        journal.get.return_value=dict(submission=json.dumps(submission),source=b'source',acceptance=b'acceptance',acceptance_replayed=0)
        client = Mock()
        with patch.object(probe,'FactoryChecksV1') as adapter, patch.object(probe.boundary,'collect_logs',return_value=(self.output(),b'')):
            adapter.return_value.inspect.return_value=snapshot
            result=probe.run_case(client,journal,'key','cancelled',{'id':'image'},b'source',b'acceptance',{},inspect=True)
            self.assertEqual(result['status'],'passed')
            client.submit_job.assert_not_called()
            client.job.return_value.cancel.assert_not_called()
            client.job.return_value.wait.assert_not_called()
            journal.prepare.assert_not_called()
            journal.bind.assert_not_called()
            adapter.return_value.inspect.assert_called_once_with('key')

    def test_cancel_requires_complete_readiness_after_journaling_uuid(self):
        submission,snapshot,_ = self.fixture('cancelled')
        journal=Mock(); journal.get.return_value={'retention':'retained','acceptance_replayed':0}
        job=Mock(); job.receipt=snapshot; job.info.return_value.terminal=False; job.wait.return_value=snapshot
        client=Mock(); client.submit_job.return_value=job
        events=[]
        journal.requested.side_effect=lambda key: events.append('requested')
        def submit(frozen, *args, **kwargs):
            events.append('submit')
            snapshot.record['specification_digest']=frozen['execution_specification_digest']
            return job
        client.submit_job.side_effect=submit
        journal.bind.side_effect=lambda *args: events.append('bind')
        job.cancel.side_effect=lambda: events.append('cancel')
        with patch.object(probe.boundary,'collect_logs',side_effect=[(b'{"type":',b''),(self.output(),b''),(self.output(),b'')]), patch.object(probe.time,'sleep'):
            result=probe.run_case(client,journal,'key','cancelled',{'id':'image'},b'source',b'acceptance',submission['specification']['resources'])
        self.assertEqual(result['status'],'passed')
        self.assertEqual(events,['requested','submit','bind','cancel'])
        job.cancel.assert_called_once()

    def test_unconfirmed_readiness_never_cancels_or_resubmits(self):
        submission,snapshot,_ = self.fixture('cancelled')
        journal=Mock(); journal.get.return_value={'retention':'retained','acceptance_replayed':0}
        job=Mock(); job.receipt=snapshot; job.info.return_value.terminal=True
        client=Mock(); client.submit_job.return_value=job
        with patch.object(probe.boundary,'collect_logs',return_value=(b'',b'')):
            with self.assertRaises(TimeoutError):
                probe.run_case(client,journal,'key','cancelled',{'id':'image'},b'source',b'acceptance',submission['specification']['resources'])
        client.submit_job.assert_called_once(); job.cancel.assert_not_called()

    def test_lost_submission_response_preserves_request_and_recovers_get_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            root.chmod(0o700)
            journal=probe.Journal(root/'lifecycle.sqlite')
            client=Mock()
            from husker import TransportError
            client.submit_job.side_effect=TransportError('lost acknowledgement')
            resources=probe.boundary.proof_resources(8*1024**3)
            try:
                with self.assertRaises(TransportError):
                    probe.run_case(client,journal,'key','cancelled',{'id':'image'},b'source',b'acceptance',resources)
                row=journal.get('key')
                self.assertEqual(row['phase'],'requested')
                self.assertIsNone(row['job_id'])
                self.assertEqual(row['source'],b'source')
                frozen=json.loads(row['submission'])
                _,snapshot,_=self.fixture('cancelled')
                snapshot.record['specification_digest']=frozen['execution_specification_digest']
                client.find_job.return_value.receipt=snapshot
                with patch.object(probe.boundary,'collect_logs',return_value=(self.output(),b'')):
                    result=probe.run_case(client,journal,'key','cancelled',{'id':'image'},b'source',b'acceptance',resources,inspect=True)
                self.assertEqual(result['status'],'passed')
                client.submit_job.assert_called_once()
                client.find_job.assert_called_once_with('key',frozen['execution_specification_digest'])
                client.job.return_value.cancel.assert_not_called()
                self.assertEqual(journal.get('key')['job_id'],'job')
            finally:
                journal.close()

    def test_native_probe_refuses_execution_and_arm_probe_cross_compiles(self):
        source=probe.boundary.ROOT/'guest/factory/lifecycle-probe.c'
        with tempfile.TemporaryDirectory() as directory:
            native=Path(directory)/'native'
            if subprocess.check_output(['uname','-s']).strip() == b'Darwin' and shutil.which('cc'):
                result=subprocess.run(['cc','-Wall','-Wextra','-Werror',str(source),'-o',str(native)],capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stderr)
                result=subprocess.run([str(native),'--hold-family'],capture_output=True,timeout=5)
                self.assertEqual(result.returncode,2)
                self.assertIn(b'refusing host execution',result.stderr)
            compiler=shutil.which('aarch64-linux-musl-gcc')
            if not compiler: self.skipTest('ARM musl compiler unavailable')
            result=subprocess.run([compiler,'-static','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(Path(directory)/'arm')],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            # ARM binary is never executed by this local test.


if __name__ == '__main__': unittest.main()
