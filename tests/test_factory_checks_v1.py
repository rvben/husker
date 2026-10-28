"""Adapter contracts with real durable SQLite and scripted supported SDK calls."""
import copy
import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from husker import Conflict, JobArtifact, JobSnapshot, NotFound, TransportError

spec = importlib.util.spec_from_file_location('factory_checks_v1', Path(__file__).parents[1]/'examples/factory_checks_v1.py')
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
ID = '01234567-89ab-cdef-0123-456789abcdef'
SESSION = '11234567-89ab-cdef-0123-456789abcdef'


class ScriptedJob:
    def __init__(self, client):
        self.client = client
        self.receipt = client.snapshot
    def wait(self, **options):
        row = self.client.journal.get(self.client.submitted_key)
        assert row['job_id'] == self.receipt.id and row['session_id'] == self.receipt.record['session_id']
        self.client.calls.append(('wait', options))
        return self.receipt
    def artifact(self, index):
        self.client.calls.append(('artifact', index))
        return JobArtifact(self.receipt.artifacts[index], self.client.artifact_data)
    def cancel(self):
        self.client.calls.append(('cancel', ID))
        return self.receipt


class ScriptedClient:
    def __init__(self, snapshot, journal):
        self.snapshot, self.journal = snapshot, journal
        self.calls, self.lose_response, self.missing = [], False, False
        self.artifact_data = b'declared artifact'
    def submit_job(self, submission, source, acceptance, **options):
        row = self.journal.get(submission['idempotency_key'])
        assert row['phase'] == 'requested'
        assert row['job_id'] is None
        assert row['source'] == source and row['acceptance'] == acceptance
        self.submitted_key = submission['idempotency_key']
        self.calls.append(('POST', submission))
        if self.lose_response:
            raise TransportError('lost acknowledgement after acceptance')
        return ScriptedJob(self)
    def find_job(self, key, digest):
        self.calls.append(('GET', key))
        if self.missing:
            raise NotFound('no acceptance in this journal')
        return ScriptedJob(self)
    def job(self, job_id, **options):
        assert job_id == self.snapshot.id
        self.calls.append(('connect', job_id))
        return ScriptedJob(self)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/'journal.db'
        self.journal = adapter.Journal(self.path)
        self.now = int(time.time())
        self.claim = self.now + 3600
        self.source, self.acceptance = b'frozen source', b'frozen acceptance'
        self.image = dict(catalog_id=ID, rootfs_digest='sha256:'+'a'*64,
                          kernel_digest='sha256:'+'b'*64, initrd_digest=None)
        self.submission = adapter.submission_for_stage('baseline/round-1', self.image,
            self.source, self.acceptance, [['printf', '$HOME;λ'], ['false']],
            stage='baseline', correlation=dict(job='issue-fixture',stage='baseline',round=1),
            claim_deadline=self.claim, now=self.now)
        self.snapshot = self.evidence()
        self.client = ScriptedClient(self.snapshot, self.journal)
        self.checks = adapter.FactoryChecksV1(self.client, self.journal)
    def tearDown(self):
        self.journal.close()
        self.temp.cleanup()
    def evidence(self):
        spec = self.submission['specification']
        result = dict(version=1, job_id=ID,
            execution_specification_digest=self.submission['execution_specification_digest'],
            image=spec['image'], source=spec['source'], acceptance=spec['acceptance'],
            commands=[dict(command_index=i,exit_code=code,outcome='completed' if code==0 else 'command_failed',
                           termination_confirmed=True,termination_error=None,duration_ms=42+i,
                           output='bounded command tail',output_truncated=True,logs_truncated=False)
                      for i,code in enumerate([0,1])],
            artifacts=[],source_changed=False,source_verification_error=None,
            collection_status='complete',outcome='command_failed')
        record = dict(id=ID, session_id=SESSION, vm_id='31234567-89ab-cdef-0123-456789abcdef',
                      vm_destroyed=True, state='command_failed', collection='complete',
                      cleanup_pending=False, output_truncated=False,
                      specification_digest=self.submission['execution_specification_digest'],
                      manifest=adapter.canonical(result))
        return JobSnapshot(record, [], dict(job='/v1/jobs/'+ID,events='/v1/jobs/'+ID+'/events',artifacts='/v1/jobs/'+ID+'/artifacts'))
    def run_checks(self):
        return self.checks.run_checks(self.submission,self.source,self.acceptance,
            retention_until=adapter.utc(self.now+86400),claim_deadline=self.claim)
    def prepare(self):
        self.journal.prepare(self.submission,self.source,self.acceptance,adapter.utc(self.now+86400))
    def test_default_budgets_literal_argv_and_separate_stage_identity(self):
        baseline = self.submission['specification']
        self.assertEqual(baseline['deadline'],adapter.utc(self.now+600))
        self.assertEqual(baseline['commands'][0]['argv'],['printf','$HOME;λ'])
        self.assertEqual(baseline['commands'][0]['timeout_secs'],600)
        candidate = adapter.submission_for_stage('candidate/round-1',self.image,self.source,self.acceptance,[['true']],
            correlation=dict(job='issue-fixture',stage='candidate',round=1),claim_deadline=self.claim,now=self.now)
        self.assertEqual(candidate['specification']['deadline'],adapter.utc(self.now+1800))
        self.assertEqual(candidate['specification']['commands'][0]['timeout_secs'],1200)
        self.assertNotEqual(candidate['execution_specification_digest'],self.submission['execution_specification_digest'])
        with self.assertRaises(ValueError):
            adapter.submission_for_stage('short',self.image,self.source,self.acceptance,[['true']],
                correlation={'stage':'candidate'},claim_deadline=self.now+1200,now=self.now)
    def test_acceptance_failure_preserves_docker_result_shape_and_journals_before_wait(self):
        result = self.run_checks()
        self.assertEqual(result['results'][0]['argv'],['printf','$HOME;λ'])
        self.assertEqual([item['exitCode'] for item in result['results']],[0,1])
        self.assertEqual(result['results'][1]['durationMs'],43)
        self.assertEqual(result['results'][0]['output'],'bounded command tail')
        self.assertEqual(result['executionIdentity']['jobId'],ID)
        row = self.journal.get(self.submission['idempotency_key'])
        self.assertEqual(row['job_id'],ID)
        self.assertEqual(row['session_id'],SESSION)
        self.assertEqual(row['phase'],'collected')
        self.assertEqual(json.loads(row['evidence'])['results'],result['results'])
        with self.assertRaises(Conflict): self.run_checks()
        self.assertEqual(sum(call[0]=='POST' for call in self.client.calls),1)
    def test_outbound_request_uses_journaled_copy_when_callers_mutate_their_input(self):
        requested = self.journal.requested
        def mutate(key):
            requested(key)
            self.submission['specification']['commands'][0]['argv']=['changed-after-freeze']
        self.journal.requested = mutate
        result = self.run_checks()
        sent = next(call[1] for call in self.client.calls if call[0]=='POST')
        self.assertEqual(sent['specification']['commands'][0]['argv'],['printf','$HOME;λ'])
        self.assertEqual(result['results'][0]['argv'],['printf','$HOME;λ'])

    def test_lost_response_reopen_inspects_without_resubmission(self):
        self.client.lose_response = True
        with self.assertRaises(adapter.Unavailable): self.run_checks()
        self.assertEqual(self.journal.get(self.submission['idempotency_key'])['phase'],'requested')
        self.journal.close()
        self.journal = adapter.Journal(self.path)
        self.client.journal = self.journal
        self.checks = adapter.FactoryChecksV1(self.client,self.journal)
        snapshot = self.checks.inspect(self.submission['idempotency_key'])
        self.assertEqual(snapshot.id,ID)
        result = self.checks.collect(self.submission['idempotency_key'])
        self.assertEqual(result['results'][1]['exitCode'],1)
        self.assertEqual(sum(call[0]=='POST' for call in self.client.calls),1)
        self.assertEqual(self.journal.get(self.submission['idempotency_key'])['phase'],'collected')
    def test_missing_acceptance_never_executes_and_pending_cleanup_never_passes(self):
        self.prepare()
        self.client.missing = True
        with self.assertRaises(adapter.Unavailable): self.checks.inspect(self.submission['idempotency_key'])
        self.assertEqual([call[0] for call in self.client.calls],['GET'])
        self.client.missing = False
        self.snapshot.record['cleanup_pending'] = True
        with self.assertRaises(adapter.Unavailable): self.checks.collect(self.submission['idempotency_key'])
        self.assertFalse(any(call[0]=='POST' for call in self.client.calls))
    def test_uncertain_or_inconsistent_evidence_is_never_a_check_failure_or_success(self):
        self.prepare()
        original = copy.deepcopy(self.snapshot.record)
        changes = [dict(state='unknown'),dict(state='timed_out'),dict(collection='failed'),dict(output_truncated=True),dict(vm_destroyed=False)]
        for change in changes:
            self.snapshot.record.update(original); self.snapshot.record.update(change)
            with self.assertRaises(adapter.Unavailable): self.checks.collect(self.submission['idempotency_key'])
        self.snapshot.record.update(original)
        manifest = json.loads(original['manifest'])
        for change in [dict(source_changed=True),dict(source_verification_error='changed'),dict(commands=[]),dict(version=True)]:
            self.snapshot.record['manifest']=adapter.canonical(dict(manifest,**change))
            with self.assertRaises(adapter.Unavailable): self.checks.collect(self.submission['idempotency_key'])
        self.snapshot.record['manifest']=original['manifest']
        for code in (125,126,127,137,143):
            changed=copy.deepcopy(manifest); changed['commands'][1]['exit_code']=code
            self.snapshot.record['manifest']=adapter.canonical(changed)
            with self.assertRaises(adapter.Unavailable): self.checks.collect(self.submission['idempotency_key'])
    def test_declared_artifact_inventory_and_download_are_required(self):
        self.submission['specification']['artifacts']=[dict(path='results/check.bin',max_bytes=64)]
        self.submission['execution_specification_digest']=adapter.digest(adapter.canonical(self.submission['specification']).encode())
        self.snapshot=self.evidence()
        data=b'declared artifact'
        descriptor=dict(index=0,path='results/check.bin',size_bytes=len(data),digest=adapter.digest(data))
        self.snapshot.artifacts.append(descriptor)
        manifest=json.loads(self.snapshot.record['manifest'])
        manifest['artifacts']=[dict(path=descriptor['path'],stored_name='0.bin',digest=descriptor['digest'],size_bytes=len(data),error=None)]
        self.snapshot.record['manifest']=adapter.canonical(manifest)
        self.client.snapshot=self.snapshot
        self.prepare()
        result=self.checks.collect(self.submission['idempotency_key'])
        self.assertEqual(result['artifactBytes'][0],data)
        self.assertEqual(result['artifactManifest'],[descriptor])
        self.snapshot.artifacts.clear()
        with self.assertRaises(adapter.Unavailable): self.checks.collect(self.submission['idempotency_key'])
        self.assertEqual(self.journal.get(self.submission['idempotency_key'])['phase'],'collected')

    def test_reconnect_identity_conflict_and_private_journal_guard(self):
        self.prepare()
        self.checks.inspect(self.submission['idempotency_key'])
        self.snapshot.record['session_id']='21234567-89ab-cdef-0123-456789abcdef'
        with self.assertRaises(Conflict): self.checks.inspect(self.submission['idempotency_key'])
        link=Path(self.temp.name)/'linked.db'; link.symlink_to(self.path)
        with self.assertRaises(ValueError): adapter.Journal(link)
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        self.assertNotIn('Authorization',self.journal.get(self.submission['idempotency_key'])['submission'])

if __name__=='__main__': unittest.main()
