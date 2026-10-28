"""Exercise opt-in harnesses through the real SDK wire parsers, without a daemon."""
import base64
import copy
from contextlib import closing
import datetime
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import uuid
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from husker import Client, TransportError
from scripts.ci import factory_lifecycle_e2e as lifecycle
from scripts.ci import factory_soak as soak
from examples.factory_checks_v1 import Journal, canonical


class WireClient(Client):
    """Only the transport boundary is replaced; all supported SDK methods run."""
    def __init__(self, journal_path, outcome, output, *, lose_ack=False, mutation=None):
        super().__init__('http://127.0.0.1:19124', token='fixture-token', timeout=1)
        self.journal_path, self.outcome, self.output = journal_path, outcome, output
        self.lose_ack, self.mutation = lose_ack, mutation
        self.calls, self.wire, self.key = [], None, None

    def _row(self):
        with closing(sqlite3.connect(self.journal_path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute('SELECT * FROM checks WHERE key=?',(self.key,)).fetchone()

    def _request(self, method, path, payload=None, **options):
        self.calls.append((method,path))
        if method == 'POST' and path == '/v1/jobs':
            submission = payload['submission']
            self.key = submission['idempotency_key']
            row = self._row()
            assert row['phase'] == 'requested' and row['job_id'] is None
            assert json.loads(row['submission']) == submission
            assert base64.b64decode(payload['source_bundle']) == row['source']
            assert base64.b64decode(payload['acceptance_bundle']) == row['acceptance']
            spec = submission['specification']
            job_id, session_id, vm_id = [str(uuid.uuid4()) for _ in range(3)]
            manifest = dict(version=1,job_id=job_id,execution_specification_digest=submission['execution_specification_digest'],
                **{name:spec[name] for name in ('image','source','acceptance')},
                source_changed=False,source_verification_error=None,outcome=self.outcome,
                collection_status='complete',artifacts=[],commands=[dict(command_index=0,
                    exit_code=7 if self.outcome == 'command_failed' else None if self.outcome == 'timed_out' else 0,
                    outcome=self.outcome,termination_confirmed=True,termination_error=None,
                    logs_truncated=False,duration_ms=42,output='fixture tail',output_truncated=False)])
            deadline = int(datetime.datetime.fromisoformat(spec['deadline'].replace('Z','+00:00')).timestamp())
            record = dict(id=job_id,session_id=session_id,vm_id=vm_id,vm_name='fixture',
                specification_digest=submission['execution_specification_digest'],specification=canonical(spec),
                created_at=int(time.time()),deadline=deadline,retention_until=deadline+86400,
                state=self.outcome,collection='complete',manifest=canonical(manifest),
                capture_cursor=1,retained_bytes=len(self.output),output_truncated=False,
                cleanup_pending=False,vm_destroyed=True,vm_allocation_aborted=False)
            self.wire = dict(contract_version=1,job=record,artifacts=[],replayed=False,
                references={name:'/v1/jobs/'+job_id+suffix for name,suffix in
                    [('job',''),('events','/events'),('artifacts','/artifacts')]})
            if self.outcome == 'cancelled':
                self.wire['job'].update(state='running',collection='pending',manifest=None,
                    cleanup_pending=True,vm_destroyed=False)
            if self.lose_ack:
                raise TransportError('fixture accepted request but acknowledgement was lost')
            return self._reply(receipt=True)
        if method == 'GET' and path.startswith('/v1/job-submissions?'):
            query = parse_qs(urlsplit(path).query)
            assert query['idempotency_key'] == [self.key]
            assert query['execution_specification_digest'] == [self.wire['job']['specification_digest']]
            return self._reply()
        job_id = self.wire['job']['id']
        row = self._row()
        assert row['job_id'] == job_id and row['session_id'] == self.wire['job']['session_id']
        if method == 'POST' and path == '/v1/jobs/'+job_id+'/cancel':
            self.finish_cancel()
            return self._reply()
        if method == 'GET' and path == '/v1/jobs/'+job_id:
            return self._reply()
        if method == 'GET' and path == '/v1/jobs/'+job_id+'/events?after=0':
            return dict(job_id=job_id,events=[dict(sequence=1,stream='stdout',data=base64.b64encode(self.output).decode())],
                next_cursor=1,has_more=False,output_truncated=False)
        raise AssertionError('unexpected transport operation: '+method+' '+path)

    def finish_cancel(self):
        self.wire['job'].update(state='cancelled',collection='failed',manifest='{"reason":"operator cancelled"}',
            cleanup_pending=False,vm_destroyed=True)

    def _reply(self, receipt=False):
        result = copy.deepcopy(self.wire)
        if not receipt:
            result.pop('replayed',None)
        if self.mutation:
            self.mutation(result)
        return result


class HarnessWireContractTests(unittest.TestCase):
    def image(self):
        return dict(catalog_id=str(uuid.uuid4()),rootfs_digest='sha256:'+'a'*64,
            kernel_digest='sha256:'+'b'*64,initrd_digest=None)

    def test_all_lifecycle_cases_parse_real_v1_wire_receipts_and_journal_before_observation(self):
        for case in lifecycle.ALL_CASES:
            outcome=lifecycle.outcome(case)
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'journal.sqlite'
                journal=Journal(path)
                client=WireClient(path,outcome,canonical(lifecycle.PIDS if case == 'pids_limit' else lifecycle.READY).encode()+b'\n')
                try:
                    result=lifecycle.run_case(client,journal,'key',case,self.image(),b'source',b'acceptance',
                        lifecycle.boundary.proof_resources(8*1024**3))
                    self.assertEqual(result['status'],'passed')
                    self.assertEqual(sum(method=='POST' and url=='/v1/jobs' for method,url in client.calls),1)
                    cancel_calls=[url for method,url in client.calls if method=='POST' and url.endswith('/cancel')]
                    self.assertEqual(len(cancel_calls),int(outcome=='cancelled'))
                    self.assertEqual(journal.get('key')['job_id'],result['job_id'])
                finally:
                    journal.close()

    def test_lost_ack_recovery_uses_supported_lookup_and_never_submits_or_cancels(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'journal.sqlite'; journal=Journal(path)
            client=WireClient(path,'cancelled',canonical(lifecycle.READY).encode()+b'\n',lose_ack=True)
            image=self.image(); resources=lifecycle.boundary.proof_resources(8*1024**3)
            try:
                with self.assertRaises(TransportError):
                    lifecycle.run_case(client,journal,'key','cancelled',image,b'source',b'acceptance',resources)
                self.assertIsNone(journal.get('key')['job_id'])
                client.finish_cancel()  # Simulated eventual host result; no real VM is started.
                client.calls.clear()
                result=lifecycle.run_case(client,journal,'key','cancelled',image,b'source',b'acceptance',resources,inspect=True)
                self.assertEqual(result['status'],'passed')
                self.assertFalse(result['fresh_acceptance_proven'])
                self.assertTrue(all(method=='GET' for method,_ in client.calls))
                self.assertTrue(client.calls[0][1].startswith('/v1/job-submissions?'))
            finally:
                journal.close()

    def test_replayed_fault_acceptance_is_durably_excluded_before_cancel_and_during_inspect(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'journal.sqlite'; journal=Journal(path)
            client=WireClient(path,'cancelled',canonical(lifecycle.READY).encode()+b'\n',
                mutation=lambda reply: reply.update(replayed=True))
            image=self.image(); resources=lifecycle.boundary.proof_resources(8*1024**3)
            try:
                with self.assertRaises(ValueError):
                    lifecycle.run_case(client,journal,'key','cancelled',image,b'source',b'acceptance',resources)
                self.assertEqual(journal.get('key')['acceptance_replayed'],1)
                self.assertEqual(journal.get('key')['job_id'],client.wire['job']['id'])
                self.assertEqual(client.calls,[('POST','/v1/jobs')])
                with self.assertRaises(ValueError):
                    lifecycle.run_case(client,journal,'key','cancelled',image,b'source',b'acceptance',resources,inspect=True)
                self.assertEqual(client.calls,[('POST','/v1/jobs')])
            finally:
                journal.close()

    def test_replayed_soak_acceptance_stays_excluded_after_reopening_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); root.chmod(0o700)
            plan=dict(run_id=str(uuid.uuid4()),resources=soak.boundary.proof_resources(8*1024**3))
            inputs={'source.tar':b'source','acceptance.tar':b'acceptance','image.json':canonical(self.image()).encode()}
            client=WireClient(root/'case-00.sqlite','completed',b'not collected',
                mutation=lambda reply: reply.update(replayed=True))
            result=soak.observe_case(root,0,plan,inputs,lambda:client)
            self.assertEqual(result['status'],'unresolved')
            self.assertEqual(client.calls,[('POST','/v1/jobs')])
            journal=Journal(root/'case-00.sqlite')
            try:
                self.assertEqual(journal.get(client.key)['acceptance_replayed'],1)
                self.assertEqual(journal.get(client.key)['job_id'],client.wire['job']['id'])
            finally:
                journal.close()
            result=soak.observe_case(root,0,plan,inputs,lambda:client,inspect=True)
            self.assertEqual(result['status'],'unresolved')
            self.assertEqual(client.calls,[('POST','/v1/jobs')])

    def test_legacy_journal_migration_preserves_frozen_unidentified_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'journal.sqlite'; journal=Journal(path)
            client=WireClient(path,'cancelled',canonical(lifecycle.READY).encode()+b'\n',lose_ack=True)
            try:
                with self.assertRaises(TransportError):
                    lifecycle.run_case(client,journal,'key','cancelled',self.image(),b'source',b'acceptance',
                        lifecycle.boundary.proof_resources(8*1024**3))
                frozen=journal.get('key')['submission']
            finally:
                journal.close()
            with closing(sqlite3.connect(path)) as db:
                db.execute('ALTER TABLE checks DROP COLUMN acceptance_replayed')
                db.commit()
            journal=Journal(path)
            try:
                row=journal.get('key')
                self.assertEqual(row['submission'],frozen)
                self.assertEqual(row['phase'],'requested')
                self.assertIsNone(row['acceptance_replayed'])
                self.assertIsNone(row['job_id'])
            finally:
                journal.close()

    def test_soak_uses_real_sdk_collection_and_rejects_malformed_cleanup_receipt(self):
        records=[dict(type='check',name=name,ok=True,errno=0) for name in sorted(soak.boundary.NAMES)]
        records.append(dict(type='summary',scope='offline-job-subset-v1',checks=11,failed=0))
        output=b'\n'.join(canonical(item).encode() for item in records)+b'\n'
        for malformed in (False,True):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); root.chmod(0o700)
                plan=dict(run_id=str(uuid.uuid4()),resources=soak.boundary.proof_resources(8*1024**3))
                inputs={'source.tar':b'source','acceptance.tar':b'acceptance','image.json':canonical(self.image()).encode()}
                mutation=(lambda reply: reply['job'].update(vm_destroyed='true')) if malformed else None
                client=WireClient(root/'case-00.sqlite','completed',output,mutation=mutation)
                result=soak.observe_case(root,0,plan,inputs,lambda:client)
                self.assertEqual(result['status'],'unresolved' if malformed else 'passed')
                count_before=len(client.calls)
                recovered=soak.observe_case(root,0,plan,inputs,lambda:client,inspect=True)
                self.assertEqual(recovered['status'],'unresolved' if malformed else 'passed')
                self.assertTrue(all(method=='GET' for method,_ in client.calls[count_before:]))


if __name__ == '__main__': unittest.main()
