import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('restart', Path(__file__).parents[1]/'scripts/ci/factory_restart_e2e.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RestartTests(unittest.TestCase):
    def output(self):
        return json.dumps(probe.lifecycle.READY).encode()+b'\n'

    def fixture(self, cleanup=False):
        record = dict(id='job', session_id='session', vm_id='vm', specification_digest='digest',
            state='unknown', collection='failed', vm_destroyed=cleanup, cleanup_pending=not cleanup,
            vm_allocation_aborted=False, output_truncated=False,
            manifest=json.dumps(dict(collection='failed', host_error=
                'daemon restarted; execution will not be resubmitted; confirmed VM cleanup required')))
        before = {name: record[name] for name in probe.IDENTITY}
        before.update(key='key', stdout_digest=probe.digest(self.output()), stderr_digest=probe.digest(b''))
        return SimpleNamespace(id='job', record=record, terminal=True, cleanup_pending=not cleanup), before

    def test_pending_ownership_cannot_pass_the_cleanup_gate(self):
        snapshot, before = self.fixture()
        result = probe.validate_after(snapshot, before, self.output(), b'')
        self.assertEqual(result['status'], 'incomplete')
        self.assertTrue(result['identity_preserved'])
        self.assertTrue(result['cleanup_pending'])
        self.assertFalse(result['vm_destruction_receipt'])
        self.assertFalse(result['host_resource_cleanup_proven'])
        snapshot, before = self.fixture(cleanup=True)
        result = probe.validate_after(snapshot, before, self.output(), b'')
        self.assertEqual(result['status'], 'passed')
        self.assertFalse(result['crash_injection_proven'])
        self.assertFalse(result['host_resource_cleanup_proven'])
        self.assertFalse(result['promotion_proven'])

    def test_changed_identity_outcome_or_log_prefix_is_rejected(self):
        snapshot, before = self.fixture()
        for name, value in [(name, 'replacement') for name in probe.IDENTITY] + [
                ('state', 'interrupted'), ('state', 'completed'), ('collection', 'complete'),
                ('vm_allocation_aborted', True), ('output_truncated', True), ('vm_destroyed', True)]:
            changed = copy.deepcopy(snapshot)
            changed.record[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                probe.validate_after(changed, before, self.output(), b'')
        changed = copy.deepcopy(snapshot)
        changed.cleanup_pending = False
        with self.assertRaises(ValueError): probe.validate_after(changed, before, self.output(), b'')
        for stdout, stderr in [(b'', b''), (self.output()*2, b''), (self.output(), b'error')]:
            with self.assertRaises(ValueError): probe.validate_after(snapshot, before, stdout, stderr)
        for manifest in [dict(collection='failed'), dict(collection='complete', host_error='daemon restarted'),
                         dict(collection='failed', host_error='command failed')]:
            changed = copy.deepcopy(snapshot)
            changed.record['manifest'] = json.dumps(manifest)
            with self.assertRaises(ValueError): probe.validate_after(changed, before, self.output(), b'')

    def test_lost_ack_is_journaled_and_cannot_submit_again(self):
        from husker import Conflict, TransportError
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            journal = probe.Journal(root/'journal.sqlite')
            client = Mock(); client.submit_job.side_effect = TransportError('lost acknowledgement')
            try:
                for error in (TransportError, Conflict):
                    with self.assertRaises(error):
                        probe.arm(client, journal, 'key', {'id': 'image'}, b'source', b'acceptance',
                            probe.lifecycle.boundary.proof_resources(8*1024**3), root/'before.json')
                self.assertEqual(journal.get('key')['phase'], 'requested')
                client.submit_job.assert_called_once()
                self.assertFalse((root/'before.json').exists())
            finally:
                journal.close()

    def arm_fixture(self, root, *, terminal=False, replayed=False):
        journal = probe.Journal(root/'journal.sqlite')
        snapshot, _ = self.fixture()
        snapshot.record.update(state='running', collection='pending')
        snapshot.terminal = terminal
        snapshot.replayed = replayed
        client = Mock()
        job = client.submit_job.return_value
        job.receipt = snapshot
        job.info.return_value = snapshot
        def submit(submission, *args, **kwargs):
            snapshot.record['specification_digest'] = submission['execution_specification_digest']
            return job
        client.submit_job.side_effect = submit
        return journal, client, snapshot

    def test_inspection_is_get_only_and_requires_original_frozen_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            journal, client, snapshot = self.arm_fixture(root)
            before_path = root/'before.json'
            try:
                with patch.object(probe.lifecycle.boundary, 'collect_logs', return_value=(self.output(), b'')):
                    result = probe.arm(client, journal, 'key', {'id': 'image'}, b'source', b'acceptance',
                        probe.lifecycle.boundary.proof_resources(8*1024**3), before_path)
                    self.assertEqual(result['status'], 'armed')
                    self.assertFalse(result['crash_injected'])
                    snapshot.record.update(state='unknown', collection='failed')
                    snapshot.terminal = True
                    snapshot.replayed = None
                    client.find_job.return_value.receipt = snapshot
                    result = probe.inspect(client, journal, 'key', before_path, {'id': 'image'}, b'source', b'acceptance')
                    self.assertEqual(result['status'], 'incomplete')
                    client.find_job.assert_called_once_with('key', snapshot.record['specification_digest'])
                    client.submit_job.assert_called_once()
                    client.job.return_value.cancel.assert_not_called()
                    client.job.return_value.wait.assert_not_called()
                    for image, source, acceptance in [({'id': 'other'}, b'source', b'acceptance'),
                            ({'id': 'image'}, b'other', b'acceptance'), ({'id': 'image'}, b'source', b'other')]:
                        with self.assertRaises(ValueError):
                            probe.inspect(client, journal, 'key', before_path, image, source, acceptance)
                    self.assertEqual(client.find_job.call_count, 1)
            finally:
                journal.close()

    def test_replayed_or_unready_execution_never_arms_a_crash(self):
        for replayed in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); root.chmod(0o700)
                journal, client, _ = self.arm_fixture(root, terminal=True, replayed=replayed)
                try:
                    with patch.object(probe.lifecycle.boundary, 'collect_logs', return_value=(b'', b'')):
                        with self.assertRaises(ValueError if replayed else TimeoutError):
                            probe.arm(client, journal, 'key', {'id': 'image'}, b'source', b'acceptance',
                                probe.lifecycle.boundary.proof_resources(8*1024**3), root/'before.json')
                    self.assertFalse((root/'before.json').exists())
                    client.submit_job.assert_called_once()
                    client.submit_job.return_value.cancel.assert_not_called()
                finally:
                    journal.close()


if __name__ == '__main__':
    unittest.main()
