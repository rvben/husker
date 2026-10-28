"""Local bundle validation and activation gates; no daemon or VM is started."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location('mini_pilot', Path(__file__).parents[1] / 'scripts/ci/factory_mini_pilot.py')
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)
TARGET = 'pilot-host'


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = {}
        for name in pilot.REQUIRED_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')
            self.files[name] = dict(digest='sha256:' + hashlib.sha256(b'fixture').hexdigest(), size_bytes=7)

    def manifest(self, version=1, **extra):
        data = json.dumps(dict(version=version, target=TARGET, files=self.files, **extra)).encode()
        (self.root / 'manifest.json').write_bytes(data)
        return 'sha256:' + hashlib.sha256(data).hexdigest()

    def worker_fixture(self):
        worker = dict(protocol_version=1, lifetime_secs=600,
                      state_dir='/private/var/tmp/hvz-abcdef012345', workspace_rust_source_sha256='a'*64)
        path = self.root / 'bin/husker-vz-worker'
        path.write_bytes(b'fixture')
        self.files['bin/husker-vz-worker'] = dict(self.files['bin/husker'])
        receipt = dict(version=1, target='aarch64-apple-darwin',
            workspace_rust_source_sha256='a'*64, daemon_version='husker 0.4.52',
            activated=False, promotion_eligible=False, frozen_source_verified_after_build=True,
            embedded_agent_bytes_present=True,
            binaries={name: dict(sha256=self.files['bin/'+name]['digest'].removeprefix('sha256:'),
                size_bytes=7, signature_verified=True, virtualization_entitlement=True,
                source_stamp_bytes_present=True) for name in ['husker', 'husker-vz-worker']})
        raw = json.dumps(receipt).encode()
        (self.root / 'build-receipt.json').write_bytes(raw)
        self.files['build-receipt.json'] = dict(digest='sha256:'+hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))
        return worker, receipt

    def test_worker_plan_binds_pair_and_renders_explicit_offline_backend(self):
        worker, _ = self.worker_fixture()
        pin = self.manifest(2, worker=worker)
        manifest = pilot.verify(self.root, pin, TARGET)
        config = tomllib.loads(pilot.configuration(self.root, manifest, self.root/'pilot-control', 'synthetic-token'))
        self.assertEqual(config['state_dir'], worker['state_dir'])
        self.assertEqual(config['apple_vz_worker'], dict(
            executable=str(self.root/'bin/husker-vz-worker'),
            sha256=self.files['bin/husker-vz-worker']['digest'].removeprefix('sha256:'),
            protocol_version=1, lifetime_secs=600))
        self.assertEqual(config['factory_resource_budget']['max_jobs'], 1)
        self.assertFalse((self.root/'pilot-control').exists())
        v1 = tomllib.loads(pilot.configuration(self.root, {'version':1}, self.root/'pilot-control', 'synthetic-token'))
        self.assertNotIn('apple_vz_worker', v1)
        self.assertEqual(v1['state_dir'], str(self.root/'pilot-control/state'))

    def test_worker_routing_cannot_be_added_to_v1_approval(self):
        worker, _ = self.worker_fixture()
        pin = self.manifest(1, worker=worker)
        with self.assertRaises(ValueError): pilot.verify(self.root, pin, TARGET)

    def test_worker_plan_rejects_unknown_fields_bool_versions_and_unreviewed_paths(self):
        worker, _ = self.worker_fixture()
        for change in [dict(protocol_version=True), dict(lifetime_secs=True), dict(lifetime_secs=3600),
                       dict(state_dir='/tmp/arbitrary'), dict(state_dir='/private/var/tmp/hvz-../escape'),
                       dict(workspace_rust_source_sha256='bad'), dict(extra=True)]:
            invalid = dict(worker, **change)
            pin = self.manifest(2, worker=invalid)
            with self.assertRaises(ValueError): pilot.verify(self.root, pin, TARGET)
        self.assertFalse((self.root/'pilot-control').exists())

    def test_worker_receipt_must_bind_both_binaries_and_frozen_source(self):
        worker, receipt = self.worker_fixture()
        for field, value in [('workspace_rust_source_sha256', 'b'*64), ('activated', True),
                             ('frozen_source_verified_after_build', False), ('version', True),
                             ('binaries', {'husker':{}})]:
            invalid = dict(receipt, **{field:value})
            raw = json.dumps(invalid).encode()
            (self.root/'build-receipt.json').write_bytes(raw)
            self.files['build-receipt.json'] = dict(digest='sha256:'+hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))
            pin = self.manifest(2, worker=worker)
            with self.assertRaises(ValueError): pilot.verify(self.root, pin, TARGET)
        self.assertFalse((self.root/'pilot-control').exists())

    def test_existing_worker_state_refuses_activation_before_any_mutation(self):
        worker, _ = self.worker_fixture()
        manifest = pilot.verify(self.root, self.manifest(2, worker=worker), TARGET)
        with patch.dict(os.environ, {'HUSKER_RUN_FACTORY_MINI_PILOT':'1'}, clear=True), \
                patch.object(pilot, 'host_inventory', return_value={}), \
                patch.object(pilot.os.path, 'lexists', return_value=True), \
                patch.object(pilot.subprocess, 'Popen') as process:
            with self.assertRaises(ValueError): pilot.activate(self.root, manifest, 19124)
            process.assert_not_called()
        self.assertFalse((self.root/'pilot-control').exists())

    def test_valid_inventory_is_read_only(self):
        pin = self.manifest()
        self.assertEqual(pilot.verify(self.root, pin, TARGET)['target'], TARGET)
        self.assertFalse((self.root / 'pilot-control').exists())

    def test_manifest_for_a_different_target_is_rejected(self):
        pin = self.manifest()
        with self.assertRaises(ValueError):
            pilot.verify(self.root, pin, 'other-host')

    def test_changed_bytes_or_review_digest_are_rejected(self):
        pin = self.manifest()
        with self.assertRaises(ValueError):
            pilot.verify(self.root, 'sha256:' + '0' * 64, TARGET)
        (self.root / 'bin/husker').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            pilot.verify(self.root, pin, TARGET)

    def test_symlinks_hardlinks_and_unsafe_paths_are_rejected(self):
        pin = self.manifest()
        path = self.root / 'bin/husker'
        path.unlink()
        path.symlink_to(self.root / 'source-pins.json')
        with self.assertRaises((ValueError, OSError)): pilot.verify(self.root, pin, TARGET)
        path.unlink()
        os.link(self.root / 'source-pins.json', path)
        with self.assertRaises(ValueError): pilot.verify(self.root, pin, TARGET)
        path.unlink(); path.write_bytes(b'fixture')
        self.files['../outside'] = self.files['bin/husker']
        pin = self.manifest()
        with self.assertRaises(ValueError): pilot.verify(self.root, pin, TARGET)

    def test_incomplete_inventory_and_public_bundle_are_rejected(self):
        self.files.pop('bin/husker')
        pin = self.manifest()
        with self.assertRaises(ValueError): pilot.verify(self.root, pin, TARGET)
        os.chmod(self.root, 0o755)
        with self.assertRaises(ValueError): pilot.verify(self.root, pin, TARGET)
        os.chmod(self.root, 0o700)

    def test_activation_opt_in_precedes_host_checks_and_mutation(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(pilot, 'host_inventory') as host:
            with self.assertRaises(ValueError): pilot.activate(self.root, {}, 19124)
            host.assert_not_called()
        self.assertFalse((self.root / 'pilot-control').exists())

    def test_wrong_host_is_rejected_before_mutation(self):
        with patch.dict(os.environ, {'HUSKER_RUN_FACTORY_MINI_PILOT': '1'}, clear=True), \
                patch.object(pilot.platform, 'system', return_value='Linux'):
            with self.assertRaises(ValueError): pilot.activate(self.root, {}, 19124)
        self.assertFalse((self.root / 'pilot-control').exists())

    def test_m4_and_insufficient_free_space_fail_host_preflight(self):
        for cpu, free in [('Apple M4', 128 * 1024**3), ('Apple M6', 32 * 1024**3)]:
            with patch.object(pilot.platform, 'system', return_value='Darwin'), \
                    patch.object(pilot.platform, 'machine', return_value='arm64'), \
                    patch.object(pilot.subprocess, 'check_output', side_effect=[cpu, str(32 * 1024**3), '10']), \
                    patch.object(pilot.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)):
                with self.assertRaises(ValueError): pilot.host_inventory(self.root)
        self.assertFalse((self.root / 'pilot-control').exists())


if __name__ == '__main__': unittest.main()
