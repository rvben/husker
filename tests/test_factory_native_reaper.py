"""CLI safety gates run without root, systemd or KVM."""
import importlib.util
import hashlib
import tempfile
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/ci/factory_native_reaper_e2e.py'


class NativeReaperCommandTests(unittest.TestCase):
    def test_normal_invocation_skips_before_reading_inputs_or_touching_host(self):
        env = dict(os.environ)
        env.pop('HUSKER_RUN_FACTORY_NATIVE_REAPER_E2E', None)
        result = subprocess.run([sys.executable, str(SCRIPT), 'run', '--bundle', '/does/not/exist'],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), dict(status='skipped', activated=False,
                         reason='HUSKER_RUN_FACTORY_NATIVE_REAPER_E2E=1 required'))

    def test_prepare_freezes_inputs_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory).resolve()
            bundle.chmod(0o700)
            for relative in ['bin/husker', 'bin/firecracker', 'bin/factory-lifecycle-probe',
                             'prepared/vmlinux', 'prepared/rootfs.ext4',
                             'inputs/source.tar', 'inputs/acceptance.tar']:
                path = bundle/relative
                path.parent.mkdir(exist_ok=True, mode=0o700)
                path.write_bytes(b'fixture input')
                path.chmod(0o600)
            command = [sys.executable, str(SCRIPT), 'prepare', '--bundle', str(bundle)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            receipt = json.loads(first.stdout)
            raw = (bundle/'manifest.json').read_bytes()
            self.assertEqual(receipt['sha256'], hashlib.sha256(raw).hexdigest())
            manifest = json.loads(raw)
            self.assertEqual(manifest['files']['bin/husker']['sha256'],
                             'bda3c7ef0c3f3baaf9aef92a40301bf443a131e675fd259d9bc9d46580e063e8')
            self.assertTrue((bundle/'support/scripts/ci/factory_restart_e2e.py').is_file())
            verify = [sys.executable, str(SCRIPT), 'verify', '--bundle', str(bundle),
                      '--sha256', receipt['sha256']]
            checked = subprocess.run(verify, capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            (bundle/'inputs/source.tar').write_bytes(b'tampered')
            rejected = subprocess.run(verify, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((bundle/'control').exists())
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual((bundle/'manifest.json').read_bytes(), raw)

    @unittest.skipIf(sys.platform == 'linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'internal commands require Linux root')
    def test_internal_unit_commands_refuse_unprivileged_invocation(self):
        for mode in ('_controller', '_watchdog'):
            result = subprocess.run([sys.executable, str(SCRIPT), mode, '--bundle', '/does/not/exist'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('private root unit required', result.stderr)

    def test_only_exact_positive_native_reaper_confirmation_counts(self):
        spec = importlib.util.spec_from_file_location('native_reaper', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        positive = ('WARN husker_core: reaped orphaned VMM process from a prior daemon '
                    'pid=123 vm=job-abc')
        self.assertEqual(module.confirm_reaper(positive, 123, 'abc'), [positive])
        for log in ('', positive.replace('pid=123', 'pid=1234'),
                    positive.replace('vm=job-abc', 'vm=job-abcd'),
                    'systemd killed orphan pid=123 vm=job-abc', positive+'\n'+positive):
            with self.subTest(log=log), self.assertRaises(ValueError):
                module.confirm_reaper(log, 123, 'abc')


if __name__ == '__main__':
    unittest.main()
