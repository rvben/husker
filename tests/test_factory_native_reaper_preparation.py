"""Exercise bundle assembly through its offline CLI and the frozen verifier."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'scripts/prepare_factory_native_reaper.py'


class NativeReaperPreparationTests(unittest.TestCase):
    def plan(self, root):
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = (62).to_bytes(2, 'little')
        pins = {}
        for name in ('daemon', 'firecracker', 'probe', 'kernel', 'rootfs'):
            path = root/name
            data = bytes(header)
            if name == 'rootfs':
                data = b'\0'*1080+b'\x53\xef'
            path.write_bytes(data)
            pins[name] = dict(path=str(path), digest='sha256:'+hashlib.sha256(data).hexdigest())
        plan = root/'plan.json'
        plan.write_text(json.dumps(dict(version=1, daemon_build_revision='a'*40, inputs=pins)))
        return plan

    def assemble(self, root, plan, output='bundle'):
        return subprocess.run([sys.executable, str(SCRIPT), '--plan', str(plan),
                               '--output', str(root/output)], capture_output=True, text=True)

    def test_one_command_assembles_frozen_verifiable_bundle_without_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            plan = self.plan(root)
            result = self.assemble(root, plan)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertFalse(receipt['activated'])
            bundle = root/'bundle'
            manifest = json.loads((bundle/'manifest.json').read_text())
            self.assertEqual(manifest['version'], 2)
            provenance = json.loads((bundle/'preparation.json').read_text())
            self.assertEqual(provenance['daemon_build_revision'], 'a'*40)
            self.assertFalse(provenance['daemon_build_revision_verified'])
            self.assertEqual(provenance['source_revision'], subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip())
            with tarfile.open(bundle/'inputs/source.tar') as archive:
                self.assertEqual(set(archive.getnames()), {'factory-lifecycle-probe', 'frozen-sentinel'})
                self.assertEqual(archive.extractfile('factory-lifecycle-probe').read(), (root/'probe').read_bytes())
                self.assertEqual(archive.extractfile('frozen-sentinel').read(), b'factory-boundary-sentinel-v1\n')
                self.assertEqual(archive.getmember('factory-lifecycle-probe').mode, 0o755)
            verify = subprocess.run([sys.executable, str(bundle/'support/scripts/ci/factory_native_reaper_e2e.py'),
                                     'verify', '--bundle', str(bundle), '--sha256', receipt['sha256']],
                                    capture_output=True, text=True)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertFalse((bundle/'control').exists())
            for path in bundle.rglob('*'):
                if path.is_file(): self.assertFalse(path.stat().st_mode & 0o222)
            (bundle/'preparation.json').chmod(0o600)
            (bundle/'preparation.json').write_text('{}')
            changed = subprocess.run(verify.args, capture_output=True, text=True)
            self.assertNotEqual(changed.returncode, 0)

    def test_preparation_is_repeatable_and_never_overwrites_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            plan = self.plan(root)
            first = self.assemble(root, plan, 'one')
            second = self.assemble(root, plan, 'two')
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(json.loads(first.stdout)['sha256'], json.loads(second.stdout)['sha256'])
            for name in ('inputs/source.tar', 'inputs/acceptance.tar', 'manifest.json', 'preparation.json'):
                self.assertEqual((root/'one'/name).read_bytes(), (root/'two'/name).read_bytes())
            sentinel = root/'one/keep'
            sentinel.write_bytes(b'preserve existing work')
            refused = self.assemble(root, plan, 'one')
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(sentinel.read_bytes(), b'preserve existing work')

    def test_mismatched_pin_leaves_no_partial_or_activatable_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            plan = self.plan(root)
            (root/'probe').write_bytes(b'changed after plan was pinned')
            result = self.assemble(root, plan)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('digest mismatch', result.stderr)
            self.assertFalse((root/'bundle').exists())
            self.assertEqual((root/'probe').read_bytes(), b'changed after plan was pinned')

    def test_wrong_guest_architecture_fails_before_any_bundle_is_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = self.plan(root)
            plan = json.loads(path.read_text())
            header = bytearray((root/'probe').read_bytes())
            header[18:20] = (183).to_bytes(2, 'little')
            (root/'probe').write_bytes(header)
            plan['inputs']['probe']['digest'] = 'sha256:'+hashlib.sha256(header).hexdigest()
            path.write_text(json.dumps(plan))
            result = self.assemble(root, path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('x86_64 ELF64', result.stderr)
            self.assertFalse((root/'bundle').exists())

    def test_noncanonical_parent_is_rejected_without_touching_its_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            plan = self.plan(root)
            (root/'target').mkdir()
            (root/'alias').symlink_to(root/'target', target_is_directory=True)
            result = self.assemble(root, plan, 'alias/bundle')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('canonical parent', result.stderr)
            self.assertEqual(list((root/'target').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
