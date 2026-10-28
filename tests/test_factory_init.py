"""Execute PID1 shell control flow with synthetic mounts; never mount on a host."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FactoryInitTests(unittest.TestCase):
    def run_init(self, filesystem, reject_dev=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root / 'commands'
            commands.mkdir()
            mounts = root / 'mounts'
            mounts.write_text('devtmpfs /dev '+filesystem+' rw 0 0\n' if filesystem else '')
            control = root / 'control'
            calls = root / 'calls'
            agent = commands / 'agent'
            scripts = {
                'mkdir': '#!/bin/sh\nexit 0\n',
                'mount': '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                         'if [ "$REJECT_DEV" = 1 ] && [ "$4" = /dev ]; then exit 32; fi\n',
                'agent': '#!/bin/sh\nprintf "agent %s\\n" "$*" >> "$CALLS"\n',
            }
            for name, data in scripts.items():
                path = commands / name
                path.write_text(data)
                path.chmod(0o755)
            script = (ROOT / 'guest/factory/init').read_text()
            script = script.replace('export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                                    'export PATH='+shlex.quote(str(commands))+':/usr/bin:/bin')
            script = script.replace('/proc/self/mounts',shlex.quote(str(mounts)))
            script = script.replace('/sys/fs/cgroup/cgroup.subtree_control',shlex.quote(str(control)))
            script = script.replace('/usr/local/bin/husker-agent',shlex.quote(str(agent)))
            result = subprocess.run(['/bin/sh'],input=script,text=True,capture_output=True,
                                    env=dict(os.environ,CALLS=str(calls),REJECT_DEV=str(int(reject_dev))),
                                    timeout=5)
            return result.returncode,calls.read_text(),control.read_text() if control.exists() else None

    def test_existing_devtmpfs_avoids_duplicate_mount_and_still_delegates_pids(self):
        code,calls,control = self.run_init('devtmpfs',reject_dev=True)
        self.assertEqual(code,0)
        self.assertNotIn('-t devtmpfs devtmpfs /dev',calls)
        self.assertIn('agent --factory-supervisor',calls)
        self.assertEqual(control,'+pids\n')

    def test_missing_devtmpfs_is_mounted_before_supervision(self):
        code,calls,control = self.run_init('')
        self.assertEqual(code,0)
        self.assertEqual(calls.count('-t devtmpfs devtmpfs /dev'),1)
        self.assertIn('agent --factory-supervisor',calls)
        self.assertEqual(control,'+pids\n')

    def test_other_existing_filesystem_does_not_hide_a_mount_failure(self):
        code,calls,control = self.run_init('tmpfs',reject_dev=True)
        self.assertEqual(code,32)
        self.assertNotIn('agent --factory-supervisor',calls)
        self.assertIsNone(control)


if __name__ == '__main__':
    unittest.main()
