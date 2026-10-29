#!/usr/bin/env python3
"""Opt-in, one-job Linux daemon SIGKILL/native-reaper regression check.

See docs/native-reaper-regression.md. No downloads or installed-unit mutations.
"""
import argparse
import ipaddress
import re
import secrets
import select
import signal
import socket
import sqlite3
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener
import hashlib
from pathlib import Path
import shutil
import stat
import sys
import json
import os


INPUTS = {'bin/husker': 512*1024**2, 'bin/firecracker': 128*1024**2,
          'bin/factory-lifecycle-probe': 4*1024**2, 'prepared/vmlinux': 128*1024**2,
          'prepared/rootfs.ext4': 8*1024**3, 'inputs/source.tar': 32*1024**2,
          'inputs/acceptance.tar': 32*1024**2}
SUPPORT = ['husker/__init__.py', 'husker/jobs.py', 'examples/factory_checks_v1.py',
           *['scripts/ci/'+name+'.py' for name in ('factory_boundary_e2e',
             'factory_lifecycle_e2e', 'factory_soak', 'factory_restart_e2e',
             'factory_native_reaper_e2e')]]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_directory(path, owner):
    metadata = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == owner and stat.S_IMODE(metadata.st_mode) == 0o700,
            'bundle must be an absolute, owned private 0700 directory without symlinks')


def pin(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and 0 < metadata.st_size <= limit, 'input must be a bounded independent regular file')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(2*1024**2), b''):
            require(stream.tell() <= limit, 'input grew beyond bound')
            digest.update(chunk)
        require(stream.tell() == metadata.st_size, 'input changed while hashing')
    return dict(sha256=digest.hexdigest(), size=metadata.st_size)


def write_once(path, value):
    # Publish complete receipts atomically; the watchdog reads them independently.
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.link(temporary, path)  # Exclusive publication, never overwrite prior evidence.
    temporary.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(bundle, preparation=None):
    private_directory(bundle, os.geteuid())
    require(not (bundle/'manifest.json').exists() and not (bundle/'control').exists(),
            'existing preparation or execution must never be reused')
    for name, limit in INPUTS.items():
        for parent in (bundle/name).parents:
            if parent == bundle: break
            require(not parent.is_symlink(), 'symlink input directory')
        pin(bundle/name, limit)
    if preparation is not None:
        write_once(bundle/'preparation.json', preparation)
    else:
        require(not (bundle/'preparation.json').exists(), 'unbound preparation receipt')
    support = bundle/'support'
    support.mkdir(mode=0o700)
    repo = Path(__file__).resolve().parents[2]
    for relative in SUPPORT:
        destination = support/relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(repo/relative, destination)
        destination.chmod(0o500 if relative.endswith('factory_native_reaper_e2e.py') else 0o400)
    files = {name: pin(bundle/name, limit) for name, limit in INPUTS.items()}
    files.update({'support/'+name: pin(support/name, 1024**2) for name in SUPPORT})
    if preparation is not None:
        files['preparation.json'] = pin(bundle/'preparation.json', 65536)
    write_once(bundle/'manifest.json', dict(version=2 if preparation is not None else 1, files=files))
    return dict(status='prepared', activated=False,
                sha256=pin(bundle/'manifest.json', 1024**2)['sha256'])


def verify(bundle, expected):
    private_directory(bundle, os.geteuid())
    require(pin(bundle/'manifest.json', 1024**2)['sha256'] == expected, 'manifest digest mismatch')
    manifest = json.loads((bundle/'manifest.json').read_text())
    limits = dict(INPUTS, **{'support/'+name: 1024**2 for name in SUPPORT})
    if manifest.get('version') == 2:
        limits['preparation.json'] = 65536
    require(type(manifest.get('version')) is int and manifest['version'] in (1, 2)
            and set(manifest['files']) == set(limits),
            'unsupported manifest inventory')
    for name, limit in limits.items():
        path = bundle/name
        for parent in path.parents:
            if parent == bundle: break
            metadata = parent.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
                    and not metadata.st_mode & 0o022, 'unsafe input directory')
        metadata = path.lstat()
        require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022,
                'inputs must be owned and not writable by others')
        require(pin(path, limit) == manifest['files'][name], 'input identity mismatch: '+name)
    actual = {str(path.relative_to(bundle)) for path in (bundle/'support').rglob('*') if not path.is_dir()}
    require(actual == {'support/'+name for name in SUPPORT}, 'unexpected executable support files')
    return manifest


def confirm_reaper(log, pid, job_id):
    matches = [line for line in log.splitlines()
               if 'reaped orphaned VMM process from a prior daemon' in line
               and re.search(r'\bpid='+str(pid)+r'(?=\s|$)', line)
               and re.search(r'\bvm=job-'+re.escape(job_id)+r'(?=\s|$)', line)]
    require(len(matches) == 1, 'exact positive native-reaper confirmation required')
    return matches


def command(*args, check=True, timeout=100):
    return subprocess.run(args, check=check, timeout=timeout, capture_output=True, text=True)


def output(*args):
    return command(*args).stdout.strip()


def wait(predicate, seconds=60):
    deadline = time.monotonic()+seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError('bounded observation expired')
        time.sleep(.25)


def alive(pidfd):
    poll = select.poll()
    poll.register(pidfd, select.POLLIN)
    return not poll.poll(0)


class Cgroup:
    """Pin the exact fixture subtree, including unexpected descendants."""
    def __init__(self, unit):
        self.path = Path('/sys/fs/cgroup/system.slice')/unit
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.inode = os.fstat(self.fd).st_ino

    def read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            return os.read(fd, 4096).decode().strip()
        finally:
            os.close(fd)

    def write(self, name, value):
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            os.write(fd, value.encode())
        finally:
            os.close(fd)

    def populated(self):
        try:
            return 'populated 1' in self.read('cgroup.events')
        except FileNotFoundError:
            return False  # Removed pinned cgroup, never follow a replacement.

    def same(self):
        require(self.path.stat().st_ino == self.inode, 'fixture cgroup replaced')

    def close(self):
        os.close(self.fd)


def host_processes():
    """Stable identity inventory, without copying unrelated argv or credentials."""
    records = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try:
            exe = os.readlink(entry/'exe')
            if Path(exe).name not in ('husker', 'husker-factory', 'firecracker',
                                      'qemu-system-x86_64', 'cloud-hypervisor'): continue
            records.append(dict(pid=int(entry.name), exe=exe,
                                start=(entry/'stat').read_text().rsplit(')', 1)[1].split()[19],
                                cgroup=(entry/'cgroup').read_text()))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(records, key=lambda item: item['pid'])


class Fixture:
    def __init__(self, bundle, manifest):
        self.bundle, self.manifest = bundle, manifest
        self.root = bundle/'control'
        private_directory(self.root, 0)
        self.evidence = self.root/'evidence'
        self.plan = json.loads((self.root/'plan.json').read_text())
        nonce = self.plan['nonce']
        require(re.fullmatch('[0-9a-f]{12}', nonce), 'invalid fixture identity')
        self.unit = 'husker-reaper-'+nonce+'.service'
        self.watch_unit = 'husker-reaper-watch-'+nonce+'.service'
        self.controller_unit = 'husker-reaper-control-'+nonce+'.service'
        self.bridge = 'hr'+nonce
        self.url = 'http://127.0.0.1:'+str(self.plan['port'])
        self.cg = None
        self.vmfd = None
        self.started = False
        self.watch_started = False

    def save(self, name, value):
        write_once(self.evidence/name, value)

    def prop(self, name):
        return output('systemctl', 'show', self.unit, '-p', name, '--value')

    def listener_owned(self):
        pid = self.prop('MainPID')
        lines = output('ss', '-Hltnp', 'sport = :'+str(self.plan['port'])).splitlines()
        return (pid != '0' and len(lines) == 1 and '127.0.0.1:'+str(self.plan['port']) in lines[0]
                and re.findall(r'pid=(\d+)', lines[0]) == [pid])

    def request(self, method, path, body=None):
        require(self.listener_owned(), 'private listener ownership unconfirmed')
        request = Request(self.url+path, method=method,
                          data=None if body is None else json.dumps(body).encode(),
                          headers={'Authorization': 'Bearer '+(self.root/'token').read_text(),
                                   'Content-Type': 'application/json', 'User-Agent': 'husker-reaper-check'})
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=120) as response:
            raw = response.read(1024**2+1)
            require(len(raw) <= 1024**2, 'oversized response')
            return json.loads(raw)

    def health(self):
        try:
            self.request('GET', '/v1/health')
            return True
        except (OSError, ValueError, HTTPError, subprocess.SubprocessError):
            return False

    def audit(self):
        with sqlite3.connect('file:'+str(self.root/'state/husker.db')+'?mode=ro', uri=True) as db:
            db.row_factory = sqlite3.Row
            jobs = [dict(row) for row in db.execute(
                'SELECT id,session_id,vm_id,state,vm_destroyed,cleanup_pending FROM execution_jobs')]
            counts = {table: db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
                      for table in ('vms', 'host_resource_leases')}
        files = {name: sorted(str(p.relative_to(self.root/name)) for p in (self.root/name).rglob('*'))
                 for name in ('data/vms', 'data/job-inputs', 'state/run')}
        return dict(jobs=jobs, counts=counts, files=files)

    def vm_identity(self, pid, generation):
        directory = Path('/proc')/str(pid)
        argv = (directory/'cmdline').read_bytes().split(b'\0')
        expected = os.fsencode(str(self.root/'state/run'/(generation+'.sock')))
        require(any(a == b'--api-sock' and b == expected for a, b in zip(argv, argv[1:])),
                'exact VMM socket identity required')
        require((directory/'cgroup').read_text() == '0::/system.slice/'+self.unit+'/vm-'+generation+'\n',
                'VMM outside private cgroup')
        require((directory/'exe').resolve() == self.bundle/'bin/firecracker', 'unexpected VMM executable')
        require(any('kvm' in os.readlink(fd).lower() for fd in (directory/'fd').iterdir()),
                'real KVM descriptor required')

    def harness(self, mode):
        require(self.listener_owned(), 'fixture ingress changed')
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(self.bundle/'support'),
                   HUSKER_RUN_FACTORY_RESTART_E2E='1',
                   HUSKER_FACTORY_RESTART_E2E_TOKEN=(self.root/'token').read_text())
        for name in list(env):
            if name.lower().endswith('_proxy'): env.pop(name)
        env['NO_PROXY'] = '127.0.0.1,localhost'
        args = [sys.executable, str(self.bundle/'support/scripts/ci/factory_restart_e2e.py'), mode,
                '--url', self.url, '--journal', str(self.evidence/'job.sqlite'),
                '--key', 'native-reaper-'+self.plan['nonce'], '--image', str(self.evidence/'image.json'),
                '--source', str(self.bundle/'inputs/source.tar'),
                '--acceptance', str(self.bundle/'inputs/acceptance.tar'), '--probe-digest',
                'sha256:'+self.manifest['files']['bin/factory-lifecycle-probe']['sha256']]
        with (self.evidence/(mode+'.json')).open('x') as stdout, (self.evidence/(mode+'.stderr')).open('x') as stderr:
            result = subprocess.run(args, env=env, stdout=stdout, stderr=stderr, timeout=330)
        require(result.returncode == 0, 'job '+mode+' unresolved; never submit this bundle again')
        return json.loads((self.evidence/(mode+'.json')).read_text())

    def start_unit(self, unit, args, properties):
        logfile = self.evidence/('watchdog.log' if unit == self.watch_unit else 'daemon.log')
        return command('systemd-run', '--unit='+unit, '--property=StandardOutput=append:'+str(logfile),
                       '--property=StandardError=append:'+str(logfile),
                       *['--property='+p for p in properties], *args)

    def watchdog(self):
        require(self.watch_unit in Path('/proc/self/cgroup').read_text(), 'wrong watchdog unit')
        group = Cgroup(self.unit)
        try:
            deadline = time.monotonic()+750
            self.save('watchdog-armed.json', dict(inode=group.inode, deadline=deadline))
            while time.monotonic() < deadline:
                if (self.evidence/'controller-complete.json').exists(): return
                time.sleep(.25)
            try:
                self.save('watchdog-triggered.json', dict(inode=group.inode))
            finally:
                group.write('cgroup.kill', '1')
                wait(lambda: not group.populated(), 15)
        finally:
            group.close()

    def guard(self, margin=0):
        require(not (self.evidence/'watchdog-triggered.json').exists(), 'watchdog fired; no native proof')
        guard = json.loads((self.evidence/'watchdog-armed.json').read_text())
        require(time.monotonic()+margin < guard['deadline'], 'insufficient watchdog time remaining')
        require(output('systemctl', 'show', self.watch_unit, '-p', 'ActiveState', '--value') == 'active',
                'watchdog not active')

    def exercise(self):
        import fcntl
        require(self.controller_unit in Path('/proc/self/cgroup').read_text(), 'wrong controller unit')
        lock = os.fdopen(os.open('/run/lock/husker-native-reaper.lock',
                         os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), 'w')
        metadata = os.fstat(lock.fileno())
        require(metadata.st_uid == 0 and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and not metadata.st_mode & 0o077, 'unsafe host lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.preflight()
            self.perform()
        finally:
            try:
                self.cleanup()
            finally:
                if self.vmfd is not None: os.close(self.vmfd)
                if self.cg is not None: self.cg.close()
                lock.close()

    def preflight(self):
        require(shutil.disk_usage(self.bundle).free >= 64*1024**3, '64 GiB free required')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', self.plan['port']))
        for unit in (self.unit, self.watch_unit):
            require(output('systemctl', 'show', unit, '-p', 'LoadState', '--value') == 'not-found',
                    'private unit already exists')
        require(command('ip', 'link', 'show', self.bridge, check=False).returncode != 0, 'bridge exists')
        subnet = ipaddress.ip_network(self.plan['subnet'])
        routes = json.loads(output('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
        require(all(not subnet.overlaps(ipaddress.ip_network(row['dst'], strict=False))
                    for row in routes if row.get('dst') not in (None, 'default')), 'subnet overlaps host route')
        self.save('host-before.json', dict(processes=host_processes(), firewall=output('nft', '-s', 'list', 'ruleset')))
        # Read-only checks of active Husker allocators, without retaining argv/config/token data.
        for process in host_processes():
            if Path(process['exe']).name not in ('husker', 'husker-factory'): continue
            databases = {fd.resolve() for fd in (Path('/proc')/str(process['pid'])/'fd').iterdir()
                         if fd.resolve().name == 'husker.db'}
            for database in databases:
                with sqlite3.connect('file:'+str(database)+'?mode=ro', uri=True) as db:
                    require(db.execute('SELECT next_cid FROM cid_allocator WHERE id=1').fetchone()[0]
                            < self.plan['cid']-1024, 'CID allocator too close to private range')
                    for table in ('vms', 'host_resource_leases'):
                        require(db.execute('SELECT COUNT(*) FROM '+table+' WHERE vsock_cid BETWEEN ? AND ?',
                                           (self.plan['cid'], self.plan['cid']+16)).fetchone()[0] == 0,
                                'private CID range occupied')
        # Validate frozen payload before any POST, through the same parser as the job harness.
        sys.path.insert(0, str(self.bundle/'support/scripts/ci'))
        import factory_lifecycle_e2e as lifecycle
        lifecycle.validate_inputs((self.bundle/'inputs/source.tar').read_bytes(),
                                  (self.bundle/'inputs/acceptance.tar').read_bytes(),
                                  'sha256:'+self.manifest['files']['bin/factory-lifecycle-probe']['sha256'])

    def perform(self):
        token = secrets.token_hex(32)
        (self.root/'token').write_text(token)
        config = dict(data_dir=str(self.root/'data'), state_dir=str(self.root/'state'),
                      default_kernel=str(self.bundle/'prepared/vmlinux'),
                      default_rootfs=str(self.bundle/'prepared/rootfs.ext4'),
                      firecracker_bin=str(self.bundle/'bin/firecracker'), bridge_name=self.bridge,
                      bridge_subnet=self.plan['subnet'], cid_base=self.plan['cid'], api_token=token,
                      guest_isolation=True, resource_limits=True, cpu_limit=True, memory_overhead_mib=512,
                      max_vms=1, service_reconcile_enabled=False, factory_jobs_enabled=True,
                      exec_allowlist=['/workspace/factory-lifecycle-probe'], exec_timeout_max_secs=1200,
                      api_max_request_bytes=100663296)
        def literal(value):
            return json.dumps(value)
        lines = [key+' = '+literal(value) for key, value in config.items()]
        lines += ['[factory_resource_budget]', 'max_jobs = 1', 'max_vcpus = 1', 'max_memory_mib = 1024',
                  'memory_overhead_mib = 512', 'max_root_disk_bytes = 8589934592',
                  'max_boot_storage_bytes = 21474836480', 'min_free_storage_bytes = 17179869184']
        (self.root/'config.toml').write_text('\n'.join(lines)+'\n')
        # No --collect: failed unit must remain available while its VMM survives.
        self.started = True  # Cleanup also covers an ambiguous systemd-run acknowledgement.
        self.start_unit(self.unit, [str(self.bundle/'bin/husker'), '--config', str(self.root/'config.toml'),
                                   'daemon', '--listen', '127.0.0.1:'+str(self.plan['port'])],
                        ['Delegate=yes', 'Restart=no', 'KillMode=process', 'TimeoutStopSec=90s',
                         'RuntimeMaxSec=900s', 'MemoryMax=2G', 'CPUQuota=200%'])
        self.cg = Cgroup(self.unit)
        self.watch_started = True
        self.start_unit(self.watch_unit, [sys.executable, '-B', str(self.bundle/'support/scripts/ci/factory_native_reaper_e2e.py'),
                        '_watchdog', '--bundle', str(self.bundle), '--sha256', self.plan['manifest_sha256']],
                        ['KillMode=control-group', 'RuntimeMaxSec=900s', 'MemoryMax=128M', 'CPUQuota=10%'])
        wait(lambda: (self.evidence/'watchdog-armed.json').exists(), 20)
        require(json.loads((self.evidence/'watchdog-armed.json').read_text())['inode'] == self.cg.inode,
                'watchdog did not pin the original unit')
        wait(self.health)
        image = self.request('POST', '/v1/images', dict(name='native-reaper-'+self.plan['nonce'],
                             source_path=str(self.bundle/'prepared/rootfs.ext4'), format='ext4', kind='rootfs'))
        digest = 'sha256:'+self.manifest['files']['prepared/rootfs.ext4']['sha256']
        require(image['content_digest'] == digest, 'imported image identity mismatch')
        self.save('image.json', dict(catalog_id=image['id'], rootfs_digest=digest,
                  kernel_digest='sha256:'+self.manifest['files']['prepared/vmlinux']['sha256'], initrd_digest=None))
        armed = self.harness('arm')
        before = self.audit()
        self.save('before-crash.json', before)
        require(len(before['jobs']) == 1 and before['jobs'][0]['state'] == 'running', 'one running job required')
        job = before['jobs'][0]
        generation = job['vm_id']
        require(generation == armed['identity']['vm_id'], 'generation mismatch')
        receipt = json.loads((self.root/'state/run'/(generation+'.recovery.json')).read_text())
        pid = receipt['pid']
        self.vmfd = os.pidfd_open(pid)
        self.vm_identity(pid, generation)
        require(receipt['id'] == generation and receipt['name'] == 'job-'+job['id'], 'receipt mismatch')
        require(alive(self.vmfd), 'VMM already exited')
        main = int(self.prop('MainPID'))
        mainfd = os.pidfd_open(main)
        invocation = self.prop('InvocationID')
        try:
            require((Path('/proc')/str(main)/'exe').resolve() == self.bundle/'bin/husker', 'wrong daemon')
            require(int(self.prop('MainPID')) == main and self.prop('KillMode') == 'process', 'unit changed')
            self.guard(180)
            self.save('crash-intent.json', dict(main_pid=main, vm_pid=pid, generation=generation, job_id=job['id']))
            signal.pidfd_send_signal(mainfd, signal.SIGKILL)
            wait(lambda: not alive(mainfd), 10)
            self.save('crash-injected.json', dict(daemon_pidfd_exited=True))
        finally:
            os.close(mainfd)
        samples = []
        for _ in range(14):
            require(alive(self.vmfd), 'VM did not survive daemon-only crash')
            self.vm_identity(pid, generation)
            samples.append(time.monotonic())
            time.sleep(.25)
        require(samples[-1]-samples[0] >= 3, 'survival interval too short')
        self.save('surviving-vmm.json', dict(vm_pid=pid, seconds=samples[-1]-samples[0], samples=samples))
        # systemd cannot attach the replacement main to a populated delegated parent.
        # Disable only child controllers, retaining the unit's own hard resource caps.
        self.cg.same()
        vm_inode = (self.cg.path/('vm-'+generation)).stat().st_ino
        limits = {name: self.cg.read(name) for name in ('memory.max', 'cpu.max')}
        require(limits == {'memory.max': str(2*1024**3), 'cpu.max': '200000 100000'}, 'unit caps changed')
        self.cg.write('cgroup.subtree_control', '-memory -cpu')
        require(limits == {name: self.cg.read(name) for name in limits}, 'unit caps changed during accommodation')
        require((self.cg.path/('vm-'+generation)).stat().st_ino == vm_inode, 'VM cgroup replaced')
        self.save('delegation-adjustment.json', dict(unit_caps=limits, vm_cgroup_inode=vm_inode,
                                                    unit_cgroup_inode=self.cg.inode))
        self.guard(180)
        offset = (self.evidence/'daemon.log').stat().st_size
        self.save('restart-intent.json', dict(log_offset=offset, vm_pid=pid, vm_alive=True))
        require(alive(self.vmfd), 'VMM exited before native startup reaper')
        command('systemctl', 'start', self.unit)
        wait(self.health)
        self.cg.same()
        self.guard()
        require(self.prop('InvocationID') != invocation and int(self.prop('MainPID')) != main, 'no replacement daemon')
        wait(lambda: not alive(self.vmfd), 5)
        native = (self.evidence/'daemon.log').read_bytes()[offset:].decode()
        matched = confirm_reaper(native, pid, job['id'])
        self.save('native-reaper-confirmed.json', dict(vm_pid=pid, matched_log=matched, original_pidfd_exited=True))
        wait(lambda: self.request('GET', '/v1/jobs/'+job['id'])['job']['cleanup_pending'] is False, 30)
        inspected = self.harness('inspect')
        after = self.audit()
        self.save('after-restart.json', after)
        require(inspected['status'] == 'passed' and inspected['identity_preserved']
                and inspected['journaled_output_preserved'], 'job identity/output not preserved')
        require(len(after['jobs']) == 1 and after['jobs'][0] == dict(job, state='unknown',
                vm_destroyed=1, cleanup_pending=0), 'job outcome or identity changed')
        require(after['counts'] == {'vms': 0, 'host_resource_leases': 0}
                and not any(after['files'].values()), 'owned VM resources remain')
        methods = re.findall(r'method=([A-Z]+) path=([^ ]+)', (self.evidence/'daemon.log').read_text())
        require(sum(m == 'POST' and p == '/v1/jobs' for m, p in methods) == 1, 'not exactly one submission')
        post = (self.evidence/'daemon.log').read_bytes()[offset:].decode()
        require(set(re.findall(r'method=([A-Z]+)', post)) == {'GET'}, 'post-restart mutation detected')
        self.guard()
        self.save('recovery.json', dict(status='passed', native_orphan_reaper_proven=True,
                  live_vm_survived_daemon=True, identity_and_output_preserved=True, terminal_unknown=True,
                  cleanup_pending=False, one_job=True, watchdog_triggered=False, promotion_proven=False))

    def cleanup(self):
        if not self.started: return
        command('systemctl', 'stop', self.unit, check=False)
        if self.cg is None:
            path = Path('/sys/fs/cgroup/system.slice')/self.unit
            if path.exists(): self.cg = Cgroup(self.unit)
        if self.cg is not None and self.cg.populated():
            self.cg.write('cgroup.kill', '1')
            self.save('emergency-cleanup.json', dict(inode=self.cg.inode))
        # Never disarm the watchdog while any descendant remains.
        if self.cg is not None:
            wait(lambda: not self.cg.populated(), 15)
            if self.cg.path.exists(): self.cg.same()
        self.save('controller-complete.json', dict(owned_cgroup_empty=True))
        if self.watch_started: command('systemctl', 'stop', self.watch_unit, check=False)
        baseline = json.loads((self.evidence/'host-before.json').read_text())
        observed = dict(no_populated_cgroup=self.cg is None or not self.cg.populated(),
                        bridge_removed=command('ip', 'link', 'show', self.bridge, check=False).returncode != 0,
                        firewall_unchanged=output('nft', '-s', 'list', 'ruleset') == baseline['firewall'],
                        other_processes_unchanged=host_processes() == baseline['processes'],
                        daemon_stopped=self.prop('MainPID') == '0',
                        watchdog_stopped=not self.watch_started or output('systemctl', 'show', self.watch_unit,
                                           '-p', 'MainPID', '--value') == '0',
                        watchdog_never_fired=not (self.evidence/'watchdog-triggered.json').exists(),
                        emergency_cleanup_unused=not (self.evidence/'emergency-cleanup.json').exists())
        self.save('final-audit.json', observed)
        require(all(observed.values()), 'final host audit failed; inspect retained evidence')
        if (self.evidence/'recovery.json').exists():
            self.save('result.json', dict(status='passed', activated=True,
                      scope='linux-daemon-only-native-reaper-v1', manifest_sha256=self.plan['manifest_sha256'],
                      recovery=json.loads((self.evidence/'recovery.json').read_text()), final_audit=observed))
        command('systemctl', 'reset-failed', self.unit, check=False)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def launch(bundle, manifest, args):
    require(sys.platform == 'linux' and os.geteuid() == 0 and sys.version_info >= (3, 11),
            'Linux root with Python 3.11+ required')
    require(Path('/sys/fs/cgroup/cgroup.controllers').exists() and Path('/dev/kvm').exists(),
            'systemd/cgroup v2 and KVM required')
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd support required')
    subnet = ipaddress.ip_network(args.subnet)
    require(subnet.version == 4 and subnet.is_private and subnet.prefixlen == 24
            and not subnet.is_loopback and not subnet.is_link_local, 'private IPv4 /24 subnet required')
    require(1024 <= args.port <= 65535 and 30000 <= args.cid <= 60000, 'invalid port or CID range')
    control = bundle/'control'
    control.mkdir(mode=0o700)  # Exclusive: never resubmit after a partial/uncertain run.
    (control/'evidence').mkdir(mode=0o700)
    nonce = secrets.token_hex(6)
    write_once(control/'plan.json', dict(nonce=nonce, port=args.port, subnet=str(subnet),
                                       cid=args.cid, manifest_sha256=args.sha256))
    controller = 'husker-reaper-control-'+nonce
    script = bundle/'support/scripts/ci/factory_native_reaper_e2e.py'
    result = command('systemd-run', '--wait', '--unit='+controller,
                     '--property=RuntimeMaxSec=1100s', '--property=MemoryMax=512M', '--property=CPUQuota=100%',
                     sys.executable, '-B', str(script), '_controller', '--bundle', str(bundle), '--sha256', args.sha256,
                     check=False, timeout=1150)
    require(result.returncode == 0 and (control/'evidence/result.json').is_file(),
            'regression check failed; inspect '+str(control/'evidence')+' and journalctl -u '+controller)
    return json.loads((control/'evidence/result.json').read_text())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare', 'verify', 'run', '_controller', '_watchdog'])
    parser.add_argument('--bundle', type=str, required=True)
    parser.add_argument('--sha256')
    parser.add_argument('--port', type=int, default=19132)
    parser.add_argument('--subnet', default='172.30.81.0/24')
    parser.add_argument('--cid', type=int, default=34000)
    args = parser.parse_args()
    if args.mode == 'run' and os.environ.get('HUSKER_RUN_FACTORY_NATIVE_REAPER_E2E') != '1':
        print(json.dumps(dict(status='skipped', activated=False,
                             reason='HUSKER_RUN_FACTORY_NATIVE_REAPER_E2E=1 required')))
        return
    if args.mode == 'prepare':
        print(json.dumps(prepare(Path(args.bundle))))
        return
    bundle = Path(args.bundle)
    if args.mode in ('_controller', '_watchdog'):
        require(os.geteuid() == 0 and sys.platform == 'linux', 'private root unit required')
        private_directory(bundle, 0)
        require(pin(bundle/'manifest.json', 1024**2)['sha256'] == args.sha256, 'manifest changed')
        fixture = Fixture(bundle, json.loads((bundle/'manifest.json').read_text()))
        require(fixture.plan['manifest_sha256'] == args.sha256, 'execution manifest changed')
        if args.mode == '_watchdog': fixture.watchdog()
        else: fixture.exercise()
        return
    manifest = verify(bundle, args.sha256)
    if args.mode == 'verify':
        print(json.dumps(dict(status='verified', activated=False)))
        return
    print(json.dumps(launch(bundle, manifest, args)))


if __name__ == '__main__':
    os.umask(0o077)
    sys.dont_write_bytecode = True
    main()
