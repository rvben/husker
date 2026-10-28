#!/usr/bin/env python3
"""Verify an immutable pilot bundle; activate only after explicit user approval.

Activation starts one isolated loopback daemon, imports one pinned image, runs
one offline boundary subset, and stops its owned daemon. No service installation,
model invocation, image download, SSH operation or unrelated process signalling.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import sys
import subprocess
import time
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError

REQUIRED_FILES = {
    'bin/husker', 'prepared/Image', 'prepared/rootfs.ext4', 'prepared/preparation.json',
    'python/husker/__init__.py', 'python/husker/jobs.py',
    'python/examples/factory_checks_v1.py', 'python/scripts/ci/factory_boundary_e2e.py',
    'python/scripts/ci/factory_mini_pilot.py', 'inputs/source.tar', 'inputs/acceptance.tar',
    'source-pins.json',
}
WORKER_FILES = {'bin/husker-vz-worker', 'build-receipt.json'}


def worker_plan(manifest):
    if manifest.get('version') != 2:
        return None
    worker = manifest.get('worker')
    if (not isinstance(worker, dict)
            or set(worker) != {'protocol_version', 'lifetime_secs', 'state_dir', 'workspace_rust_source_sha256'}
            or type(worker['protocol_version']) is not int or worker['protocol_version'] != 1
            or type(worker['lifetime_secs']) is not int or worker['lifetime_secs'] != 600
            or not isinstance(worker['state_dir'], str)
            or not re.fullmatch(r'/private/var/tmp/hvz-[0-9a-f]{12}', worker['state_dir'])
            or not isinstance(worker['workspace_rust_source_sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', worker['workspace_rust_source_sha256'])):
        raise ValueError('invalid reviewed VZ worker pilot plan')
    socket_path = Path(worker['state_dir']) / 'runtime' / ('vz-worker-' + '0'*36) / 'control.sock'
    if len(os.fsencode(socket_path)) >= 104:
        raise ValueError('worker state path exceeds macOS socket limit')
    return worker


def verify_worker_receipt(bundle, manifest):
    worker = worker_plan(manifest)
    if worker is None:
        return
    fd = os.open(bundle / 'build-receipt.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(64*1024 + 1)
    if (len(raw) > 64*1024 or ('sha256:' + hashlib.sha256(raw).hexdigest(), len(raw))
            != (manifest['files']['build-receipt.json']['digest'], manifest['files']['build-receipt.json']['size_bytes'])):
        raise ValueError('worker build receipt changed or exceeded bound')
    receipt = json.loads(raw)
    if (not isinstance(receipt, dict) or type(receipt.get('version')) is not int
            or receipt['version'] != 1 or receipt.get('target') != 'aarch64-apple-darwin'
            or receipt.get('workspace_rust_source_sha256') != worker['workspace_rust_source_sha256']
            or receipt.get('daemon_version') != 'husker 0.4.52'
            or receipt.get('activated') is not False
            or receipt.get('promotion_eligible') is not False
            or receipt.get('frozen_source_verified_after_build') is not True
            or receipt.get('embedded_agent_bytes_present') is not True):
        raise ValueError('worker build receipt is not the reviewed frozen pair')
    if not isinstance(receipt.get('binaries'), dict):
        raise ValueError('worker receipt binary inventory required')
    for name in ['husker', 'husker-vz-worker']:
        binary = receipt['binaries'].get(name, {})
        pin = manifest['files']['bin/' + name]
        if (not isinstance(binary, dict) or type(binary.get('size_bytes')) is not int
                or binary.get('sha256') != pin['digest'].removeprefix('sha256:')
                or binary.get('size_bytes') != pin['size_bytes']
                or binary.get('signature_verified') is not True
                or binary.get('virtualization_entitlement') is not True
                or binary.get('source_stamp_bytes_present') is not True
                or not 0 < pin['size_bytes'] <= 64*1024*1024):
            raise ValueError('worker receipt does not bind reviewed binary pins')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def digest_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
            raise ValueError('bundle input must be a bounded independent regular file')
        digest = hashlib.sha256()
        size = 0
        while True:
            data = stream.read(2 * 1024 * 1024)
            if not data:
                break
            size += len(data)
            if size > limit:
                raise ValueError('bundle input grew beyond bound')
            digest.update(data)
        if size != metadata.st_size:
            raise ValueError('bundle input changed size')
        return 'sha256:' + digest.hexdigest(), size


def verify(bundle, expected):
    metadata = bundle.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077):
        raise ValueError('bundle directory must be private and owned, without symlinks')
    fd = os.open(bundle / 'manifest.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size > 1024 * 1024):
            raise ValueError('manifest must be a bounded independent regular file')
        raw = stream.read(1024 * 1024 + 1)
        if len(raw) != metadata.st_size:
            raise ValueError('manifest changed or exceeded bound')
    actual = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError('manifest digest differs from reviewed bundle')
    manifest = json.loads(raw)
    if (type(manifest.get('version')) is not int or manifest['version'] not in (1, 2)
            or manifest.get('target') != 'mac-mini-m6'):
        raise ValueError('unsupported pilot manifest')
    files = manifest['files']
    required = REQUIRED_FILES | (WORKER_FILES if manifest['version'] == 2 else set())
    if (not isinstance(files, dict) or not 1 <= len(files) <= 100
            or not required.issubset(files)):
        raise ValueError('invalid bundle inventory')
    for relative, pin in files.items():
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or str(path) != relative:
            raise ValueError('unsafe inventory path')
        for parent in path.parents:
            if parent != Path('.') and not stat.S_ISDIR((bundle / parent).lstat().st_mode):
                raise ValueError('inventory parent is not an independent directory')
        if (not isinstance(pin['size_bytes'], int) or isinstance(pin['size_bytes'], bool)
                or not 0 <= pin['size_bytes'] <= 8 * 1024**3):
            raise ValueError('invalid bundle size bound')
        if digest_file(bundle / path, pin['size_bytes']) != (pin['digest'], pin['size_bytes']):
            raise ValueError('bundle input identity mismatch: ' + relative)
    if manifest['version'] == 1 and 'worker' in manifest:
        raise ValueError('worker routing requires a separately reviewed v2 manifest')
    verify_worker_receipt(bundle, manifest)
    return manifest


def host_inventory(bundle):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise ValueError('pilot activation requires Apple Silicon macOS')
    def sysctl(name):
        return subprocess.check_output(['/usr/sbin/sysctl', '-n', name], timeout=5, text=True).strip()
    inventory = dict(cpu=sysctl('machdep.cpu.brand_string'), memory_bytes=int(sysctl('hw.memsize')),
                     cpu_count=int(sysctl('hw.ncpu')), os_version=platform.mac_ver()[0],
                     free_bytes=shutil.disk_usage(bundle).free)
    if inventory['cpu'] != 'Apple M6':
        raise ValueError('intended Apple M6 host required; do not use the M4 alias')
    if inventory['memory_bytes'] < 16 * 1024**3 or inventory['cpu_count'] < 4:
        raise ValueError('pilot host capacity floor not met')
    if inventory['free_bytes'] < 64 * 1024**3:
        raise ValueError('pilot requires at least 64 GiB free after staging')
    return inventory


def request(url, token, method='GET', body=None, timeout=10):
    data = None if body is None else json.dumps(body).encode()
    req = Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
        'User-Agent': 'husker-factory-pilot',
    })
    with build_opener(ProxyHandler({}), NoRedirect()).open(req, timeout=timeout) as response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('oversized pilot response')
        return json.loads(raw)


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def configuration(bundle, manifest, control, token):
    worker = worker_plan(manifest)
    def quoted(path):
        return json.dumps(str(path))
    lines = [
        'data_dir = ' + quoted(control / 'data'),
        'state_dir = ' + quoted(worker['state_dir'] if worker else control / 'state'),
        'default_kernel = ' + quoted(bundle / 'prepared/Image'),
        'default_rootfs = ' + quoted(bundle / 'prepared/rootfs.ext4'),
        'api_token = ' + json.dumps(token),
        'max_vms = 1', 'service_reconcile_enabled = false',
        'factory_jobs_enabled = true',
        'exec_allowlist = ["/workspace/factory-boundary-probe"]',
        'exec_env_allowlist = []', 'exec_timeout_max_secs = 30',
        '[factory_resource_budget]', 'max_jobs = 1', 'max_vcpus = 1',
        'max_memory_mib = 768', 'memory_overhead_mib = 256',
        'max_root_disk_bytes = 8589934592', 'max_boot_storage_bytes = 21474836480',
        'min_free_storage_bytes = 17179869184', '',
    ]
    if worker:
        lines.extend(['[apple_vz_worker]',
            'executable = ' + quoted(bundle / 'bin/husker-vz-worker'),
            'sha256 = ' + json.dumps(manifest['files']['bin/husker-vz-worker']['digest'].removeprefix('sha256:')),
            'protocol_version = 1', 'lifetime_secs = 600', ''])
    return '\n'.join(lines)


def activate(bundle, manifest, port):
    if os.environ.get('HUSKER_RUN_FACTORY_MINI_PILOT') != '1':
        raise ValueError('explicit approval plus HUSKER_RUN_FACTORY_MINI_PILOT=1 required')
    inventory = host_inventory(bundle)
    worker = worker_plan(manifest)
    if worker is not None and os.path.lexists(worker['state_dir']):
        raise ValueError('reviewed worker state path already exists; no adoption or replay')
    # Fail before creating state if the reviewed loopback port is occupied.
    with socket.socket() as test_socket:
        test_socket.bind(('127.0.0.1', port))
    control = bundle / 'pilot-control'
    control.mkdir(mode=0o700)  # Existing state is never reused or silently rerun.
    if worker is not None:
        Path(worker['state_dir']).mkdir(mode=0o700)  # Exclusive; retain on any uncertainty.
    token = secrets.token_hex(32)
    config = control / 'config.toml'
    write_private(config, configuration(bundle, manifest, control, token))
    write_private(control / 'host.json', json.dumps(inventory, indent=2) + '\n')
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C',
                   'RUST_LOG': 'warn', 'PYTHONDONTWRITEBYTECODE': '1'}
    url = 'http://127.0.0.1:' + str(port)
    daemon = None
    outcome = {'promotion_proven': False, 'phase': 'startup',
               'pilot_version': manifest.get('version', 1),
               'worker_state_dir': worker['state_dir'] if worker else None,
               'manifest_digest': digest_file(bundle / 'manifest.json', 1024*1024)[0]}
    try:
        with open(control / 'daemon.log', 'xb') as logs:
            os.chmod(control / 'daemon.log', 0o600)
            daemon = subprocess.Popen([str(bundle / 'bin/husker'), '--config', str(config),
                'daemon', '--listen', '127.0.0.1:' + str(port)], env=environment,
                stdin=subprocess.DEVNULL, stdout=logs, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while True:
                if daemon.poll() is not None:
                    raise RuntimeError('isolated daemon exited during startup; preserve logs')
                try:
                    request(url + '/v1/health', token)
                    try:
                        request(url + '/v1/jobs/00000000-0000-0000-0000-000000000000', token)
                    except HTTPError as error:
                        raw = error.read(1024 * 1024 + 1)
                        if (error.code != 404 or len(raw) > 1024 * 1024
                                or json.loads(raw).get('kind') != 'job_not_found'):
                            raise RuntimeError('isolated authenticated daemon identity not established')
                    else:
                        raise RuntimeError('unexpected existing receipt in fresh pilot state')
                    if daemon.poll() is not None:
                        raise RuntimeError('owned daemon exited before authenticated readiness')
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('isolated daemon readiness not observed; preserve state')
                    time.sleep(0.2)
            # Single POST. A lost import acknowledgement stops this pilot.
            outcome['phase'] = 'image-import'
            image = request(url + '/v1/images', token, 'POST', dict(name='factory-pilot-v' + str(manifest.get('version', 1)),
                source_path=str(bundle / 'prepared/rootfs.ext4'), format='ext4', kind='rootfs'), timeout=180)
            if image['content_digest'] != manifest['files']['prepared/rootfs.ext4']['digest']:
                raise ValueError('catalog image digest mismatch')
            write_private(control / 'image.json', json.dumps(dict(catalog_id=image['id'],
                rootfs_digest=image['content_digest'],
                kernel_digest=manifest['files']['prepared/Image']['digest'], initrd_digest=None)) + '\n')
            probe_environment = dict(environment, PYTHONPATH=str(bundle / 'python'),
                HUSKER_RUN_FACTORY_BOUNDARY_E2E='1', HUSKER_FACTORY_BOUNDARY_E2E_TOKEN=token)
            with open(control / 'boundary.json', 'xb') as output:
                outcome['phase'] = 'boundary'
                os.chmod(control / 'boundary.json', 0o600)
                proof = subprocess.run([sys.executable, str(bundle / 'python/scripts/ci/factory_boundary_e2e.py'),
                    '--url', url, '--journal', str(control / 'boundary.sqlite'), '--key', 'pilot-boundary-v' + str(manifest.get('version', 1)),
                    '--image', str(control / 'image.json'), '--source', str(bundle / 'inputs/source.tar'),
                    '--acceptance', str(bundle / 'inputs/acceptance.tar'), '--disk-size-bytes', '8589934592',
                    '--probe-digest', manifest['probe_digest']], env=probe_environment,
                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=720)
            outcome['boundary_exit_code'] = proof.returncode
            if proof.returncode != 0:
                raise RuntimeError('boundary proof incomplete; retain journal and use GET-only inspection')
            digest_file(control / 'boundary.json', 1024 * 1024)
            result = json.loads((control / 'boundary.json').read_text())
            if (result.get('status') != 'passed' or result.get('scope') != 'offline-job-subset-v1'
                    or result.get('promotion_proven') is not False):
                raise ValueError('boundary result is not the expected passing subset')
            outcome['executionIdentity'] = result['executionIdentity']
            outcome['phase'] = 'boundary-finished'
    except BaseException as error:
        outcome['failure_type'] = type(error).__name__
        raise
    finally:
        if daemon is not None:
            if daemon.poll() is None:
                daemon.send_signal(signal.SIGTERM)
                try:
                    daemon.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    # No hard kill or resource deletion without a separate decision.
                    outcome['daemon_shutdown_pending'] = True
            outcome['daemon_exit_code'] = daemon.poll()
        outcome['resource_cleanup_proven'] = False  # Boundary receipt is narrower than host orphan proof.
        write_private(control / 'pilot-outcome.json', json.dumps(outcome, indent=2) + '\n')
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--manifest-digest', required=True)
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--port', type=int, default=19124)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('unprivileged TCP port required')
    bundle = args.bundle.absolute()
    manifest = verify(bundle, args.manifest_digest)
    result = activate(bundle, manifest, args.port) if args.activate else {
        'verified': True, 'activated': False, 'target': manifest['target'], 'promotion_proven': False,
    }
    print(json.dumps(result))


if __name__ == '__main__':
    main()
