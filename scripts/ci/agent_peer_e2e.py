#!/usr/bin/env python3
"""Opt-in guest-local control-channel proof on an isolated existing daemon.

Requires a prepared image with Python 3, an updated root-owned agent and a
kernel supporting vsock loopback. Creates only its own disposable offline VM;
never installs/restarts a daemon. An unavailable loopback is inconclusive.
"""
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from husker import Client, NotFound  # noqa: E402

# Runs inside the disposable guest. Probe only that guest's agent port, never
# host services or unrelated machines. Root launches this helper and immediately
# drops ALL supplementary groups and privilege before creating the socket.
GUEST_PROBE = r'''
import json, os, socket, struct, sys
os.setgroups([])
os.setgid(1000)
os.setuid(1000)
assert os.geteuid() == 1000 and os.getegid() == 1000 and not os.getgroups()
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect((1, 52))  # VMADDR_CID_LOCAL, own guest only
except OSError as e:
    print(json.dumps({"status": "inconclusive", "errno": e.errno,
                      "reason": "guest-local loopback did not connect"}))
    sys.exit(2)
frame = b'{"type":"Ping"}'
try:
    s.sendall(struct.pack(">I", len(frame)) + frame)
    data = s.recv(4)
    if data:
        raise RuntimeError("guest-local peer received an agent protocol response")
except (BrokenPipeError, ConnectionResetError):
    pass
except socket.timeout:
    raise RuntimeError("agent did not reject loopback within two seconds")
finally:
    s.close()
print(json.dumps({"status": "passed", "uid": os.geteuid(),
                  "cid": 1, "agent_port": 52, "peer_rejected": True}))
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    if os.environ.get("HUSKER_RUN_AGENT_PEER_E2E") != "1":
        print(json.dumps({"status": "skipped", "reason": "opt-in isolated test daemon required"}))
        return
    client = Client(os.environ["HUSKER_AGENT_PEER_E2E_URL"],
                    token=os.environ.get("HUSKER_AGENT_PEER_E2E_TOKEN"), timeout=30)
    image = os.environ["HUSKER_AGENT_PEER_E2E_IMAGE"]
    name = "agent-peer-proof-" + uuid4().hex[:12]
    vm = None
    generation = None
    started = time.monotonic()
    try:
        vm = client.create(name, image=image, network="none", vcpu_count=1,
                           mem_size_mib=512, disk_size=4 * 1024**3,
                           expires_after_secs=180, owner="agent-peer-proof/" + name)
        identity = vm.info()
        generation = identity["id"]
        vm.wait_ready(timeout=60)
        probe = vm.exec(["python3", "-c", GUEST_PROBE], timeout_secs=10)
        require(probe.exit_code == 0, "peer boundary failed or was inconclusive: " + probe.stdout + probe.stderr)
        result = json.loads(probe.stdout)
        require(result.get("status") == "passed" and result.get("peer_rejected"), "missing rejection evidence")
        # Host management must still work after rejecting the local connection.
        require(vm.exec(["true"], timeout_secs=5).exit_code == 0, "host control channel stopped working")
        result.update(vm_id=generation, image=image, host_control_still_works=True)
    finally:
        if vm is not None:
            try:
                current = vm.info()
            except NotFound:
                current = None
            if current is not None:
                require(generation is not None and current["id"] == generation,
                        "VM generation uncertain; hard expiration must perform cleanup")
                vm.destroy()
                try:
                    vm.info()
                except NotFound:
                    pass
                else:
                    raise RuntimeError("proof VM remains after destruction")
    result.update(cleanup_confirmed=True, elapsed_secs=round(time.monotonic() - started, 3))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
