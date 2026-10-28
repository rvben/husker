#!/usr/bin/env python3
"""Opt-in session replay proof on an existing, isolated test daemon.

Creates one offline disposable VM. Never installs or restarts a daemon. This
proves only session behavior, not factory job evidence retention or promotion.
"""
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from husker import Client, Conflict, NotFound  # noqa: E402


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def proof(client, vm, key):
    argv = ["sh", "-c", "printf x >> /tmp/replay-counter; printf accepted; sleep 1"]
    # Deliberately discard the first receipt, then reconnect with another client.
    vm.start(argv, timeout_secs=10, idempotency_key=key)
    replay = client.connect(vm.name).start(argv, timeout_secs=10, idempotency_key=key)
    require(replay.wait(timeout=20).state == "completed", "replayed command did not complete")
    require(vm.exec(["cat", "/tmp/replay-counter"]).stdout == "x", "submission executed more than once")
    require(len(vm.sessions()) == 1, "submission created duplicate sessions")
    events = replay.events()
    require(b"".join(e.data for e in events.events) == b"accepted", "retained evidence differs")
    require(not replay.events(after=events.next_cursor).events, "cursor reconnect replayed consumed output")
    try:
        vm.start(["true"], timeout_secs=10, idempotency_key=key)
    except Conflict:
        pass
    else:
        raise RuntimeError("changed specification was accepted")
    replay.remove()
    try:
        vm.start(argv, timeout_secs=10, idempotency_key=key)
    except Conflict:
        pass
    else:
        raise RuntimeError("removed key reexecuted")
    cancelled = vm.start(["sh", "-c", "sh -c 'sleep 3; touch /tmp/child-survived' & printf ready; wait"],
                         timeout_secs=15, idempotency_key=key + "/cancel")
    deadline = time.monotonic() + 10
    while not cancelled.events().events:
        require(time.monotonic() < deadline, "child workload did not start")
        time.sleep(0.05)
    cancelled.cancel()
    require(cancelled.wait(timeout=10).state == "cancelled", "cancellation was not confirmed")
    time.sleep(3.2)
    require(vm.exec(["test", "!", "-e", "/tmp/child-survived"]).exit_code == 0, "nested child survived")
    return dict(session_id=replay.id, replay=True, conflict=True, cursor=True,
                removal_receipt=True, process_group_cancellation=True)


def main():
    if os.environ.get("HUSKER_RUN_SESSION_REPLAY_E2E") != "1":
        print(json.dumps(dict(status="skipped", reason="opt-in isolated test daemon required")))
        return
    origin = os.environ["HUSKER_SESSION_REPLAY_E2E_URL"]
    image = os.environ["HUSKER_SESSION_REPLAY_E2E_IMAGE"]
    token = os.environ.get("HUSKER_SESSION_REPLAY_E2E_TOKEN")
    client = Client(origin, token=token, timeout=30)
    reconnected = Client(origin, token=token, timeout=30)
    name = "session-replay-proof-" + uuid4().hex[:12]
    vm = None
    generation = None
    created_at = time.monotonic()
    try:
        # Unsupported offline policy must fail here; no NAT/host fallback.
        vm = client.create(name, image=image, network="none", vcpu_count=1,
                           mem_size_mib=512, disk_size=4 * 1024**3,
                           expires_after_secs=180, owner="session-replay-proof/" + name)
        generation = vm.info()["id"]
        vm.wait_ready(timeout=60)
        result = proof(reconnected, vm, "proof/" + name)
        result.update(vm_id=generation, image=image)
    finally:
        if vm is not None:
            # Do not destroy a different VM generation which reused the name.
            try:
                current = vm.info()
            except NotFound:
                current = None
            if current is not None:
                require(generation is not None and current["id"] == generation,
                        "VM ownership cannot be reconciled; hard expiration must clean up")
                vm.destroy()
                try:
                    vm.info()
                except NotFound:
                    pass
                else:
                    raise RuntimeError("proof VM remains after destruction")

    print(json.dumps(dict(status="passed", scope="session-replay-only",
                          duration_ms=round((time.monotonic() - created_at) * 1000), **result)))


if __name__ == "__main__":
    main()
