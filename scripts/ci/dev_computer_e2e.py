#!/usr/bin/env python3
"""Opt-in proof against a test Firecracker daemon. Never installs/restarts it."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from husker import Client  # noqa: E402


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def fetch(vm, path):
    result = vm.exec(["python3", "-c", "import urllib.request,sys; "
        "print(urllib.request.urlopen('http://127.0.0.1:38973'+sys.argv[1], timeout=5).read().decode())", path], check=True)
    return json.loads(result.stdout)


def main():
    if os.environ.get("HUSKER_RUN_DEV_E2E") != "1":
        print("SKIPPED: set HUSKER_RUN_DEV_E2E=1, HUSKER_DEV_E2E_URL and HUSKER_DEV_E2E_IMAGE")
        return
    origin = os.environ["HUSKER_DEV_E2E_URL"]
    image = os.environ["HUSKER_DEV_E2E_IMAGE"]
    token = os.environ.get("HUSKER_DEV_E2E_TOKEN")
    binary = os.environ.get("HUSKER_DEV_E2E_BIN", "target/debug/husker")
    client = Client(origin, token=token, timeout=60)
    name = "dev-proof-" + uuid4().hex[:12]
    created = []
    preview = None
    started = time.monotonic()
    try:
        vm = client.create(name, image=image, vcpu_count=2, mem_size_mib=4096, disk_size=20 * 1024**3)
        created.append(vm)
        vm.exec(["sh", "-c", "set -eu; git --version; node --version; python3 --version; "
                 "RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo rustc --version; "
                 "codex --version; runuser -u developer -- claude --version"], check=True)
        # Docker must execute a real container, not merely answer `docker info`.
        vm.exec(["sh", "-c", "set -eu; if ! docker info >/dev/null 2>&1; then "
                 "nohup dockerd </dev/null >/tmp/husker-docker.log 2>&1 & fi; "
                 "n=0; until docker info >/dev/null 2>&1; do n=$((n+1)); "
                 "test $n -lt 60; sleep 1; done; docker run --rm hello-world"], timeout_secs=180, check=True)
        vm.write_file("/workspace/value.txt", b"parent")
        detached = vm.start(["sh", "-c", "printf before; sleep 1; printf after"])
        # A fresh client must be enough to recover status and retained output.
        reattached = Client(origin, token=token).connect(name).session(detached.id)
        require(reattached.wait(timeout=10).exit_code == 0, "reattached command failed")
        require(b"".join(e.data for e in reattached.iter_events() if e.stream == "stdout") == b"beforeafter", "reattached logs differ")
        cancelled = vm.start(["sleep", "60"], timeout_secs=120)
        cancelled.cancel()
        require(cancelled.wait(timeout=10).state == "cancelled", "command did not cancel")

        vm.write_file("/workspace/dev-proof.py", Path(__file__).with_name("dev_proof_guest.py").read_bytes())
        service = vm.start(["python3", "/workspace/dev-proof.py"], workdir="/workspace", timeout_secs=600)
        vm.wait_ready(["python3", "-c", "import urllib.request; "
            "urllib.request.urlopen('http://127.0.0.1:38973/health', timeout=1).read()"], timeout=30)
        before = fetch(vm, "/state")
        running = vm.start(["sh", "-c", "printf live; while ! test -f /workspace/continue-proof; "
                            "do sleep .1; done; printf resumed"], timeout_secs=180)
        vm.suspend()
        require(vm.info()["state"] == "suspended", "source must suspend")
        require(vm.info()["pid"] is None, "suspended source must release its VMM process")
        forks = int(os.environ.get("HUSKER_DEV_E2E_FORKS", "2"))
        require(1 <= forks <= 8, "HUSKER_DEV_E2E_FORKS must be between 1 and 8")
        # Leave a measurable wall-clock gap so restoration cannot accidentally
        # pass by returning the snapshot's original realtime clock.
        time.sleep(6)
        measurements, nonces, children = [], {before["entropy"]}, []
        for index in range(forks):
            fork_started = time.monotonic()
            child = vm.fork(name + "-child-" + str(index))
            created.append(child)
            children.append(child)
            fork_api_ms = (time.monotonic() - fork_started) * 1000
            state = fetch(child, "/state")
            first_response_ms = (time.monotonic() - fork_started) * 1000
            measurements.append(dict(fork_api_ms=round(fork_api_ms, 2),
                                     first_guest_response_ms=round(first_response_ms, 2)))
            require(state["pid"] == before["pid"], "warm process PID must survive fork")
            require(state["counter"] == before["counter"] + 1, "fork RAM must start at the captured counter")
            require(state["entropy"] not in nonces, "kernel random output must diverge across forks")
            nonces.add(state["entropy"])
            require(state["monotonic"] >= before["monotonic"], "monotonic clock moved backwards")
            require(abs(state["wall_time"] - time.time()) < 5, "restored guest wall clock drifted")
            timer = fetch(child, "/timer")
            require(0.09 <= timer["elapsed"] <= 5, "guest timer did not progress normally")
            child.write_file("/workspace/value.txt", ("child-" + str(index)).encode())
            require(vm.info()["state"] == "suspended", "fork/monitor must not wake source")
        # Alter one child's RAM again; siblings must still hold independent counters.
        require(fetch(children[0], "/state")["counter"] == before["counter"] + 2, "fork counter lost progress")
        vm.resume()
        require(vm.read_file("/workspace/value.txt") == b"parent", "fork disk writes must be isolated")
        for index, child in enumerate(children):
            require(child.read_file("/workspace/value.txt") == ("child-" + str(index)).encode(), "fork disks are shared")
        parent = fetch(vm, "/state")
        require(parent["pid"] == before["pid"] and parent["counter"] == before["counter"] + 1,
                "fork writes leaked into source RAM")
        require(parent["entropy"] not in nonces, "resumed source entropy duplicates a fork")
        require(abs(parent["wall_time"] - time.time()) < 5, "resumed source wall clock drifted")
        vm.write_file("/workspace/continue-proof", b"resume")
        require(running.wait(timeout=20).exit_code == 0, "resumed command failed")
        require(b"".join(e.data for e in running.iter_events() if e.stream == "stdout") == b"liveresumed", "resumed logs differ")

        with tempfile.TemporaryDirectory(prefix="husker-dev-proof-") as work:
            config = Path(work) / "config.toml"
            config.write_text("api_token = " + json.dumps(token) + "\n" if token else "")
            config.chmod(0o600)
            with tempfile.TemporaryFile() as errors:
                preview = subprocess.Popen([binary, "--api-url", origin, "--config", str(config),
                    "--output", "text", "preview", name, "38973"], stdout=subprocess.PIPE, stderr=errors)
                with selectors.DefaultSelector() as selector:
                    selector.register(preview.stdout, selectors.EVENT_READ)
                    if not selector.select(30):
                        raise RuntimeError("preview did not publish a local URL")
                    url = preview.stdout.readline().decode().strip()
                if not url.startswith("http://127.0.0.1:"):
                    errors.seek(0)
                    raise RuntimeError("preview failed: " + errors.read().decode())
                request = Request(url + "value.txt?version=1", headers={"User-Agent": "husker-dev-proof"})
                with urlopen(request, timeout=10) as response:
                    require(response.read() == b"parent", "preview returned wrong file")
                preview.send_signal(signal.SIGINT)
                require(preview.wait(timeout=10) == 0, "preview did not shut down cleanly")
                preview = None
        service.cancel()
        print(json.dumps(dict(status="passed", elapsed_secs=round(time.monotonic()-started, 2),
            forks=measurements,
            checks=["tools", "docker-container", "reconnect", "cancel", "warm-fork-service",
                    "disk-isolation", "ram-isolation", "warm-pid", "entropy-divergence",
                    "monotonic-timers", "wall-clock", "resumed-session", "private-preview"])))
    finally:
        if preview is not None and preview.poll() is None:
            preview.terminate()
            try:
                preview.wait(timeout=10)
            except subprocess.TimeoutExpired:
                preview.kill()
                preview.wait()
        failures = []
        for vm in reversed(created):
            try:
                vm.destroy()
            except Exception as error:
                failures.append(vm.name)
                print("cleanup failed for %s: %s" % (vm.name, error), file=sys.stderr)
        if failures:
            raise RuntimeError("destroy proof VMs manually: " + ", ".join(failures))


if __name__ == "__main__":
    main()
