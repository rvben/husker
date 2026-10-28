"""Python client contracts over real HTTP, with no daemon or VM side effects."""
import base64
import json
import io
import hashlib
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from husker import (CapabilityUnsupported, Client, CommandFailed, Conflict, FileChanged,
                    NotFound, Unauthorized, TransportError)

ID = "01234567-89ab-cdef-0123-456789abcdef"
INFO = dict(id=ID, command="sh", state="completed", created_at=1,
            finished_at=2, exit_code=0, output_truncated=False)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_DELETE(self):
        self.dispatch()

    def dispatch(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        payload = json.loads(body) if body else None
        self.server.requests.append((self.command, self.path, dict(self.headers), payload))
        path = urlsplit(self.path).path
        status = 200
        if self.headers.get("Authorization") != "Bearer test-token":
            status, value = 401, {"kind": "unauthorized", "message": "token required"}
        elif self.server.override is not None:
            status, value = self.server.override(self.command, self.path, payload) if callable(self.server.override) else self.server.override
        elif path.endswith("/events"):
            after = int(self.path.split("after=")[1])
            value = dict(session=INFO, next_cursor=2, has_more=False,
                         events=[dict(sequence=2, stream="stdout", data="AP8=")] if after < 2 else [])
        elif path.endswith("/session-submissions"):
            value = INFO
        elif path.endswith("/sessions"):
            value = INFO if self.command == "POST" else [INFO]
        elif "/sessions/" in path:
            value = INFO
        elif path.endswith("/exec"):
            code = self.server.health.pop(0) if self.server.health else 0
            value = dict(exit_code=code, stdout="hello", stderr="")
        elif path.endswith("/files/read"):
            data = self.server.file_data
            start = payload.get("offset") or 0
            part = data[start:start + (payload.get("len") or len(data))]
            modified = 2 if self.server.change_file and start else 1
            value = dict(data=base64.b64encode(part).decode("ascii"), size=len(part),
                         total_size=len(data), modified_nanos=modified)
        elif path.endswith("/files/write"):
            value = dict(bytes_written=len(base64.b64decode(payload["data"])))
        elif path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", self.server.base + "/v1/vms/credential-leak")
            self.end_headers()
            return
        else:
            value = {"name": "dev", "state": "running"}
        encoded = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.base = "http://127.0.0.1:%s" % cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.requests = []
        self.server.override = None
        self.server.health = []
        self.server.file_data = b"\x00\xff"
        self.server.change_file = False
        self.client = Client(self.server.base, token="test-token")

    def test_create_and_exec_use_existing_api_and_literal_arguments(self):
        vm = self.client.create("dev", image="husker-dev", mem_size_mib=4096)
        result = vm.exec(["sh", "-c", "printf '%s' '$HOME;$(id)'"], workdir="/workspace")
        self.assertEqual(result.stdout, "hello")
        create = self.server.requests[0][3]
        self.assertEqual(create["rootfs_path"], "husker-dev")
        self.assertNotIn("image", create)
        self.assertEqual(create["mem_size_mib"], 4096)
        self.assertEqual(self.server.requests[1][3]["args"], ["-c", "printf '%s' '$HOME;$(id)'"])
        self.assertEqual(self.server.requests[0][2]["User-Agent"], "husker-python-sdk")
        self.assertEqual(vm.exec(["true"], timeout_secs=None).exit_code, 0)

    def test_keyed_submission_uses_fail_closed_endpoint(self):
        vm = self.client.connect("dev")
        self.assertEqual(vm.start(["true"], idempotency_key="stage/1/check/0").id, ID)
        self.assertTrue(self.server.requests[-1][1].endswith("/session-submissions"))
        self.assertEqual(self.server.requests[-1][3]["idempotency_key"], "stage/1/check/0")
        for key in ("", "x" * 129, "é" * 65, 123):
            with self.assertRaises(ValueError):
                vm.start(["true"], idempotency_key=key)
        self.server.override = (404, {"kind": "not_found", "message": "old daemon"})
        before = len(self.server.requests)
        with self.assertRaises(NotFound):
            vm.start(["true"], idempotency_key="key")
        self.assertEqual(len(self.server.requests), before + 1)

    def test_detach_and_reattach_cursor_preserves_binary_output(self):
        vm = self.client.connect("dev")
        session = vm.start(["sh", "-c", "echo hello"], secrets={"API_KEY": "stored-key"})
        self.assertEqual(session.id, ID)
        self.assertEqual(vm.sessions()[0].state, "completed")
        reattached = self.client.connect("dev").session(ID)
        events = list(reattached.iter_events(after=1))
        self.assertEqual(events[0].data, b"\x00\xff")
        self.assertEqual(events[0].sequence, 2)
        self.assertEqual(list(reattached.iter_events(after=2)), [])
        self.assertEqual(reattached.wait(timeout=1).exit_code, 0)
        self.assertEqual(reattached.cancel().state, "completed")
        reattached.remove()
        self.assertEqual(self.server.requests[-1][0], "DELETE")
        self.assertEqual(self.server.requests[1][3]["secret_env"], {"API_KEY": "stored-key"})

    def test_file_bytes_and_fork_lifecycle(self):
        vm = self.client.connect("dev")
        self.assertEqual(vm.write_file("/workspace/binary", b"\x00\xff", mode=0o600), 2)
        self.assertEqual(vm.read_file("/workspace/binary"), b"\x00\xff")
        vm.suspend()
        vm.resume()
        fork = vm.fork("child")
        self.assertEqual(fork.name, "child")
        fork.destroy()
        self.assertEqual(self.server.requests[-2][3], {"fork_name": "child"})
        self.assertEqual(self.server.requests[-1][:2], ("DELETE", "/v1/vms/child"))

    def test_readiness_probes_application_and_fails_fast_on_auth(self):
        vm = self.client.connect("dev")
        self.server.health = [1, 1, 0]
        result = vm.wait_ready(["curl", "--fail", "http://127.0.0.1:3000/health"],
                               timeout=1, poll_interval=0.01)
        self.assertEqual(result.exit_code, 0)
        probes = [r[3] for r in self.server.requests if r[1].endswith("/exec")]
        self.assertEqual(len(probes), 3)
        self.assertEqual(probes[0]["args"], ["--fail", "http://127.0.0.1:3000/health"])
        self.server.override = (401, {"message": "denied"})
        with self.assertRaises(Unauthorized):
            vm.wait_ready(timeout=1)
        self.server.override = None
        self.server.health = [1] * 100
        with self.assertRaises(TimeoutError):
            vm.wait_ready(timeout=0.03, poll_interval=0.01)

    def test_streaming_files_keep_binary_ranges_and_detect_changes(self):
        vm = self.client.connect("dev")
        self.server.file_data = bytes(range(256)) * 5
        chunks = list(vm.iter_file("/workspace/large", chunk_size=103))
        self.assertEqual(b"".join(chunks), self.server.file_data)
        self.assertTrue(all(len(c) <= 103 for c in chunks))
        self.server.change_file = True
        with self.assertRaises(FileChanged) as raised:
            list(vm.iter_file("/workspace/large", chunk_size=103))
        # The SDK detected the change itself: a Conflict for existing handlers,
        # without a daemon error kind.
        self.assertIsInstance(raised.exception, Conflict)
        self.assertIsNone(raised.exception.kind)
        self.assertIsNone(raised.exception.status)
        source = io.BytesIO(self.server.file_data)
        self.assertEqual(vm.upload("/workspace/upload", source, mode=0o600, chunk_size=103), 1280)
        writes = [r[3] for r in self.server.requests if r[1].endswith("/files/write")]
        self.assertEqual(b"".join(base64.b64decode(w["data"]) for w in writes), self.server.file_data)
        self.assertFalse(writes[0]["append"])
        self.assertEqual(writes[0]["mode"], 0o600)
        self.assertTrue(all(w["append"] and w["mode"] is None for w in writes[1:]))
        self.assertEqual(vm.upload("/workspace/empty", io.BytesIO()), 0)
        self.assertFalse(self.server.requests[-1][3]["append"])

    def test_exec_check_raises_command_failed_with_the_result(self):
        vm = self.client.connect("dev")
        self.server.health = [3]
        with self.assertRaises(CommandFailed) as raised:
            vm.exec(["false"], check=True)
        error = raised.exception
        self.assertEqual(error.result.exit_code, 3)
        self.assertEqual(error.result.stdout, "hello")
        self.assertIn("exited with 3", str(error))
        # No daemon error was involved, so there is no daemon kind or status.
        self.assertIsNone(error.kind)
        self.assertIsNone(error.status)
        self.server.health = [3]
        self.assertEqual(vm.exec(["false"]).exit_code, 3)

    def test_typed_errors_include_server_hint(self):
        for status, cls in [(404, NotFound), (409, Conflict), (501, CapabilityUnsupported)]:
            self.server.override = status, dict(kind="test_kind", message="denied", hint="refresh guest")
            with self.assertRaises(cls) as caught:
                self.client.connect("dev")
            self.assertEqual(caught.exception.status, status)
            self.assertEqual(caught.exception.kind, "test_kind")
            self.assertEqual(caught.exception.hint, "refresh guest")
        self.server.override = None
        with self.assertRaises(Unauthorized):
            Client(self.server.base).connect("dev")

    def test_credentials_are_not_forwarded_to_redirect(self):
        from husker import HuskerError
        with self.assertRaises(HuskerError) as caught:
            self.client._request("GET", "/redirect")
        self.assertEqual(caught.exception.status, 302)
        self.assertEqual(len(self.server.requests), 1)

    def test_wait_timeout_does_not_cancel_or_delete(self):
        self.server.override = 200, dict(INFO, state="running", finished_at=None, exit_code=None)
        session = self.client.create("dev").session(ID)
        with self.assertRaises(TimeoutError):
            session.wait(timeout=0.03, poll_interval=0.01)
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests[1:]))

    def factory_fixture(self, *, state="completed", cleanup_pending=False):
        source, acceptance = b"frozen-source", b"frozen-acceptance"
        digest = lambda data: "sha256:" + hashlib.sha256(data).hexdigest()
        spec = {"version": 1, "source": {"digest": digest(source), "size_bytes": len(source)},
                "acceptance": {"digest": digest(acceptance), "size_bytes": len(acceptance)},
                "commands": [{"argv": ["printf", "λ;$HOME"], "timeout_secs": 20}]}
        canonical = json.dumps(spec, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        submission = {"idempotency_key": "baseline-round-1", "specification": spec,
                      "execution_specification_digest": digest(canonical)}
        artifact = b"\x00\xffdeclared result"
        descriptor = dict(index=0, path="results/check.txt", size_bytes=len(artifact), digest=digest(artifact))
        record = dict(id=ID, session_id="11234567-89ab-cdef-0123-456789abcdef", vm_id=None,
                      specification_digest=digest(canonical), specification=canonical.decode(),
                      state=state, created_at=1, deadline=60, retention_until=3600,
                      capture_cursor=2, retained_bytes=2, output_truncated=False,
                      collection="pending" if state == "running" else "complete",
                      manifest=None if state == "running" else '{"commands":[]}',
                      cleanup_pending=cleanup_pending, vm_destroyed=True, vm_allocation_aborted=False)
        inspection = dict(contract_version=1, job=record, artifacts=[descriptor],
                          references={"job": "/v1/jobs/"+ID, "events": "/v1/jobs/"+ID+"/events",
                                      "artifacts": "/v1/jobs/"+ID+"/artifacts"}, replayed=False)
        return submission, source, acceptance, inspection, artifact

    def test_factory_submission_identity_replay_and_host_evidence(self):
        submission, source, acceptance, inspection, artifact = self.factory_fixture()
        def response(method, path, payload):
            if path.endswith("/artifacts/0"):
                return 200, dict(descriptor=inspection["artifacts"][0], data=base64.b64encode(artifact).decode())
            if "/events?" in path:
                after = int(path.split("after=")[1])
                return 200, dict(job_id=ID, next_cursor=2, has_more=False, output_truncated=False,
                                 events=[dict(sequence=2, stream="stdout", data="AP8=")] if after < 2 else [])
            if method == "DELETE":
                return 204, None
            return 200, inspection
        self.server.override = response
        job = self.client.submit_job(submission, source, acceptance, retention_until="2026-10-08T12:00:00Z")
        self.assertEqual(job.id, ID)
        self.assertFalse(job.receipt.replayed)
        sent = self.server.requests[0][3]
        self.assertEqual(sent["submission"], submission)
        self.assertEqual(base64.b64decode(sent["source_bundle"]), source)
        self.assertEqual(base64.b64decode(sent["acceptance_bundle"]), acceptance)
        self.assertEqual(sent["submission"]["specification"]["commands"][0]["argv"], ["printf", "λ;$HOME"])
        # Reconstruct only from journaled identity; observation performs no POST.
        reconnected = self.client.job(ID, specification_digest=submission["execution_specification_digest"])
        self.assertTrue(reconnected.info().terminal)
        page = reconnected.events(after=0)
        self.assertEqual(page.events[0].data, b"\0\xff")
        self.assertEqual(reconnected.events(after=page.next_cursor).events, [])
        self.assertEqual(reconnected.artifact(0).data, artifact)
        self.assertTrue(reconnected.wait(timeout=0.1, cleanup=True).terminal)
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests[1:]))
        inspection["replayed"] = True
        replay = self.client.submit_job(submission, source, acceptance, retention_until="2026-10-08T12:00:00Z")
        self.assertTrue(replay.receipt.replayed)
        self.assertEqual(replay.id, job.id)
        self.assertFalse(job.cancel().cleanup_pending)
        job.remove()
        self.assertEqual(self.server.requests[-1][0], "DELETE")

    def test_factory_unknown_version_identity_and_bad_input_never_fall_back(self):
        submission, source, acceptance, inspection, _ = self.factory_fixture()
        self.server.override = 200, inspection
        for bad_source in (b"changed", "not bytes"):
            with self.assertRaises(ValueError):
                self.client.submit_job(submission, bad_source, acceptance, retention_until="UTC")
        self.assertEqual(self.server.requests, [])
        inspection["contract_version"] = 2
        with self.assertRaises(CapabilityUnsupported):
            self.client.submit_job(submission, source, acceptance, retention_until="UTC")
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.server.requests[0][1], "/v1/jobs")
        inspection["contract_version"] = 1
        wrong = self.client.job("21234567-89ab-cdef-0123-456789abcdef")
        with self.assertRaises(Conflict):
            wrong.info()
        inspection["references"]["job"] = "https://example.invalid/?token=synthetic"
        with self.assertRaises(TransportError):
            self.client.job(ID).info()
        self.assertTrue(all(path.startswith("/v1/jobs") for _, path, _, _ in self.server.requests))

    def test_factory_preallocation_abort_receipt_is_explicit_and_cannot_claim_destruction(self):
        _, _, _, inspection, _ = self.factory_fixture(state="infrastructure_failed")
        record=inspection["job"]
        record.update(collection="failed",vm_destroyed=False,vm_allocation_aborted=True,
                      vm_id="21234567-89ab-cdef-0123-456789abcdef")
        self.server.override=200,inspection
        snapshot=self.client.job(ID).info()
        self.assertTrue(snapshot.record["vm_allocation_aborted"])
        self.assertFalse(snapshot.record["vm_destroyed"])
        for value in (1,None,"true"):
            record["vm_allocation_aborted"]=value
            with self.assertRaises(TransportError): self.client.job(ID).info()
        record["vm_allocation_aborted"]=True; record["vm_destroyed"]=True
        with self.assertRaises(TransportError): self.client.job(ID).info()
        record.update(vm_destroyed=False,state="completed")
        with self.assertRaises(TransportError): self.client.job(ID).info()
        record.update(state="infrastructure_failed",vm_id=None)
        with self.assertRaises(TransportError): self.client.job(ID).info()
        record["vm_id"]="21234567-89ab-cdef-0123-456789abcdef"
        record.update(vm_destroyed=False,state="running",collection="pending",manifest=None)
        with self.assertRaises(TransportError): self.client.job(ID).info()
        self.assertTrue(all(method=="GET" for method,_,_,_ in self.server.requests))

    def test_factory_cursor_and_artifact_corruption_fail_closed(self):
        submission, _, _, inspection, artifact = self.factory_fixture()
        job = self.client.job(ID, specification_digest=submission["execution_specification_digest"])
        def response(method, path, payload):
            if path.endswith("/artifacts/0"):
                return 200, dict(descriptor=inspection["artifacts"][0], data=base64.b64encode(artifact+b"changed").decode())
            return 200, inspection
        self.server.override = response
        with self.assertRaises(Conflict):
            job.artifact(0)
        page = dict(job_id=ID, next_cursor=2, has_more=True, output_truncated=False,
                    events=[dict(sequence=2, stream="stdout", data="AP8=")])
        self.server.override = 200, page
        self.assertEqual(job.events(after=1).next_cursor, 2)
        for change in (dict(events=[]), dict(next_cursor=1), dict(events=[dict(sequence=1, stream="stdout", data="AP8=")]),
                       dict(events=[dict(sequence=2, stream="stdout", data="a"*12000)]), dict(has_more="yes")):
            self.server.override = 200, dict(page, **change)
            with self.assertRaises(TransportError):
                job.events(after=1)
        self.server.override = 200, dict(page, job_id="21234567-89ab-cdef-0123-456789abcdef")
        with self.assertRaises(Conflict):
            job.events(after=1)

    def test_factory_pending_cleanup_and_local_wait_timeout_do_not_cancel(self):
        _, _, _, inspection, _ = self.factory_fixture(cleanup_pending=True)
        self.server.override = 200, inspection
        job = self.client.job(ID)
        self.assertTrue(job.wait(timeout=0.1).cleanup_pending)
        with self.assertRaises(TimeoutError):
            job.wait(timeout=0.015, poll_interval=0.005, cleanup=True)
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests))
        self.assertTrue(job.cancel().cleanup_pending)
        self.assertEqual(self.server.requests[-1][1], "/v1/jobs/"+ID+"/cancel")

    def test_factory_lost_receipt_lookup_is_read_only_and_preserves_identity(self):
        submission, _, _, inspection, _ = self.factory_fixture()
        del inspection["replayed"]
        self.server.override = 200, inspection
        job = self.client.find_job("round/1 café?", submission["execution_specification_digest"])
        self.assertEqual(job.id, ID)
        method, path, headers, payload = self.server.requests[-1]
        self.assertEqual(method, "GET")
        self.assertIsNone(payload)
        self.assertEqual(urlsplit(path).path, "/v1/job-submissions")
        self.assertEqual(parse_qs(urlsplit(path).query)["idempotency_key"], ["round/1 café?"])
        self.assertNotIn("test-token", path)
        self.assertIsNone(job.receipt.replayed)
        self.server.override = 404, {"kind": "job_not_found", "message": "no acceptance"}
        with self.assertRaises(NotFound):
            self.client.find_job("never-accepted", submission["execution_specification_digest"])
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests))
        count = len(self.server.requests)
        for key in ("", "key\n", "x"*129):
            with self.assertRaises(ValueError):
                self.client.find_job(key, submission["execution_specification_digest"])
        self.assertEqual(len(self.server.requests), count)

    def test_factory_canonical_digest_matches_shared_rust_vector(self):
        from husker.jobs import _canonical
        fixtures = Path(__file__).parent / "fixtures"
        specification = json.loads((fixtures / "job_spec_v1.json").read_text())
        digest = "sha256:" + hashlib.sha256(_canonical(specification)).hexdigest()
        self.assertEqual(digest, (fixtures / "job_spec_v1.sha256").read_text().strip())

    def test_http_response_read_is_bounded(self):
        self.server.override = 200, dict(padding="x"*4096)
        with self.assertRaises(TransportError):
            self.client._request("GET", "/v1/jobs/"+ID, max_response_bytes=128)

    def test_invalid_names_commands_and_origins_fail_before_network(self):
        for name in ["../dev", "a/b", "bad?query", ""]:
            with self.assertRaises(ValueError):
                self.client.create(name)
        for url in ["file:///tmp/daemon", "http://user:secret@localhost", "http://localhost/path"]:
            with self.assertRaises(ValueError):
                Client(url)
        vm = self.client.create("dev")
        for command in ["sh -c echo", [], [1]]:
            with self.assertRaises(ValueError):
                vm.start(command)
        self.assertEqual(len(self.server.requests), 1)


if __name__ == "__main__":
    unittest.main()
