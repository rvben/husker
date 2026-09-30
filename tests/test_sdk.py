"""Python client contracts over real HTTP, with no daemon or VM side effects."""
import base64
import json
import io
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from husker import Client, CapabilityUnsupported, Conflict, NotFound, Unauthorized

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
            status, value = self.server.override
        elif path.endswith("/events"):
            after = int(self.path.split("after=")[1])
            value = dict(session=INFO, next_cursor=2, has_more=False,
                         events=[dict(sequence=2, stream="stdout", data="AP8=")] if after < 2 else [])
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
        with self.assertRaises(Conflict):
            list(vm.iter_file("/workspace/large", chunk_size=103))
        source = io.BytesIO(self.server.file_data)
        self.assertEqual(vm.upload("/workspace/upload", source, mode=0o600, chunk_size=103), 1280)
        writes = [r[3] for r in self.server.requests if r[1].endswith("/files/write")]
        self.assertEqual(b"".join(base64.b64decode(w["data"]) for w in writes), self.server.file_data)
        self.assertFalse(writes[0]["append"])
        self.assertEqual(writes[0]["mode"], 0o600)
        self.assertTrue(all(w["append"] and w["mode"] is None for w in writes[1:]))
        self.assertEqual(vm.upload("/workspace/empty", io.BytesIO()), 0)
        self.assertFalse(self.server.requests[-1][3]["append"])

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
