"""Synchronous client for a running, self-hosted Husker daemon (Python 3.8+)."""
import base64
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

__all__ = ["Client", "Sandbox", "Session", "SessionInfo", "Event", "EventPage",
           "ExecResult", "HuskerError", "TransportError", "NotFound", "Conflict",
           "PolicyDenied", "Unauthorized", "CapabilityUnsupported", "CapacityExceeded"]


class HuskerError(Exception):
    def __init__(self, message, *, status=None, kind=None, hint=None):
        super().__init__(message)
        self.status, self.kind, self.hint = status, kind, hint


class TransportError(HuskerError):
    pass


class NotFound(HuskerError):
    pass


class Conflict(HuskerError):
    pass


class PolicyDenied(HuskerError):
    pass


class Unauthorized(HuskerError):
    pass


class CapabilityUnsupported(HuskerError):
    pass


class CapacityExceeded(HuskerError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a daemon credential to a redirect destination.
        return None


def _segment(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("invalid resource name")
    return quote(value, safe="")


def _command(argv, workdir, env, secrets, timeout_secs):
    if isinstance(argv, (str, bytes)) or not argv or not all(isinstance(v, str) for v in argv):
        raise ValueError("command must be a nonempty sequence of arguments")
    if timeout_secs is not None and (isinstance(timeout_secs, bool) or
            not isinstance(timeout_secs, int) or timeout_secs <= 0):
        raise ValueError("timeout_secs must be a positive integer")
    return dict(command=argv[0], args=list(argv[1:]), working_dir=workdir,
                env=dict(env or {}), secret_env=dict(secrets or {}), timeout_secs=timeout_secs)


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class SessionInfo:
    id: str
    command: str
    state: str
    created_at: int
    finished_at: Optional[int]
    exit_code: Optional[int]
    output_truncated: bool

    @classmethod
    def _parse(cls, value):
        return cls(**{key: value[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Event:
    sequence: int
    stream: str
    data: bytes


@dataclass(frozen=True)
class EventPage:
    session: SessionInfo
    events: List[Event]
    next_cursor: int
    has_more: bool


class Client:
    """No daemon spawning or implicit VM deletion. TLS verifies certificates.

    For SSH contexts, point this client at an explicitly established local
    forward. The native CLI manages SSH contexts and preview WebSockets.
    """
    def __init__(self, base_url="http://127.0.0.1:7777", *, token=None, timeout=30):
        parts = urlsplit(base_url)
        if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username
                or parts.password or parts.query or parts.fragment or parts.path not in ("", "/")):
            raise ValueError("base_url must be an HTTP(S) daemon origin without credentials")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._token = token
        self._opener = build_opener(_NoRedirect())

    def _request(self, method, path, body=None, *, timeout=None):
        headers = {"Accept": "application/json", "User-Agent": "husker-python-sdk"}
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        data = None if body is None else json.dumps(body).encode("utf-8")
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout if timeout is None else timeout) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except HTTPError as error:
            with error:
                raw = error.read()
            try:
                details = json.loads(raw)
                if not isinstance(details, dict):
                    details = {}
            except (ValueError, UnicodeError):
                details = {}
            cls = {401: Unauthorized, 403: PolicyDenied, 404: NotFound,
                   409: Conflict, 429: CapacityExceeded, 501: CapabilityUnsupported}.get(error.code, HuskerError)
            raise cls(details.get("message", "Husker HTTP error %s" % error.code),
                      status=error.code, kind=details.get("kind"), hint=details.get("hint")) from None
        except (URLError, OSError) as error:
            raise TransportError("unable to reach Husker daemon: %s" % error) from None
        except (ValueError, UnicodeError) as error:
            raise TransportError("invalid JSON response from Husker daemon") from error

    def create(self, name, *, image=None, **options):
        """Create a VM. Options use the HTTP API names, e.g. mem_size_mib."""
        _segment(name)
        if image is not None:
            if "rootfs_path" in options or "cloud_image" in options:
                raise ValueError("image conflicts with rootfs_path or cloud_image")
            options["rootfs_path"] = image
        self._request("POST", "/v1/vms", dict(options, name=name))
        return Sandbox(self, name)

    def connect(self, name):
        sandbox = Sandbox(self, name)
        sandbox.info()
        return sandbox


class Sandbox:
    def __init__(self, client, name):
        self.client, self.name = client, name
        self._path = "/v1/vms/" + _segment(name)

    def info(self):
        return self.client._request("GET", self._path)

    def wait_ready(self, argv=("true",), *, timeout=60, poll_interval=0.25, workdir=None):
        """Wait for a successful guest health command, not merely a running VMM.

        Supply an application probe to establish app readiness before suspend
        or warm-pool capture. Authentication and policy failures are immediate.
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        if not math.isfinite(poll_interval) or poll_interval <= 0:
            raise ValueError("poll_interval must be positive and finite")
        request = _command(argv, workdir, None, None, 5)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("guest health command did not become ready")
            request["timeout_secs"] = max(1, min(5, math.ceil(remaining)))
            request["connect_timeout_secs"] = max(1, min(5, math.ceil(remaining)))
            try:
                result = ExecResult(**self.client._request("POST", self._path + "/exec",
                    request, timeout=min(remaining, self.client.timeout)))
                if result.exit_code == 0:
                    return result
            except TransportError:
                pass
            except HuskerError as error:
                if error.status not in (502, 503, 504):
                    raise
            time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))

    def exec(self, argv: Sequence[str], *, workdir=None, env=None, secrets=None,
             timeout_secs=30, check=False):
        request = _command(argv, workdir, env, secrets, timeout_secs)
        http_timeout = self.client.timeout if timeout_secs is None else max(self.client.timeout, timeout_secs + 35)
        result = ExecResult(**self.client._request("POST", self._path + "/exec", request,
            timeout=http_timeout))
        if check and result.exit_code != 0:
            raise HuskerError("guest command exited with %s: %s" % (result.exit_code, result.stderr), kind="exec_failed")
        return result

    def start(self, argv: Sequence[str], *, workdir=None, env=None, secrets=None, timeout_secs=3600):
        info = self.client._request("POST", self._path + "/sessions",
            _command(argv, workdir, env, secrets, timeout_secs))
        return Session(self, info["id"])

    def session(self, session_id):
        return Session(self, session_id)

    def sessions(self):
        return [SessionInfo._parse(value) for value in self.client._request("GET", self._path + "/sessions")]

    def read_file(self, path, *, offset=0, length=1024 * 1024):
        """Read one bounded, binary-safe range. Repeat with an offset for large files."""
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (offset, length)):
            raise ValueError("offset and length must be nonnegative integers")
        value = self.client._request("POST", self._path + "/files/read", dict(path=path, offset=offset, len=length))
        return base64.b64decode(value["data"], validate=True)

    def iter_file(self, path, *, chunk_size=256 * 1024):
        """Stream binary ranges; reject a file that changes between requests.

        Consumers can have received earlier chunks when a later read fails.
        Use an immutable guest file for a consistent transfer.
        """
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or not 1 <= chunk_size <= 1024 * 1024:
            raise ValueError("chunk_size must be an integer between 1 and 1048576")
        offset, identity = 0, None
        while True:
            value = self.client._request("POST", self._path + "/files/read",
                dict(path=path, offset=offset, len=chunk_size))
            current = (value.get("total_size"), value.get("modified_nanos"))
            if current[0] is None or current[1] is None:
                raise CapabilityUnsupported("streaming files requires a guest with ranged-read metadata")
            if identity is not None and current != identity:
                raise Conflict("guest file changed during transfer", kind="file_changed")
            identity = current
            data = base64.b64decode(value["data"], validate=True)
            if len(data) > chunk_size or offset + len(data) > current[0] or (not data and offset < current[0]):
                raise TransportError("invalid guest file range response")
            if data:
                yield data
                offset += len(data)
            if offset == current[0]:
                return

    def upload(self, path, source, *, mode=None, chunk_size=256 * 1024):
        """Copy a binary readable stream with bounded memory. Failure may leave
        a partial guest file; no write is automatically retried or duplicated.
        """
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or not 1 <= chunk_size <= 1024 * 1024:
            raise ValueError("chunk_size must be an integer between 1 and 1048576")
        total, append = 0, False
        while True:
            data = source.read(chunk_size)
            if not isinstance(data, bytes):
                raise ValueError("source must be a binary readable stream")
            if len(data) > chunk_size:
                raise ValueError("source exceeded the requested chunk size")
            if data or not append:
                written = self.write_file(path, data, mode=mode if not append else None, append=append)
                if written != len(data):
                    raise TransportError("incomplete guest file write")
                total += written
                append = True
            if not data:
                return total

    def write_file(self, path, data: bytes, *, mode=None, append=False):
        value = self.client._request("POST", self._path + "/files/write",
            dict(path=path, data=base64.b64encode(data).decode("ascii"), mode=mode, append=append))
        return value["bytes_written"]

    def suspend(self):
        return self.client._request("POST", self._path + "/suspend")

    def resume(self):
        return self.client._request("POST", self._path + "/resume")

    def fork(self, name):
        _segment(name)
        self.client._request("POST", self._path + "/fork", dict(fork_name=name))
        return Sandbox(self.client, name)

    def destroy(self):
        self.client._request("DELETE", self._path)


class Session:
    def __init__(self, sandbox, session_id):
        self.sandbox, self.id = sandbox, session_id
        self._path = sandbox._path + "/sessions/" + _segment(session_id)

    def info(self):
        return SessionInfo._parse(self.sandbox.client._request("GET", self._path))

    def cancel(self):
        return SessionInfo._parse(self.sandbox.client._request("POST", self._path + "/cancel"))

    def remove(self):
        self.sandbox.client._request("DELETE", self._path)

    def events(self, *, after=0):
        if isinstance(after, bool) or not isinstance(after, int) or after < 0:
            raise ValueError("cursor must be a nonnegative integer")
        page = self.sandbox.client._request("GET", self._path + "/events?after=" + str(after))
        return EventPage(SessionInfo._parse(page["session"]),
            [Event(event["sequence"], event["stream"], base64.b64decode(event["data"], validate=True)) for event in page["events"]],
            page["next_cursor"], page["has_more"])

    def iter_events(self, *, after=0, poll_interval=0.5) -> Iterator[Event]:
        """Reattach using the last yielded sequence. Stopping iteration detaches."""
        if not math.isfinite(poll_interval) or poll_interval <= 0:
            raise ValueError("poll_interval must be positive and finite")
        while True:
            page = self.events(after=after)
            yield from page.events
            after = page.next_cursor
            if page.session.state != "running" and not page.has_more:
                return
            if not page.has_more:
                time.sleep(poll_interval)

    def wait(self, *, timeout=None, poll_interval=0.5):
        """Wait for completion. A client wait timeout leaves the guest command running."""
        if not math.isfinite(poll_interval) or poll_interval <= 0:
            raise ValueError("poll_interval must be positive and finite")
        if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("timeout must be positive and finite")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("session wait timed out; guest command remains detached")
            info = SessionInfo._parse(self.sandbox.client._request("GET", self._path,
                timeout=self.sandbox.client.timeout if remaining is None else min(remaining, self.sandbox.client.timeout)))
            if info.state != "running":
                return info
            time.sleep(poll_interval if remaining is None else min(poll_interval, max(0, deadline - time.monotonic())))
