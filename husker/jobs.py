"""Version-one factory job client; all observations use retained host evidence."""
import base64
import hashlib
import json
import math
import re
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional

from . import CapabilityUnsupported, Conflict, Event, TransportError

_MAX_BUNDLE = 32 * 1024 * 1024
_MAX_ARTIFACT = 4 * 1024 * 1024
_STATES = {"accepted", "preparing", "running", "completed", "command_failed",
           "infrastructure_failed", "interrupted", "cancelled", "timed_out", "unknown"}


def _uuid(value):
    if not isinstance(value, str):
        raise ValueError("job identity must be a canonical nonnil UUID")
    parsed = uuid.UUID(value)
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("job identity must be a canonical nonnil UUID")
    return value


def _key(value):
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 128 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise ValueError("idempotency_key must contain 1–128 non-control UTF-8 bytes")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("expected a lowercase sha256 digest")
    return value


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("integer outside contract bounds")
    return value


def _hash(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _binary(value, maximum):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise ValueError("base64 value exceeds contract bounds")
    data = base64.b64decode(value, validate=True)
    if len(data) > maximum:
        raise ValueError("decoded bytes exceed contract bounds")
    return data


def _descriptor(value):
    if not isinstance(value, dict):
        raise ValueError("invalid artifact descriptor")
    _integer(value["index"], 0, 15)
    _integer(value["size_bytes"], 0, _MAX_ARTIFACT)
    _digest(value["digest"])
    path = value["path"]
    if (not isinstance(path, str) or not path or len(path.encode("utf-8")) > 255
            or "\\" in path or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path)
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise ValueError("unsafe artifact path")
    return dict(value)


@dataclass(frozen=True)
class JobSnapshot:
    record: dict
    artifacts: List[dict]
    references: dict
    replayed: Optional[bool] = None

    @property
    def id(self):
        return self.record["id"]

    @property
    def terminal(self):
        return self.record["state"] not in ("accepted", "preparing", "running")

    @property
    def cleanup_pending(self):
        return self.record["cleanup_pending"]

    @classmethod
    def _parse(cls, value, *, expected_id=None, expected_digest=None, receipt=False):
        if not isinstance(value, dict) or type(value.get("contract_version")) is not int or value["contract_version"] != 1:
            raise CapabilityUnsupported("factory jobs require contract version 1; no execution fallback")
        try:
            record = value["job"]
            if not isinstance(record, dict):
                raise ValueError("invalid job record")
            job_id = _uuid(record["id"])
            _uuid(record["session_id"])
            if record.get("vm_id") is not None:
                _uuid(record["vm_id"])
            digest = _digest(record["specification_digest"])
            if expected_id is not None and job_id != expected_id:
                raise Conflict("job response changed execution identity")
            if expected_digest is not None and digest != expected_digest:
                raise Conflict("job response changed immutable specification")
            if record["state"] not in _STATES or record["collection"] not in ("pending", "complete", "truncated", "failed"):
                raise ValueError("unknown job outcome or collection state")
            for key in ("cleanup_pending", "vm_destroyed", "output_truncated"):
                if type(record[key]) is not bool:
                    raise ValueError("invalid job receipt flag")
            if "vm_allocation_aborted" in record:
                if type(record["vm_allocation_aborted"]) is not bool:
                    raise ValueError("invalid allocation abort receipt")
                if record["vm_allocation_aborted"] and (record["vm_destroyed"] or record.get("vm_id") is None
                        or record["state"] in ("accepted", "running", "completed", "command_failed")):
                    raise ValueError("conflicting allocation abort receipt")
            for key in ("created_at", "deadline", "retention_until"):
                _integer(record[key], 0, 2**63 - 1)
            _integer(record["capture_cursor"], 0, 4096)
            _integer(record["retained_bytes"], 0, _MAX_ARTIFACT)
            specification = record["specification"]
            if not isinstance(specification, str) or len(specification.encode("utf-8")) > 64 * 1024 or _hash(specification.encode("utf-8")) != digest:
                raise ValueError("invalid retained specification identity")
            manifest = record["manifest"]
            if manifest is not None:
                if not isinstance(manifest, str) or len(manifest.encode("utf-8")) > 64 * 1024:
                    raise ValueError("invalid result manifest")
                json.loads(manifest)
            if record["state"] in ("accepted", "preparing", "running"):
                if record["collection"] != "pending":
                    raise ValueError("active job claimed terminal collection")
            elif record["collection"] == "pending" or manifest is None:
                raise ValueError("terminal job lacks sealed evidence status")
            artifacts = value["artifacts"]
            if not isinstance(artifacts, list) or len(artifacts) > 16:
                raise ValueError("artifact inventory exceeds contract bounds")
            artifacts = [_descriptor(item) for item in artifacts]
            if (len({item["index"] for item in artifacts}) != len(artifacts)
                    or len({item["path"] for item in artifacts}) != len(artifacts)
                    or sum(item["size_bytes"] for item in artifacts) > 16 * 1024 * 1024):
                raise ValueError("invalid artifact inventory")
            references = {"job": "/v1/jobs/" + job_id,
                          "events": "/v1/jobs/" + job_id + "/events",
                          "artifacts": "/v1/jobs/" + job_id + "/artifacts"}
            if value["references"] != references:
                raise ValueError("unexpected evidence references")
            replayed = value.get("replayed")
            if receipt and type(replayed) is not bool:
                raise ValueError("submission lacks replay receipt")
            return cls(dict(record), artifacts, references, replayed)
        except (KeyError, TypeError, ValueError, UnicodeError) as error:
            raise TransportError("invalid factory job response") from error


@dataclass(frozen=True)
class JobEventPage:
    job_id: str
    events: List[Event]
    next_cursor: int
    has_more: bool
    output_truncated: bool


@dataclass(frozen=True)
class JobArtifact:
    descriptor: dict
    data: bytes


class Job:
    def __init__(self, client, job_id, *, specification_digest=None):
        self.client, self.id = client, _uuid(job_id)
        self.specification_digest = None if specification_digest is None else _digest(specification_digest)
        self._path = "/v1/jobs/" + self.id
        self.receipt = None

    def _parse(self, value, *, receipt=False):
        return JobSnapshot._parse(value, expected_id=self.id,
            expected_digest=self.specification_digest, receipt=receipt)

    def info(self):
        return self._parse(self.client._request("GET", self._path, max_response_bytes=256 * 1024))

    def cancel(self):
        """Persist cancellation; inspect cleanup_pending for destruction proof."""
        return self._parse(self.client._request("POST", self._path + "/cancel", max_response_bytes=256 * 1024))

    def remove(self):
        """Delete sealed host evidence only after cleanup; retain key tombstone."""
        self.client._request("DELETE", self._path, max_response_bytes=64 * 1024)

    def events(self, *, after=0):
        _integer(after, 0, 4096)
        value = self.client._request("GET", self._path + "/events?after=" + str(after), max_response_bytes=2 * 1024 * 1024)
        try:
            if value["job_id"] != self.id:
                raise Conflict("event response changed job identity")
            cursor = _integer(value["next_cursor"], after, 4096)
            if type(value["has_more"]) is not bool or type(value["output_truncated"]) is not bool:
                raise ValueError("invalid event page flags")
            if not isinstance(value["events"], list) or len(value["events"]) > 128:
                raise ValueError("event page exceeds contract bounds")
            events, previous = [], after
            for item in value["events"]:
                sequence = _integer(item["sequence"], previous + 1, cursor)
                if item["stream"] not in ("stdout", "stderr"):
                    raise ValueError("unknown event stream")
                events.append(Event(sequence, item["stream"], _binary(item["data"], 8192)))
                previous = sequence
            if value["has_more"] and (not events or cursor != previous):
                raise ValueError("event cursor cannot advance")
            return JobEventPage(self.id, events, cursor, value["has_more"], value["output_truncated"])
        except (KeyError, TypeError, ValueError, UnicodeError) as error:
            raise TransportError("invalid factory event page") from error

    def artifact(self, index):
        _integer(index, 0, 15)
        # Inspection pins the retained descriptor before the byte transfer.
        snapshot = self.info()
        expected = next((item for item in snapshot.artifacts if item["index"] == index), None)
        if expected is None:
            from . import NotFound
            raise NotFound("artifact has no retained bytes", kind="artifact_not_found")
        value = self.client._request("GET", self._path + "/artifacts/" + str(index), max_response_bytes=6 * 1024 * 1024)
        try:
            descriptor = _descriptor(value["descriptor"])
            data = _binary(value["data"], _MAX_ARTIFACT)
            if descriptor != expected or len(data) != descriptor["size_bytes"] or _hash(data) != descriptor["digest"]:
                raise Conflict("artifact differs from retained hash/size receipt")
            return JobArtifact(descriptor, data)
        except (KeyError, TypeError, ValueError, UnicodeError) as error:
            raise TransportError("invalid factory artifact response") from error

    def wait(self, *, timeout=None, poll_interval=0.5, cleanup=False):
        """Wait for terminal evidence (and optionally cleanup). A local timeout
        leaves the owned worker running and does not resubmit or cancel the job.
        """
        if not math.isfinite(poll_interval) or poll_interval <= 0:
            raise ValueError("poll_interval must be positive and finite")
        if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("timeout must be positive and finite")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("job observation timed out; execution remains detached")
            snapshot = self._parse(self.client._request("GET", self._path,
                timeout=self.client.timeout if remaining is None else min(remaining, self.client.timeout),
                max_response_bytes=256 * 1024))
            if snapshot.terminal and (not cleanup or not snapshot.cleanup_pending):
                return snapshot
            time.sleep(poll_interval if remaining is None else min(poll_interval, max(0, deadline - time.monotonic())))


def submit_job(client, submission, source, acceptance, retention_until):
    # Freeze the caller's nested containers before hashing and sending them.
    frozen = json.loads(_canonical(submission))
    _key(frozen["idempotency_key"])
    specification = _canonical(frozen["specification"])
    expected_digest = _digest(frozen["execution_specification_digest"])
    if len(specification) > 64 * 1024 or _hash(specification) != expected_digest:
        raise ValueError("execution specification digest mismatch or excessive size")
    for name, data in (("source", source), ("acceptance", acceptance)):
        if not isinstance(data, bytes) or not 1 <= len(data) <= _MAX_BUNDLE:
            raise ValueError("bundle must be nonempty bytes bounded to 32 MiB")
        identity = frozen["specification"][name]
        if identity["size_bytes"] != len(data) or _hash(data) != identity["digest"]:
            raise ValueError("frozen bundle identity mismatch")
    if not isinstance(retention_until, str):
        raise ValueError("retention_until must be an explicit UTC timestamp string")
    value = client._request("POST", "/v1/jobs", {
        "submission": frozen, "source_bundle": base64.b64encode(source).decode("ascii"),
        "acceptance_bundle": base64.b64encode(acceptance).decode("ascii"), "retention_until": retention_until,
    }, max_response_bytes=256 * 1024)
    receipt = JobSnapshot._parse(value, expected_digest=expected_digest, receipt=True)
    job = Job(client, receipt.id, specification_digest=expected_digest)
    job.receipt = receipt
    return job
