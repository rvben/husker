"""Versioned Werkt checks integration example. No worker/model/daemon activation.

Callers supply already frozen canonical tar bytes and operator-owned commands.
The journal belongs in a private directory separate from checkout/build caches.
"""
import datetime
import hashlib
import json
import os
import sqlite3
import stat
import time
from pathlib import Path

from husker import Client, Conflict, HuskerError, NotFound


class Unavailable(RuntimeError):
    """Stop the uncertain stage; do not reacquire its claim or rerun checks."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def utc(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def submission_for_stage(key, image, source, acceptance, trusted_commands, *,
                         correlation, claim_deadline, stage="candidate",
                         writable_directories=(), artifacts=(), environment=None,
                         resources=None, uid=1000, gid=1000, now=None):
    """Freeze the deadline once and journal this result before any retry.

    Default budgets: baseline 600s, candidate 1800s, command <=1200s. Boot,
    staging and collection consume the same stage deadline. Claims are supplied
    by Werkt and never extended/reacquired here.
    """
    if stage not in ("baseline", "candidate"):
        raise ValueError("stage must be baseline or candidate")
    if correlation.get("stage") != stage:
        raise ValueError("correlation stage must match the isolated check stage")
    if type(claim_deadline) is not int:
        raise ValueError("claim_deadline must be an absolute UTC epoch second")
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 0:
        raise ValueError("now must be an absolute UTC epoch second")
    budget = 600 if stage == "baseline" else 1800
    deadline = current + budget
    if deadline >= claim_deadline or claim_deadline - current > 3600:
        raise ValueError("stage must finish within the existing one-hour claim")
    if not isinstance(key, str) or not 1 <= len(key.encode()) <= 128:
        raise ValueError("bounded journaled submission key required")
    commands = []
    for argv in trusted_commands:
        if isinstance(argv, (str, bytes)) or not argv or not all(isinstance(arg, str) and '\0' not in arg for arg in argv):
            raise ValueError("trusted checks must be literal argv arrays")
        commands.append({"argv": list(argv), "timeout_secs": min(1200, budget)})
    if not 1 <= len(commands) <= 32:
        raise ValueError("one to thirty-two trusted commands required")
    for bundle in (source, acceptance):
        if not isinstance(bundle, bytes) or not 1 <= len(bundle) <= 32 * 1024 * 1024:
            raise ValueError("canonical frozen bundles must be bounded bytes")
    spec = dict(version=1, image=image,
        source=dict(digest=digest(source), size_bytes=len(source)),
        acceptance=dict(digest=digest(acceptance), size_bytes=len(acceptance)),
        commands=commands, working_directory="/workspace",
        writable_directories=list(writable_directories),
        environment=dict(environment or {}), uid=uid, gid=gid,
        resources=resources or dict(vcpu_count=2, mem_size_mib=4096,
                                    disk_size_bytes=20 * 1024**3, pids_limit=128),
        network={"mode": "none"}, deadline=utc(deadline), artifacts=list(artifacts),
        correlation=correlation)
    spec = json.loads(canonical(spec))
    return dict(idempotency_key=key, specification=spec,
                execution_specification_digest=digest(canonical(spec).encode()))


class Journal:
    """FULL-sync SQLite with frozen inputs committed before outbound submission.

    Bounded to 64 entries/32 MiB per tar/256 KiB evidence per entry. No daemon
    credential is stored. This is an example single-admin journal, not a claim
    service or a concurrent-worker fencing replacement.
    """
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError("journal parent must be an owned private 0700 directory")
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
                raise ValueError("journal must be an owned unlinked regular 0600 file")
        self.db = sqlite3.connect(str(path), timeout=5)
        os.chmod(path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS checks (
            key TEXT PRIMARY KEY, submission TEXT NOT NULL CHECK(length(CAST(submission AS BLOB))<=65536),
            source BLOB NOT NULL CHECK(length(source)<=33554432),
            acceptance BLOB NOT NULL CHECK(length(acceptance)<=33554432), retention TEXT NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('prepared','requested','identified','collected')),
            job_id TEXT, session_id TEXT, acceptance_replayed INTEGER CHECK(acceptance_replayed IN (0,1)), evidence TEXT CHECK(length(CAST(evidence AS BLOB))<=262144))""")
        self.db.commit()
        # Serialize migration with other journal openers; retain old request/UUID rows.
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(checks)")}
            if "acceptance_replayed" not in columns:
                self.db.execute("ALTER TABLE checks ADD COLUMN acceptance_replayed INTEGER CHECK(acceptance_replayed IN (0,1))")
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def close(self):
        self.db.close()

    def get(self, key):
        row = self.db.execute("SELECT * FROM checks WHERE key=?", (key,)).fetchone()
        if row is None:
            raise Unavailable("submission identity is absent from the local journal")
        return row

    def prepare(self, submission, source, acceptance, retention):
        encoded = canonical(submission)
        if len(encoded.encode()) > 64 * 1024 or not isinstance(source, bytes) or not isinstance(acceptance, bytes):
            raise ValueError("bounded immutable request and binary bundles required")
        spec = submission["specification"]
        if digest(canonical(spec).encode()) != submission["execution_specification_digest"]:
            raise ValueError("specification digest mismatch")
        for name, data in (("source", source), ("acceptance", acceptance)):
            if len(data) > 32 * 1024 * 1024 or spec[name] != dict(digest=digest(data), size_bytes=len(data)):
                raise ValueError("frozen bundle mismatch")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT 1 FROM checks WHERE key=?", (submission["idempotency_key"],)).fetchone():
                raise Conflict("stage already journaled; inspect instead of rerunning")
            if self.db.execute("SELECT count(*) FROM checks").fetchone()[0] >= 64:
                raise Unavailable("local evidence journal capacity exhausted")
            self.db.execute("INSERT INTO checks(key,submission,source,acceptance,retention,phase) VALUES (?,?,?,?,?,'prepared')",
                (submission["idempotency_key"], encoded, source, acceptance, retention))

    def requested(self, key):
        with self.db:
            self.db.execute("UPDATE checks SET phase='requested' WHERE key=? AND phase='prepared'", (key,))

    def bind(self, key, snapshot):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(key)
            submission = json.loads(row["submission"])
            if snapshot.record["specification_digest"] != submission["execution_specification_digest"]:
                raise Conflict("server changed frozen stage identity")
            if ((row["job_id"] is not None and row["job_id"] != snapshot.id)
                    or (row["session_id"] is not None and row["session_id"] != snapshot.record["session_id"])):
                raise Conflict("execution identity changed on reconnect")
            replayed = getattr(snapshot, "replayed", None)
            if replayed is not None and type(replayed) is not bool:
                raise Conflict("invalid submission replay classification")
            self.db.execute("UPDATE checks SET job_id=?,session_id=?,acceptance_replayed=COALESCE(acceptance_replayed,?),phase=CASE WHEN phase='collected' THEN phase ELSE 'identified' END WHERE key=?",
                (snapshot.id, snapshot.record["session_id"], None if replayed is None else int(replayed), key))

    def collected(self, key, evidence):
        encoded = canonical(evidence)
        if len(encoded.encode()) > 256 * 1024:
            raise Unavailable("retained evidence exceeds local journal bound")
        with self.db:
            self.db.execute("UPDATE checks SET phase='collected',evidence=? WHERE key=?", (encoded, key))


class FactoryChecksV1:
    def __init__(self, client: Client, journal: Journal):
        self.client, self.journal = client, journal

    def run_checks(self, submission, source, acceptance, *, retention_until, claim_deadline, require_fresh_receipt=False):
        if type(require_fresh_receipt) is not bool:
            raise ValueError("require_fresh_receipt must be boolean")
        submission = json.loads(canonical(submission))
        deadline = datetime.datetime.fromisoformat(submission["specification"]["deadline"].replace("Z", "+00:00")).timestamp()
        if type(claim_deadline) is not int or deadline >= claim_deadline or deadline <= time.time():
            raise Unavailable("stage deadline must remain within the existing claim")
        self.journal.prepare(submission, source, acceptance, retention_until)
        key = submission["idempotency_key"]
        self.journal.requested(key) # Durable attempt marker before HTTP.
        row = self.journal.get(key)
        try:
            job = self.client.submit_job(json.loads(row["submission"]), row["source"], row["acceptance"], retention_until=row["retention"])
            self.journal.bind(key, job.receipt) # Durable UUID/session before observations.
            if require_fresh_receipt and job.receipt.replayed is not False:
                raise Conflict("pilot requires a fresh acceptance; inspect existing execution")
            snapshot = job.wait(timeout=max(0.001, deadline-time.time()), cleanup=True)
            return self._collect(key, snapshot)
        except (HuskerError, TimeoutError) as error:
            raise Unavailable("uncertain checks execution; inspect the journaled identity") from error

    def inspect(self, key):
        """Read-only reconnect even when the original response never arrived."""
        row = self.journal.get(key)
        submission = json.loads(row["submission"])
        try:
            job = self.client.find_job(key, submission["execution_specification_digest"])
        except NotFound as error:
            raise Unavailable("no retained acceptance found; do not rerun the uncertain stage") from error
        self.journal.bind(key, job.receipt)
        return job.receipt

    def collect(self, key):
        return self._collect(key, self.inspect(key))

    def cancel(self, key):
        snapshot = self.inspect(key)
        submission = json.loads(self.journal.get(key)["submission"])
        return self.client.job(snapshot.id, specification_digest=submission["execution_specification_digest"]).cancel()

    def _collect(self, key, snapshot):
        row = self.journal.get(key)
        submission = json.loads(row["submission"])
        spec = submission["specification"]
        record = snapshot.record
        if (record["state"] not in ("completed", "command_failed") or record["collection"] != "complete"
                or snapshot.cleanup_pending or record.get("vm_destroyed") is not True
                or record.get("vm_id") is None
                or record["output_truncated"]):
            raise Unavailable("checks lack complete sealed evidence and confirmed cleanup")
        try:
            result = json.loads(record["manifest"])
            if (type(result["version"]) is not int or result["version"] != 1 or result["job_id"] != snapshot.id
                    or result["execution_specification_digest"] != submission["execution_specification_digest"]
                    or any(result[name] != spec[name] for name in ("image", "source", "acceptance"))
                    or result["source_changed"] is not False or result["source_verification_error"] is not None
                    or result["collection_status"] != "complete" or result["outcome"] != record["state"]
                    or len(result["commands"]) != len(spec["commands"])):
                raise ValueError("inconsistent sealed manifest")
            results = []
            for index, command in enumerate(result["commands"]):
                code = command["exit_code"]
                if (type(command["command_index"]) is not int or command["command_index"] != index or type(code) is not int or code in (125,126,127,137,143)
                        or command["outcome"] != ("completed" if code == 0 else "command_failed")
                        or command["termination_confirmed"] is not True or command["termination_error"] is not None
                        or command["logs_truncated"] is not False or type(command["duration_ms"]) is not int
                        or command["duration_ms"] < 0 or not isinstance(command["output"], str)
                        or type(command["output_truncated"]) is not bool):
                    raise ValueError("unconfirmed command result")
                results.append(dict(argv=spec["commands"][index]["argv"], exitCode=code,
                    output=command["output"][-1000:], durationMs=command["duration_ms"], backend="husker",
                    job=snapshot.id, session=record["session_id"], image=spec["image"],
                    outputTruncated=command["output_truncated"], logsReference=snapshot.references["events"]))
            if (record["state"] == "completed") != all(item["exitCode"] == 0 for item in results):
                raise ValueError("outcome contradicts commands")
            artifacts = result["artifacts"]
            if len(artifacts) != len(spec["artifacts"]) or len(snapshot.artifacts) != len(artifacts):
                raise ValueError("artifact inventory incomplete")
            job = self.client.job(snapshot.id, specification_digest=submission["execution_specification_digest"])
            retained = []
            artifact_bytes = {}
            for index, (artifact, declaration) in enumerate(zip(artifacts, spec["artifacts"])):
                descriptor = next((item for item in snapshot.artifacts if item["index"] == index), None)
                if (descriptor is None or artifact["error"] is not None or artifact["path"] != declaration["path"]
                        or artifact["stored_name"] != str(index)+".bin" or descriptor["path"] != artifact["path"]
                        or descriptor["digest"] != artifact["digest"] or descriptor["size_bytes"] != artifact["size_bytes"]
                        or descriptor["size_bytes"] > declaration["max_bytes"]):
                    raise ValueError("artifact identity incomplete")
                downloaded = job.artifact(index) # Supported client rechecks bytes/hash/size.
                if downloaded.descriptor != descriptor:
                    raise ValueError("artifact changed during collection")
                retained.append(descriptor)
                artifact_bytes[index] = downloaded.data
        except (KeyError, TypeError, ValueError, HuskerError) as error:
            raise Unavailable("invalid or incomplete check evidence") from error
        identity = dict(jobId=snapshot.id, sessionId=record["session_id"], vmId=record["vm_id"],
            specificationDigest=submission["execution_specification_digest"], idempotencyKey=key,
            references=snapshot.references)
        evidence = dict(contractVersion=1, executionIdentity=identity, results=results,
                        artifactManifest=retained, hostRecord=record)
        self.journal.collected(key, evidence)
        return dict(evidence, artifactBytes=artifact_bytes)
