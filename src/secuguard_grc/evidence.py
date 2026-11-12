"""Evidence records, run manifests, and integrity verification.

Every collector result is wrapped in an evidence record: who collected it,
from which account, when, with which API calls, plus a SHA-256 hash of the
payload. Each run ends with a manifest that lists every file and its hash and
points at the manifest of the run before it. Change one byte in any file from
any run and verification fails.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
MANIFEST_NAME = "manifest.json"
MANIFEST_HASH_NAME = "manifest.sha256"
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime(_TIME_FORMAT)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime(_TIME_FORMAT)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return str(value)


def normalize(payload: Any) -> Any:
    """Turn an AWS API response into plain JSON types (dates become UTC strings)."""
    return json.loads(json.dumps(payload, default=_json_default))


def canonical_bytes(obj: Any) -> bytes:
    """Stable byte form of a JSON value, so the same data always hashes the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, obj: Any) -> bytes:
    # Bytes, not text mode, so Windows does not rewrite line endings and change the hash.
    data = (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(data)
    return data


class EvidenceRun:
    """One collection run: a folder of evidence files plus a manifest."""

    def __init__(self, output_root: Path | str, source: dict, previous_manifest_sha256: str | None = None):
        now = datetime.now(timezone.utc)
        # Timestamp to the microsecond first, so sorting run folders by name sorts them by
        # time even when two runs start within the same second. The suffix avoids collisions.
        self.run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{now.microsecond:06d}-{uuid.uuid4().hex[:4]}"
        self.run_dir = Path(output_root) / self.run_id
        self.run_dir.mkdir(parents=True)
        self.source = source
        self.started_at = now.strftime(_TIME_FORMAT)
        self.previous_manifest_sha256 = previous_manifest_sha256
        self.files: list[dict] = []
        self.errors: list[dict] = []
        self.manifest_sha256: str | None = None

    def add(self, *, collector: str, description: str, api_calls: list[str],
            relevant_to: dict, payload: Any) -> Path:
        payload = normalize(payload)
        record = {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": str(uuid.uuid4()),
            "run_id": self.run_id,
            "collector": collector,
            "description": description,
            "collected_at": utc_now(),
            "source": self.source,
            "api_calls": api_calls,
            "relevant_to": relevant_to,
            "payload_sha256": sha256_hex(canonical_bytes(payload)),
            "payload": payload,
        }
        path = self.run_dir / f"{collector}.json"
        data = _write_json(path, record)
        self.files.append({
            "path": path.name,
            "collector": collector,
            "sha256": sha256_hex(data),
            "bytes": len(data),
        })
        return path

    def add_error(self, collector: str, message: str) -> None:
        self.errors.append({"collector": collector, "error": message})

    def finalize(self) -> Path:
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": utc_now(),
            "source": self.source,
            "previous_manifest_sha256": self.previous_manifest_sha256,
            "files": self.files,
            "collector_errors": self.errors,
        }
        path = self.run_dir / MANIFEST_NAME
        data = _write_json(path, manifest)
        self.manifest_sha256 = sha256_hex(data)
        (self.run_dir / MANIFEST_HASH_NAME).write_bytes((self.manifest_sha256 + "\n").encode("ascii"))
        return path


def list_runs(output_root: Path | str) -> list[Path]:
    """Run folders under a root, oldest first. Run IDs start with a UTC timestamp down to the microsecond, so name order is time order."""
    root = Path(output_root)
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if (p / MANIFEST_NAME).is_file())


def manifest_sha256(run_dir: Path | str) -> str:
    return sha256_hex((Path(run_dir) / MANIFEST_NAME).read_bytes())


def latest_manifest_sha256(output_root: Path | str) -> str | None:
    runs = list_runs(output_root)
    return manifest_sha256(runs[-1]) if runs else None


def verify_run(run_dir: Path | str) -> list[str]:
    """Recompute every hash in one run. Returns a list of problems; empty means intact."""
    run_dir = Path(run_dir)
    problems: list[str] = []
    manifest_path = run_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"{run_dir.name}: manifest.json is missing"]

    manifest_bytes = manifest_path.read_bytes()
    hash_path = run_dir / MANIFEST_HASH_NAME
    if not hash_path.is_file():
        problems.append(f"{run_dir.name}: manifest.sha256 is missing")
    elif hash_path.read_text(encoding="ascii").strip() != sha256_hex(manifest_bytes):
        problems.append(f"{run_dir.name}: manifest.json does not match manifest.sha256")

    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        return problems + [f"{run_dir.name}: manifest.json is not valid JSON"]

    listed = set()
    for entry in manifest.get("files", []):
        listed.add(entry["path"])
        path = run_dir / entry["path"]
        if not path.is_file():
            problems.append(f"{run_dir.name}/{entry['path']}: listed in the manifest but missing")
            continue
        data = path.read_bytes()
        if sha256_hex(data) != entry["sha256"]:
            problems.append(f"{run_dir.name}/{entry['path']}: file hash does not match the manifest")
            continue
        record = json.loads(data)
        if sha256_hex(canonical_bytes(record["payload"])) != record["payload_sha256"]:
            problems.append(f"{run_dir.name}/{entry['path']}: payload hash does not match the record")

    for path in sorted(run_dir.glob("*.json")):
        if path.name != MANIFEST_NAME and path.name not in listed:
            problems.append(f"{run_dir.name}/{path.name}: present but not listed in the manifest")
    return problems


def verify_chain(output_root: Path | str) -> list[str]:
    """Verify every run under a root and the hash links between consecutive runs."""
    runs = list_runs(output_root)
    problems: list[str] = []
    for run in runs:
        problems.extend(verify_run(run))
    for previous, current in zip(runs, runs[1:]):
        try:
            recorded = json.loads((current / MANIFEST_NAME).read_bytes()).get("previous_manifest_sha256")
        except json.JSONDecodeError:
            continue
        if recorded != manifest_sha256(previous):
            problems.append(
                f"{current.name}: does not link to {previous.name}. "
                "A run was altered, removed, or collected somewhere else."
            )
    return problems
