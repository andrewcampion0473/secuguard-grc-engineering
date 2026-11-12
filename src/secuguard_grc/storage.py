"""Copy a finished run into the locked S3 evidence bucket.

The bucket has Object Lock, so once a file lands there it cannot be changed or
deleted until its retention period ends. That is what makes the hashes
trustworthy: someone who edits evidence on a laptop cannot also edit the copy
of record.
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from .evidence import MANIFEST_NAME, manifest_sha256, utc_now

HEAD_KEY = "chain/head.json"


def read_chain_head(s3, bucket: str) -> str | None:
    """Manifest hash of the last run uploaded to the bucket, or None for the first run."""
    try:
        body = s3.get_object(Bucket=bucket, Key=HEAD_KEY)["Body"].read()
    except ClientError as error:
        if error.response["Error"]["Code"] in {"NoSuchKey", "404"}:
            return None
        raise
    return json.loads(body).get("manifest_sha256")


def upload_run(s3, bucket: str, run_dir: Path | str) -> list[str]:
    run_dir = Path(run_dir)
    keys = []
    # Evidence files first, manifest last, so a manifest in S3 always describes files that are there.
    files = sorted(p for p in run_dir.iterdir() if p.is_file() and p.name != MANIFEST_NAME)
    for path in files + [run_dir / MANIFEST_NAME]:
        key = f"runs/{run_dir.name}/{path.name}"
        s3.put_object(Bucket=bucket, Key=key, Body=path.read_bytes(),
                      ContentType="application/json" if path.suffix == ".json" else "text/plain")
        keys.append(key)

    head = {
        "run_id": run_dir.name,
        "manifest_sha256": manifest_sha256(run_dir),
        "updated_at": utc_now(),
    }
    # The bucket is versioned, so every earlier head pointer is kept as an older version.
    s3.put_object(Bucket=bucket, Key=HEAD_KEY, Body=json.dumps(head, indent=2).encode("utf-8"),
                  ContentType="application/json")
    return keys


def download_runs(s3, bucket: str, destination: Path | str) -> int:
    """Copy every run in the vault to a local folder so it can be verified. Returns the file count."""
    destination = Path(destination)
    count = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="runs/"):
        for item in page.get("Contents", []):
            parts = item["Key"].split("/")
            if len(parts) != 3 or not parts[2]:
                continue
            target = destination / parts[1] / parts[2]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(s3.get_object(Bucket=bucket, Key=item["Key"])["Body"].read())
            count += 1
    return count


def test_lock(s3, bucket: str) -> dict:
    """Prove the vault refuses deletion, without touching any evidence.

    Uploads a small marker file, then tries to delete that exact stored version for good,
    asking AWS to bypass a governance lock if it can. A vault in compliance mode refuses.
    """
    key = f"lock-test/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.txt"
    version = s3.put_object(
        Bucket=bucket, Key=key,
        Body=b"SecuGuard lock test. This file exists only to prove that locked files cannot be deleted.\n",
    ).get("VersionId")
    mode = until = None
    try:
        head = s3.head_object(Bucket=bucket, Key=key, VersionId=version)
        mode, until = head.get("ObjectLockMode"), head.get("ObjectLockRetainUntilDate")
    except ClientError:
        pass
    try:
        s3.delete_object(Bucket=bucket, Key=key, VersionId=version, BypassGovernanceRetention=True)
        refused, error = False, None
    except ClientError as failure:
        refused, error = True, failure.response["Error"]["Code"]
    return {
        "key": key, "version_id": version, "lock_mode": mode,
        "locked_until": until.strftime("%Y-%m-%d %H:%M UTC") if until else None, "delete_refused": refused, "error": error,
    }
