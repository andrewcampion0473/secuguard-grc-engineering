"""Copy a finished run into the locked S3 evidence bucket.

The bucket has Object Lock, so once a file lands there it cannot be changed or
deleted until its retention period ends. That is what makes the hashes
trustworthy: someone who edits evidence on a laptop cannot also edit the copy
of record.
"""

from __future__ import annotations

import json
from pathlib import Path

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
