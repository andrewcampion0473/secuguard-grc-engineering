"""Command line entry point: secuguard collect | verify | collectors."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .collectors import COLLECTORS
from .collectors.base import FRAMEWORKS
from .evidence import EvidenceRun, latest_manifest_sha256, list_runs, verify_chain, verify_run
from .evidence import MANIFEST_NAME
from .storage import read_chain_head, upload_run

DEFAULT_REGION = "us-east-1"
DEFAULT_OUTPUT = "evidence"


def _run_collection(session, mode: str, output: Path, bucket: str | None) -> int:
    identity = session.client("sts").get_caller_identity()
    source = {
        "mode": mode,
        "account_id": identity["Account"],
        "region": session.region_name,
        "collected_by": identity["Arn"],
        "tool_version": __version__,
    }
    s3 = session.client("s3") if bucket else None
    previous = read_chain_head(s3, bucket) if bucket else None
    if previous is None:
        previous = latest_manifest_sha256(output)

    run = EvidenceRun(output, source, previous)
    print(f"Run {run.run_id}  ({mode} mode, account {source['account_id']}, {source['region']})")
    for collector in COLLECTORS:
        try:
            payload = collector.collect(session)
        except (ClientError, BotoCoreError) as error:
            run.add_error(collector.name, str(error))
            print(f"  FAILED  {collector.name}: {error}")
            continue
        path = run.add(
            collector=collector.name,
            description=collector.description,
            api_calls=collector.api_calls,
            relevant_to=collector.relevant_to,
            payload=payload,
        )
        print(f"  ok      {collector.name:<8} -> {path}")
    run.finalize()
    print(f"Manifest {run.run_dir / MANIFEST_NAME}")
    print(f"  sha256   {run.manifest_sha256}")
    print(f"  previous {run.previous_manifest_sha256 or 'none (first run in this chain)'}")

    if bucket:
        keys = upload_run(s3, bucket, run.run_dir)
        print(f"Uploaded {len(keys)} files to s3://{bucket}/runs/{run.run_id}/")
    return 1 if run.errors else 0


def cmd_collect(args) -> int:
    output = Path(args.output)
    if args.mock:
        from moto import mock_aws

        from .mock.environment import build_mock_environment

        # Remove anything that could point boto3 at a real account.
        for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
            os.environ.pop(name, None)
        with mock_aws():
            session = boto3.Session(
                aws_access_key_id="mock", aws_secret_access_key="mock", region_name=args.region
            )
            mock_bucket = build_mock_environment(session)
            return _run_collection(session, "mock", output, mock_bucket if args.upload else None)

    bucket = args.bucket or os.environ.get("SECUGUARD_EVIDENCE_BUCKET")
    if args.upload and not bucket:
        print("--upload needs a bucket. Pass --bucket or set SECUGUARD_EVIDENCE_BUCKET.", file=sys.stderr)
        return 2
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        return _run_collection(session, "aws", output, bucket if args.upload else None)
    except (ClientError, BotoCoreError) as error:
        print(f"Could not reach AWS: {error}", file=sys.stderr)
        print("If you use SSO, run 'aws sso login --profile <your profile>' and try again.", file=sys.stderr)
        return 2


def cmd_verify(args) -> int:
    target = Path(args.path)
    if (target / MANIFEST_NAME).is_file():
        runs, problems = [target], verify_run(target)
    else:
        runs, problems = list_runs(target), verify_chain(target)
    if not runs:
        print(f"No evidence runs found in {target}", file=sys.stderr)
        return 2
    if problems:
        print(f"TAMPERING OR DAMAGE DETECTED in {len(runs)} run(s) checked:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"OK. {len(runs)} run(s) verified. Every file matches its recorded hash"
          + (" and every run links to the one before it." if len(runs) > 1 else "."))
    return 0


def cmd_collectors(_args) -> int:
    print("Frameworks:")
    for key, name in FRAMEWORKS.items():
        print(f"  {key}: {name}")
    print()
    for collector in COLLECTORS:
        print(f"{collector.name}\n  {collector.description}")
        print(f"  API calls: {', '.join(collector.api_calls)}")
        for framework, requirements in collector.relevant_to.items():
            print(f"  {framework}: {', '.join(requirements)}")
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secuguard",
        description="Collect and verify compliance evidence for SecuGuard (a fictional company).",
    )
    parser.add_argument("--version", action="version", version=f"secuguard {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    collect = commands.add_parser("collect", help="Collect evidence from AWS or from the mock environment")
    collect.add_argument("--mock", action="store_true", help="Use the simulated environment. No AWS account needed.")
    collect.add_argument("--profile", help="AWS CLI profile name (real mode)")
    collect.add_argument("--region", default=DEFAULT_REGION, help=f"AWS region (default {DEFAULT_REGION})")
    collect.add_argument("--output", default=DEFAULT_OUTPUT, help=f"Local evidence folder (default {DEFAULT_OUTPUT}/)")
    collect.add_argument("--upload", action="store_true", help="Also copy the run to the locked S3 evidence bucket")
    collect.add_argument("--bucket", help="Evidence bucket name (or set SECUGUARD_EVIDENCE_BUCKET)")
    collect.set_defaults(func=cmd_collect)

    verify = commands.add_parser("verify", help="Recompute hashes for one run folder or a whole evidence folder")
    verify.add_argument("path", nargs="?", default=DEFAULT_OUTPUT)
    verify.set_defaults(func=cmd_verify)

    listing = commands.add_parser("collectors", help="List collectors and what each one gathers")
    listing.set_defaults(func=cmd_collectors)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
