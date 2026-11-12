"""Command line entry point: secuguard collect | report | verify | test-lock | collectors | checks."""

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
from .checks import run_checks
from .evidence import MANIFEST_NAME, EvidenceRun, latest_manifest_sha256, list_runs, load_run
from .evidence import utc_now, verify_chain, verify_run
from .report import render_markdown, render_text
from .storage import download_runs, read_chain_head, test_lock, upload_run

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
        print(f"  ok      {collector.name:<14}-> {path}")
    results = run_checks(run.payloads, utc_now(), source)
    path = run.add(
        collector="check-results",
        description=(
            "The outcome of every check, graded from the evidence files in this run. Each check "
            "lists the resources it looked at and the requirements it reports against."
        ),
        api_calls=[],
        relevant_to={fw: sorted(rows) for fw, rows in results["by_framework"].items()},
        payload=results,
    )
    summary = results["summary"]
    print(f"  graded  {len(results['checks'])} checks -> {path}")
    print(f"          {summary['pass']} passed, {summary['fail']} failed, {summary['error']} could not be assessed")
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


def _session(args):
    return boto3.Session(profile_name=getattr(args, "profile", None), region_name=getattr(args, "region", None))


def _bucket(args) -> str | None:
    return args.bucket or os.environ.get("SECUGUARD_EVIDENCE_BUCKET")


def cmd_report(args) -> int:
    target = Path(args.path)
    if not (target / MANIFEST_NAME).is_file():
        runs = list_runs(target)
        if not runs:
            print(f"No evidence runs found in {target}. Run 'secuguard collect' first.", file=sys.stderr)
            return 2
        target = runs[-1]
    manifest, payloads = load_run(target)
    results = payloads.pop("check-results", None)
    if results is None or args.regrade:
        # Older runs, or a request to grade again with the current checks.
        results = run_checks(payloads, manifest["started_at"], manifest["source"])
    render = render_markdown if args.markdown else render_text
    print(render(results, manifest["run_id"], manifest["source"]))
    if args.fail_on_findings and (results["summary"]["fail"] or results["summary"]["error"]):
        return 1
    return 0


def cmd_test_lock(args) -> int:
    bucket = _bucket(args)
    if not bucket:
        print("test-lock needs a bucket. Pass --bucket or set SECUGUARD_EVIDENCE_BUCKET.", file=sys.stderr)
        return 2
    try:
        outcome = test_lock(_session(args).client("s3"), bucket)
    except (ClientError, BotoCoreError) as error:
        print(f"Could not run the lock test: {error}", file=sys.stderr)
        return 2
    print(f"Uploaded a marker file to s3://{bucket}/{outcome['key']}")
    print(f"  lock mode     {outcome['lock_mode'] or 'none'}")
    print(f"  locked until  {outcome['locked_until'] or 'not locked'}")
    print("Tried to delete that stored version permanently, asking AWS to bypass the lock.")
    if not outcome["delete_refused"]:
        print("NOT PROTECTED. AWS deleted the file. Evidence in this vault can be removed.")
        return 1
    if outcome["lock_mode"] == "COMPLIANCE":
        print(f"REFUSED ({outcome['error']}). The vault would not delete a locked file, even on request to bypass.")
        return 0
    print(f"REFUSED ({outcome['error']}), but the lock mode is not COMPLIANCE, so this identity may simply lack "
          "permission. An administrator might still be able to delete evidence.")
    return 1


def cmd_verify(args) -> int:
    if getattr(args, "bucket", None) or (args.vault and _bucket(args)):
        import tempfile

        bucket = _bucket(args)
        with tempfile.TemporaryDirectory() as folder:
            try:
                count = download_runs(_session(args).client("s3"), bucket, folder)
            except (ClientError, BotoCoreError) as error:
                print(f"Could not read the vault: {error}", file=sys.stderr)
                return 2
            print(f"Read {count} files from s3://{bucket}/runs/")
            args.bucket, args.vault, args.path = None, False, folder
            return cmd_verify(args)
    if args.vault:
        print("--vault needs a bucket. Pass --bucket or set SECUGUARD_EVIDENCE_BUCKET.", file=sys.stderr)
        return 2
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


def cmd_checks(_args) -> int:
    from .checks import CHECKS

    for check in CHECKS:
        print(f"{check.id}  {check.title}  [{check.severity}]")
        print(f"  {check.why}")
        for framework, requirements in check.frameworks.items():
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
    verify.add_argument("--vault", action="store_true", help="Verify the copy of record in the S3 vault")
    verify.add_argument("--bucket", help="Evidence bucket name (or set SECUGUARD_EVIDENCE_BUCKET)")
    verify.add_argument("--profile", help="AWS CLI profile name")
    verify.add_argument("--region", default=DEFAULT_REGION)
    verify.set_defaults(func=cmd_verify)

    report = commands.add_parser("report", help="Show check results for a run, by check and by framework")
    report.add_argument("path", nargs="?", default=DEFAULT_OUTPUT, help="A run folder or an evidence folder")
    report.add_argument("--markdown", action="store_true", help="Print Markdown, for pasting or publishing")
    report.add_argument("--regrade", action="store_true", help="Grade the evidence again with the current checks")
    report.add_argument("--fail-on-findings", action="store_true", help="Exit with an error if any check fails")
    report.set_defaults(func=cmd_report)

    lock = commands.add_parser("test-lock", help="Prove the vault refuses to delete a locked file")
    lock.add_argument("--bucket", help="Evidence bucket name (or set SECUGUARD_EVIDENCE_BUCKET)")
    lock.add_argument("--profile", help="AWS CLI profile name")
    lock.add_argument("--region", default=DEFAULT_REGION)
    lock.set_defaults(func=cmd_test_lock)

    checks = commands.add_parser("checks", help="List every check and the requirements it reports against")
    checks.set_defaults(func=cmd_checks)

    listing = commands.add_parser("collectors", help="List collectors and what each one gathers")
    listing.set_defaults(func=cmd_collectors)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
