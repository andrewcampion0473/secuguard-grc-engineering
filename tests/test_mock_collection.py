import json

import boto3
from moto import mock_aws

from secuguard_grc.cli import main
from secuguard_grc.evidence import list_runs, verify_chain
from secuguard_grc.mock.environment import SCOPE_TAG, build_mock_environment
from secuguard_grc.storage import HEAD_KEY, read_chain_head, upload_run


def load(run_dir, name):
    return json.loads((run_dir / f"{name}.json").read_text())


def test_mock_collect_end_to_end(tmp_path):
    assert main(["collect", "--mock", "--output", str(tmp_path)]) == 0
    assert main(["collect", "--mock", "--output", str(tmp_path)]) == 0
    runs = list_runs(tmp_path)
    assert len(runs) == 2
    assert verify_chain(tmp_path) == []
    assert main(["verify", str(tmp_path)]) == 0

    run = runs[-1]
    manifest = json.loads((run / "manifest.json").read_text())
    assert manifest["collector_errors"] == []
    assert {f["collector"] for f in manifest["files"]} == {
        "network", "kms", "s3", "iam", "identities", "certificates", "loadbalancers", "audit_logging",
        "monitoring", "scope_baseline", "check-results", "ksi-validation"}

    network = load(run, "network")
    assert network["source"]["mode"] == "mock"
    scopes = sorted(
        tag["Value"]
        for subnet in network["payload"]["subnets"]
        for tag in subnet.get("Tags", [])
        if tag["Key"] == SCOPE_TAG
    )
    assert scopes == ["cde", "cde", "connected", "connected", "out-of-scope", "out-of-scope"]

    keys = load(run, "kms")["payload"]["keys"]
    assert sorted(k["rotation"]["KeyRotationEnabled"] for k in keys) == [False, True, True]

    buckets = {b["name"]: b for b in load(run, "s3")["payload"]["buckets"]}
    assert len(buckets) == 3
    bucket = buckets["secuguard-evidence-123456789012"]
    assert bucket["object_lock"]["ObjectLockEnabled"] == "Enabled"
    assert bucket["versioning"]["Status"] == "Enabled"
    assert bucket["public_access_block"]["BlockPublicAcls"] is True

    assert load(run, "iam")["payload"]["password_policy"]["MinimumPasswordLength"] == 14


def test_verify_command_fails_on_tampering(tmp_path):
    main(["collect", "--mock", "--output", str(tmp_path)])
    run = list_runs(tmp_path)[0]
    path = run / "iam.json"
    path.write_text(path.read_text().replace('"MinimumPasswordLength": 14', '"MinimumPasswordLength": 20'))
    assert main(["verify", str(tmp_path)]) == 1


def test_mock_upload_flag(tmp_path):
    assert main(["collect", "--mock", "--upload", "--output", str(tmp_path)]) == 0


@mock_aws
def test_upload_and_chain_head(tmp_path):
    session = boto3.Session(aws_access_key_id="mock", aws_secret_access_key="mock", region_name="us-east-1")
    bucket = build_mock_environment(session)
    s3 = session.client("s3")
    assert read_chain_head(s3, bucket) is None

    from secuguard_grc.evidence import EvidenceRun
    run = EvidenceRun(tmp_path, {"mode": "test"})
    run.add(collector="sample", description="d", api_calls=[], relevant_to={}, payload={"a": 1})
    run.finalize()
    keys = upload_run(s3, bucket, run.run_dir)

    assert keys[-1].endswith("manifest.json")
    assert read_chain_head(s3, bucket) == run.manifest_sha256
    stored = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket)["Contents"]}
    assert stored == set(keys) | {HEAD_KEY}


def test_every_collector_is_labelled_for_all_three_frameworks():
    from secuguard_grc.collectors import COLLECTORS
    from secuguard_grc.collectors.base import FRAMEWORKS

    for collector in COLLECTORS:
        assert set(collector.relevant_to) == set(FRAMEWORKS), collector.name
        assert all(collector.relevant_to[key] for key in FRAMEWORKS), collector.name
