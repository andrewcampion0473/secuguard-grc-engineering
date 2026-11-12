import boto3
import pytest
from moto import mock_aws

from secuguard_grc.cli import main
from secuguard_grc.evidence import EvidenceRun, verify_chain
from secuguard_grc.mock.environment import build_mock_environment
from secuguard_grc.storage import download_runs, read_chain_head, test_lock as run_lock_test, upload_run


@pytest.fixture
def vault():
    with mock_aws():
        session = boto3.Session(aws_access_key_id="mock", aws_secret_access_key="mock", region_name="us-east-1")
        yield session.client("s3"), build_mock_environment(session)


def make_run(root, s3, bucket):
    run = EvidenceRun(root, {"mode": "test"}, read_chain_head(s3, bucket))
    run.add(collector="sample", description="d", api_calls=[], relevant_to={}, payload={"a": 1})
    run.finalize()
    upload_run(s3, bucket, run.run_dir)
    return run


def test_vault_chain_downloads_and_verifies(vault, tmp_path):
    s3, bucket = vault
    for _ in range(3):
        make_run(tmp_path / "local", s3, bucket)
    assert download_runs(s3, bucket, tmp_path / "copy") == 9      # 3 runs of 3 files each
    assert verify_chain(tmp_path / "copy") == []


def test_vault_verification_notices_a_missing_file(vault, tmp_path):
    s3, bucket = vault
    run = make_run(tmp_path / "local", s3, bucket)
    s3.delete_object(Bucket=bucket, Key=f"runs/{run.run_id}/sample.json")     # hides the file
    download_runs(s3, bucket, tmp_path / "copy")
    assert any("missing" in problem for problem in verify_chain(tmp_path / "copy"))


def test_lock_test_reports_what_happened(vault):
    s3, bucket = vault
    outcome = run_lock_test(s3, bucket)
    assert outcome["key"].startswith("lock-test/")
    assert outcome["lock_mode"] == "COMPLIANCE"
    assert outcome["delete_refused"] is True


def test_report_command_runs_on_a_practice_collection(tmp_path, capsys):
    assert main(["collect", "--mock", "--output", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["report", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "PCI scope of the network" in out and "Certificate inventory" in out
    assert main(["report", str(tmp_path), "--markdown", "--regrade"]) == 0
    assert "| NET-01 |" in capsys.readouterr().out
    assert main(["report", str(tmp_path), "--fail-on-findings"]) == 1
