"""The checks are tested two ways: against the simulated environment, where every planted
weakness must be found, and against hand-written evidence, where each rule is tried on a
good case and a bad case."""

import boto3
import pytest
from moto import mock_aws

from secuguard_grc.checks import CHECKS, run_checks
from secuguard_grc.collectors import COLLECTORS
from secuguard_grc.collectors.base import FRAMEWORKS
from secuguard_grc.evidence import normalize
from secuguard_grc.mock.environment import build_mock_environment
from secuguard_grc.report import render_markdown, render_text

NOW = "2026-11-12T12:00:00Z"


@pytest.fixture(scope="module")
def mock_results():
    with mock_aws():
        session = boto3.Session(aws_access_key_id="mock", aws_secret_access_key="mock", region_name="us-east-1")
        build_mock_environment(session)
        evidence = {c.name: normalize(c.collect(session)) for c in COLLECTORS}
    from secuguard_grc.evidence import utc_now
    results = run_checks(evidence, utc_now(), {"account_id": "123456789012"})
    return {c["id"]: c for c in results["checks"]}, results


def failed(check):
    return [r["resource"] for r in check["results"] if r["status"] == "fail"]


# Every planted weakness, and the check that must catch it.
PLANTED = [
    ("NET-01", "secuguard-planted-open-admin"),
    ("CRY-01", "alias/secuguard-legacy-no-rotation"),
    ("CRY-02", "secuguard-legacy-exports-123456789012"),
    ("CRY-03", "secuguard-legacy-exports-123456789012"),
    ("CRY-04", "legacy-api.secuguard.example"),
    ("CRY-05", "legacy-api.secuguard.example"),
    ("CRY-06", "secuguard-portal"),
    ("IAM-04", "secuguard-dev-alice"),
    ("IAM-05", "secuguard-svc-reports"),
    ("IAM-06", "secuguard-svc-reports"),
    ("IAM-07", "secuguard-legacy-vendor"),
]


@pytest.mark.parametrize("check_id,resource", PLANTED)
def test_planted_weakness_is_found(mock_results, check_id, resource):
    checks, _ = mock_results
    assert any(resource in name for name in failed(checks[check_id])), check_id


def test_healthy_resources_are_not_flagged(mock_results):
    checks, _ = mock_results
    flagged = " ".join(name for check in checks.values() for name in failed(check))
    assert "secuguard-evidence-" not in flagged          # the vault and its key
    assert "alias/secuguard-evidence" not in flagged
    assert "portal.secuguard.example" not in flagged     # the healthy certificate
    assert "secuguard-audit-carol" not in flagged        # the well-behaved user
    assert "secuguard-cde" not in flagged                # the card data zone firewall
    assert checks["NET-02"]["status"] == "pass"
    assert checks["LOG-02"]["status"] == "pass"


def test_no_check_errors_on_complete_evidence(mock_results):
    _, results = mock_results
    assert results["summary"]["error"] == 0


def test_missing_evidence_is_an_error_never_a_pass():
    results = run_checks({}, NOW)
    assert {c["status"] for c in results["checks"]} == {"error"}


def test_failed_collection_is_an_error_never_a_pass():
    evidence = {"iam": {"account_summary": {"collection_error": "AccessDenied"}, "password_policy": None}}
    checks = {c["id"]: c for c in run_checks(evidence, NOW)["checks"]}
    assert checks["IAM-01"]["status"] == "error"
    assert "AccessDenied" in checks["IAM-01"]["note"]
    assert checks["IAM-03"]["status"] == "fail"      # "no policy" was collected, and is a real finding


def user(**changes):
    base = {"name": "u", "has_console_password": False, "mfa_devices": 0, "access_keys": [],
            "attached_policies": [], "groups": []}
    return {**base, **changes}


def grade(evidence, check_id):
    return {c["id"]: c for c in run_checks(evidence, NOW, {"account_id": "111111111111"})["checks"]}[check_id]


def test_access_key_age_rule():
    def key(created, last_used):
        return {"access_key_ending": "ABCD", "status": "Active", "created": created, "last_used": last_used}

    def status(k):
        return grade({"identities": {"users": [user(access_keys=[k])], "roles": []}}, "IAM-06")["status"]

    assert status(key("2026-10-01T00:00:00Z", "2026-11-10T00:00:00Z")) == "pass"
    assert status(key("2026-10-01T00:00:00Z", None)) == "fail"                       # never used
    assert status(key("2026-01-01T00:00:00Z", "2026-11-10T00:00:00Z")) == "fail"     # older than 90 days
    inactive = dict(key("2026-01-01T00:00:00Z", None), status="Inactive")
    assert status(inactive) == "not_applicable"                                       # switched off


def test_certificate_expiry_rule():
    def status(not_after):
        cert = {"domain_name": "x", "parsed": {"key_type": "RSA", "key_bits": 2048, "signature_hash": "sha256",
                                               "not_after": not_after}}
        return grade({"certificates": {"certificates": [cert]}}, "CRY-05")

    assert status("2027-06-01T00:00:00Z")["status"] == "pass"
    assert "expires in 8 days" in status("2026-11-20T12:00:00Z")["results"][0]["detail"]
    assert "expired" in status("2026-11-01T00:00:00Z")["results"][0]["detail"]


def test_certificate_strength_rule():
    def status(**parsed):
        base = {"key_type": "RSA", "key_bits": 2048, "signature_hash": "sha256", "not_after": "2027-06-01T00:00:00Z"}
        cert = {"domain_name": "x", "parsed": {**base, **parsed}}
        return grade({"certificates": {"certificates": [cert]}}, "CRY-04")["status"]

    assert status() == "pass"
    assert status(key_type="EC", key_bits=256) == "pass"
    assert status(key_bits=1024) == "fail"
    assert status(signature_hash="sha1") == "fail"


def test_external_trust_rule():
    def status(statement):
        role = {"name": "r", "path": "/", "trust_policy": {"Statement": [statement]}}
        return grade({"identities": {"users": [], "roles": [role]}}, "IAM-07")["status"]

    outside = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}
    assert status(outside) == "fail"
    assert status({**outside, "Condition": {"StringEquals": {"sts:ExternalId": "abc"}}}) == "pass"
    assert status({**outside, "Principal": {"AWS": "arn:aws:iam::111111111111:root"}}) == "not_applicable"
    assert status({**outside, "Principal": {"Service": "ec2.amazonaws.com"}}) == "not_applicable"
    assert status({**outside, "Principal": "*"}) == "fail"


def test_cde_traffic_rule():
    def group(group_id, scope, rules):
        return {"GroupId": group_id, "GroupName": group_id, "IpPermissions": rules,
                "Tags": [{"Key": "secuguard:pci-scope", "Value": scope}]}

    def status(rule):
        groups = [group("sg-cde", "cde", [rule]), group("sg-shared", "connected", []),
                  group("sg-office", "out-of-scope", [])]
        return grade({"network": {"security_groups": groups, "vpcs": []}}, "NET-02")["status"]

    assert status({"IpProtocol": "tcp", "UserIdGroupPairs": [{"GroupId": "sg-shared"}]}) == "pass"
    assert status({"IpProtocol": "tcp", "UserIdGroupPairs": [{"GroupId": "sg-office"}]}) == "fail"
    assert status({"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "10.20.30.0/24"}]}) == "fail"


def test_every_check_reports_against_all_three_frameworks():
    assert len({c.id for c in CHECKS}) == len(CHECKS)
    for check in CHECKS:
        assert set(check.frameworks) == set(FRAMEWORKS), check.id
        assert all(check.frameworks[key] for key in FRAMEWORKS), check.id


def test_reports_render(mock_results):
    _, results = mock_results
    source = {"account_id": "123456789012", "region": "us-east-1", "mode": "mock"}
    text = render_text(results, "run", source)
    markdown = render_markdown(results, "run", source)
    assert "NET-01  FAIL" in text and "PCI DSS 4.0.1" in text
    assert "| NET-01 | FAIL |" in markdown and "### FedRAMP 20x" in markdown
    rows = list(results["by_framework"]["pci_dss_4_0_1"])
    assert rows.index("3.5.1") < rows.index("10.2.1")     # numeric order, not alphabetical
