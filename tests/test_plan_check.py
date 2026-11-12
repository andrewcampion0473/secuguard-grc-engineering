"""The plan check is tested against a real plan produced from this project's own Terraform,
and against small hand-written plans that each try one rule."""

import json
from datetime import date
from pathlib import Path

import pytest

from secuguard_grc.plan_check import RULES, evaluate, load_exceptions

ROOT = Path(__file__).parent.parent
TODAY = date(2026, 11, 12)


@pytest.fixture(scope="module")
def fresh_plan():
    return json.loads((ROOT / "tests" / "fixtures" / "plan-fresh.json").read_text())


@pytest.fixture(scope="module")
def exceptions():
    return load_exceptions(ROOT / "policy" / "exceptions.json")


def test_the_projects_own_plan_is_allowed_only_because_of_recorded_exceptions(fresh_plan, exceptions):
    outcome = evaluate(fresh_plan, exceptions, TODAY)
    assert outcome["allowed"] and outcome["violations"] == []
    assert {a["rule"] for a in outcome["accepted"]} == {
        "PLAN-01", "PLAN-02", "PLAN-03", "PLAN-04", "PLAN-05", "PLAN-06", "PLAN-08"}
    assert all("planted" in a["address"] for a in outcome["accepted"])


def test_without_exceptions_every_planted_weakness_is_blocked(fresh_plan):
    outcome = evaluate(fresh_plan, [], TODAY)
    assert not outcome["allowed"]
    assert len(outcome["violations"]) == 7
    assert all("planted" in v["address"] for v in outcome["violations"])     # nothing healthy is blocked


def test_an_expired_exception_stops_counting(fresh_plan, exceptions):
    outcome = evaluate(fresh_plan, exceptions, date(2027, 2, 1))
    assert not outcome["allowed"]
    assert all("expired on 2027-01-31" in v["problem"] for v in outcome["violations"])


def test_every_exception_names_a_real_rule_and_has_the_required_fields(exceptions):
    rule_ids = {rule.id for rule in RULES}
    for entry in exceptions:
        assert entry["rule"] in rule_ids
        assert all(entry.get(field) for field in ("address", "reason", "approved_by", "expires"))
        date.fromisoformat(entry["expires"])


def change(kind, name, after, actions=("create",)):
    return {"address": f"{kind}.{name}", "mode": "managed", "type": kind, "name": name,
            "change": {"actions": list(actions), "after": after}}


def plan(*changes, existing=()):
    resources = [{"address": address, "values": {"id": ident, "tags": tags}} for address, ident, tags in existing]
    return {"resource_changes": list(changes), "prior_state": {"values": {"root_module": {"resources": resources}}}}


CDE = ("aws_security_group.cde", "sg-cde", {"secuguard:pci-scope": "cde"})
SHARED = ("aws_security_group.shared", "sg-shared", {"secuguard:pci-scope": "connected"})
OFFICE = ("aws_security_group.office", "sg-office", {"secuguard:pci-scope": "out-of-scope"})


def blocked_rules(plan_data):
    return [v["rule"] for v in evaluate(plan_data, [], TODAY)["violations"]]


def ingress(**after):
    return change("aws_vpc_security_group_ingress_rule", "r", {"ip_protocol": "tcp", "from_port": 443,
                                                              "to_port": 443, **after})


def test_only_in_scope_groups_may_be_let_into_the_card_data_zone():
    existing = (CDE, SHARED, OFFICE)
    into_cde = {"security_group_id": "sg-cde"}
    assert blocked_rules(plan(ingress(**into_cde, referenced_security_group_id="sg-shared"), existing=existing)) == []
    assert blocked_rules(plan(ingress(**into_cde, referenced_security_group_id="sg-office"), existing=existing)) == ["PLAN-02"]
    assert blocked_rules(plan(ingress(**into_cde, cidr_ipv4="10.20.30.0/24"), existing=existing)) == ["PLAN-02"]
    # The same address range into the office zone is none of this rule's business.
    assert blocked_rules(plan(ingress(security_group_id="sg-office", cidr_ipv4="10.20.30.0/24"), existing=existing)) == []


def test_admin_ports_open_to_the_internet_are_blocked():
    def rule(**after):
        return blocked_rules(plan(ingress(security_group_id="sg-office", **after), existing=(OFFICE,)))

    assert rule(cidr_ipv4="0.0.0.0/0", from_port=22, to_port=22) == ["PLAN-01"]
    assert rule(cidr_ipv4="0.0.0.0/0", from_port=0, to_port=65535) == ["PLAN-01"]
    assert rule(cidr_ipv6="::/0", from_port=3389, to_port=3389) == ["PLAN-01"]
    assert rule(cidr_ipv4="0.0.0.0/0", from_port=443, to_port=443) == []
    assert rule(cidr_ipv4="10.0.0.0/8", from_port=22, to_port=22) == []


def test_the_evidence_vault_cannot_be_weakened_or_removed():
    lock = lambda mode: change("aws_s3_bucket_object_lock_configuration", "evidence",
                               {"rule": [{"default_retention": [{"mode": mode, "days": 1}]}]}, ("update",))
    assert blocked_rules(plan(lock("COMPLIANCE"))) == []
    assert blocked_rules(plan(lock("GOVERNANCE"))) == ["PLAN-07"]
    assert blocked_rules(plan(change("aws_s3_bucket", "evidence", None, ("delete",)))) == ["PLAN-07"]
    assert blocked_rules(plan(change("aws_s3_bucket", "evidence", {}, ("delete", "create")))) == ["PLAN-07"]
    # Deleting something that is not the vault is allowed.
    assert blocked_rules(plan(change("aws_s3_bucket", "scratch", None, ("delete",)))) == []


def test_the_remaining_rules_each_block_their_own_problem():
    assert blocked_rules(plan(change("aws_kms_key", "k", {"enable_key_rotation": False}))) == ["PLAN-04"]
    assert blocked_rules(plan(change("aws_kms_key", "k", {"enable_key_rotation": True}))) == []
    assert blocked_rules(plan(change("aws_security_group", "g", {"tags": {"Name": "g"}}))) == ["PLAN-03"]
    assert blocked_rules(plan(change("aws_security_group", "g", {"tags": {"secuguard:pci-scope": "connected"}}))) == []
    assert blocked_rules(plan(change("aws_lb_listener", "l", {"protocol": "HTTP"}))) == ["PLAN-06"]
    assert blocked_rules(plan(change("aws_lb_listener", "l", {
        "protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"}))) == []
    assert blocked_rules(plan(change("aws_iam_user_policy_attachment", "a", {
        "user": "u", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}))) == ["PLAN-08"]
    all_on = dict.fromkeys(("block_public_acls", "ignore_public_acls", "block_public_policy",
                            "restrict_public_buckets"), True)
    assert blocked_rules(plan(change("aws_s3_bucket_public_access_block", "b", all_on))) == []
    assert blocked_rules(plan(change("aws_s3_bucket_public_access_block", "b", {**all_on, "block_public_policy": False}))) == ["PLAN-05"]


def test_unchanged_resources_are_ignored():
    untouched = change("aws_kms_key", "k", {"enable_key_rotation": False}, ("no-op",))
    outcome = evaluate(plan(untouched), [], TODAY)
    assert outcome["examined"] == 0 and outcome["allowed"]
