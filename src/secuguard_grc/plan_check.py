"""A preventive control: judge a Terraform plan before it is applied.

The checks in checks.py are detective. They find a problem after it exists. This module
is preventive. It reads the plan Terraform produces, which lists exactly what would be
created, changed, or deleted, and refuses changes that break a rule. A refused plan is
never applied, so the problem never reaches AWS.

Known, accepted violations are listed in policy/exceptions.json. Each exception names
one resource and one rule, gives a reason, says who approved it, and has an expiry date.
An exception past its expiry date no longer counts.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable

from .checks import ADMIN_PORTS, ANYWHERE, ADMIN_POLICIES, SCOPE_TAG, WEAK_TLS_POLICIES
from .scope import VALID_SCOPES

EXCEPTIONS_FILE = "policy/exceptions.json"
FRAMEWORKS = {
    "pci_dss_4_0_1": ["1.2.2", "6.5.1"],
    "soc_2": ["CC8.1"],
    "fedramp_20x": ["KSI-MLA-EVC", "KSI-CMT-VTD"],
}
VAULT_ADDRESSES = ("aws_s3_bucket.evidence", "aws_s3_bucket_object_lock_configuration.evidence",
                   "aws_s3_bucket_versioning.evidence", "aws_kms_key.evidence")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    run: Callable[[dict, "Plan"], list[str]]


class Plan:
    """A Terraform plan, with helpers for following references between resources."""

    def __init__(self, data: dict):
        self.changes = [c for c in data.get("resource_changes", []) if c.get("mode", "managed") == "managed"]
        self.after_tags = {c["address"]: (c["change"].get("after") or {}).get("tags") or {} for c in self.changes}
        self.by_id, self.prior_tags = {}, {}
        for resource in _walk((data.get("prior_state") or {}).get("values", {}).get("root_module", {})):
            values = resource.get("values") or {}
            if values.get("id"):
                self.by_id[values["id"]] = resource["address"]
            self.prior_tags[resource["address"]] = values.get("tags") or {}
        self.config = {r["address"]: r for r in _walk((data.get("configuration") or {}).get("root_module", {}))}
        self.addresses = set(self.after_tags) | set(self.prior_tags)

    def tags_of_referenced(self, change: dict, attribute: str) -> dict | None:
        """Tags of the resource that `attribute` points at, or None if it cannot be worked out."""
        value = (change["change"].get("after") or {}).get(attribute)
        address = self.by_id.get(value) if value else None
        if address is None:
            config = self.config.get(re.sub(r"\[[^\]]*\]$", "", change["address"]), {})
            for reference in (config.get("expressions", {}).get(attribute) or {}).get("references", []):
                if reference in self.addresses:
                    address = reference
                    break
        if address is None:
            return None
        return self.after_tags.get(address) or self.prior_tags.get(address) or {}


def _walk(module: dict):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []) + [m.get("module", {}) for m in module.get("module_calls", {}).values()]:
        yield from _walk(child)


def _after(change: dict) -> dict:
    return change["change"].get("after") or {}


def _open_admin(sources: set, protocol, low, high) -> list[str]:
    if not sources & ANYWHERE:
        return []
    hit = [f"{name} (port {port})" for port, name in ADMIN_PORTS.items()
           if str(protocol) == "-1" or (low is not None and high is not None and low <= port <= high)]
    return [f"opens {', '.join(hit)} to the whole internet"] if hit else []


def rule_internet_admin(change, plan):
    after = _after(change)
    if change["type"] == "aws_vpc_security_group_ingress_rule":
        return _open_admin({after.get("cidr_ipv4"), after.get("cidr_ipv6")}, after.get("ip_protocol"),
                           after.get("from_port"), after.get("to_port"))
    if change["type"] == "aws_security_group":
        problems = []
        for rule in after.get("ingress") or []:
            problems += _open_admin(set(rule.get("cidr_blocks") or []) | set(rule.get("ipv6_cidr_blocks") or []),
                                    rule.get("protocol"), rule.get("from_port"), rule.get("to_port"))
        return problems
    return []


def rule_cde_ingress(change, plan):
    if change["type"] != "aws_vpc_security_group_ingress_rule":
        return []
    target = plan.tags_of_referenced(change, "security_group_id")
    if target is None or target.get(SCOPE_TAG) != "cde":
        return []
    after = _after(change)
    cidr = after.get("cidr_ipv4") or after.get("cidr_ipv6")
    if cidr:
        return [f"lets address range {cidr} into the card data zone. Only named in-scope groups may be let in."]
    source = plan.tags_of_referenced(change, "referenced_security_group_id")
    if source is None:
        return ["lets a group into the card data zone whose PCI scope cannot be determined from the plan"]
    if source.get(SCOPE_TAG) not in {"cde", "connected"}:
        return [f"lets a group tagged {source.get(SCOPE_TAG) or 'with no scope'} into the card data zone"]
    return []


def rule_scope_tag(change, plan):
    if change["type"] not in {"aws_security_group", "aws_subnet"}:
        return []
    scope = (_after(change).get("tags") or {}).get(SCOPE_TAG)
    return [] if scope in VALID_SCOPES else [f"has no valid {SCOPE_TAG} tag, so its PCI scope is undecided"]


def rule_key_rotation(change, plan):
    if change["type"] != "aws_kms_key":
        return []
    return [] if _after(change).get("enable_key_rotation") is True else ["creates an encryption key with rotation off"]


def rule_public_access(change, plan):
    if change["type"] != "aws_s3_bucket_public_access_block":
        return []
    off = [name for name in ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")
           if _after(change).get(name) is not True]
    return [f"switches off public access protections: {', '.join(off)}"] if off else []


def rule_tls(change, plan):
    if change["type"] != "aws_lb_listener":
        return []
    after = _after(change)
    if after.get("protocol") not in {"HTTPS", "TLS"}:
        return [f"accepts unencrypted {after.get('protocol')} traffic"]
    if after.get("ssl_policy") in WEAK_TLS_POLICIES:
        return [f"uses TLS policy {after.get('ssl_policy')}, which still allows TLS 1.0 or 1.1"]
    return []


def rule_vault(change, plan):
    address = change["address"]
    if not address.startswith(VAULT_ADDRESSES):
        return []
    if "delete" in change["change"]["actions"]:
        return ["would delete or replace part of the evidence vault"]
    after = _after(change)
    if change["type"] == "aws_s3_bucket_object_lock_configuration":
        mode = ((((after.get("rule") or [{}])[0]).get("default_retention") or [{}])[0]).get("mode")
        if mode != "COMPLIANCE":
            return [f"sets the evidence lock mode to {mode}. It must stay COMPLIANCE."]
    if change["type"] == "aws_s3_bucket_versioning":
        status = ((after.get("versioning_configuration") or [{}])[0]).get("status")
        if status != "Enabled":
            return [f"sets evidence versioning to {status}. It must stay Enabled."]
    return []


def rule_direct_admin(change, plan):
    if change["type"] != "aws_iam_user_policy_attachment":
        return []
    name = str(_after(change).get("policy_arn", "")).split("/")[-1]
    return [f"attaches {name} directly to user {_after(change).get('user')}"] if name in ADMIN_POLICIES else []


RULES = [
    Rule("PLAN-01", "No administrative port is opened to the internet", rule_internet_admin),
    Rule("PLAN-02", "Only in-scope groups are let into the card data zone", rule_cde_ingress),
    Rule("PLAN-03", "New network resources declare their PCI scope", rule_scope_tag),
    Rule("PLAN-04", "Encryption keys are created with rotation on", rule_key_rotation),
    Rule("PLAN-05", "Storage keeps its public access protections", rule_public_access),
    Rule("PLAN-06", "Listeners require TLS 1.2 or newer", rule_tls),
    Rule("PLAN-07", "The evidence vault is not weakened or removed", rule_vault),
    Rule("PLAN-08", "Administrator rights are not attached directly to a user", rule_direct_admin),
]


def load_exceptions(path: Path | str = EXCEPTIONS_FILE) -> list[dict]:
    path = Path(path)
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8-sig")).get("exceptions", [])


def evaluate(plan_data: dict, exceptions: list[dict], today: date | None = None) -> dict:
    """Apply every rule to every planned change. Returns violations, accepted exceptions, and counts."""
    today = today or date.today()
    plan = Plan(plan_data)
    violations, accepted, examined = [], [], 0
    for change in plan.changes:
        actions = set(change["change"]["actions"])
        if actions <= {"no-op", "read"}:
            continue
        examined += 1
        for rule in RULES:
            if not (actions & {"create", "update", "delete"}):
                continue
            if actions == {"delete"} and rule.id != "PLAN-07":
                continue
            for problem in rule.run(change, plan):
                finding = {"rule": rule.id, "title": rule.title, "address": change["address"], "problem": problem}
                match = next((e for e in exceptions if e.get("rule") == rule.id
                              and fnmatch.fnmatchcase(change["address"], e.get("address", ""))), None)
                if match and date.fromisoformat(match["expires"]) >= today:
                    accepted.append({**finding, "reason": match.get("reason"),
                                     "approved_by": match.get("approved_by"), "expires": match["expires"]})
                else:
                    if match:
                        finding["problem"] += f" (its exception expired on {match['expires']})"
                    violations.append(finding)
    return {"examined": examined, "violations": violations, "accepted": accepted,
            "allowed": not violations, "frameworks": FRAMEWORKS}


def render(outcome: dict) -> str:
    lines = [f"Examined {outcome['examined']} planned changes against {len(RULES)} rules."]
    if outcome["accepted"]:
        lines += ["", f"Accepted exceptions ({len(outcome['accepted'])}), listed in {EXCEPTIONS_FILE}:"]
        lines += [f"  {a['rule']}  {a['address']}\n           {a['problem']}\n           accepted until {a['expires']}: {a['reason']}"
                  for a in outcome["accepted"]]
    if outcome["violations"]:
        lines += ["", f"BLOCKED. {len(outcome['violations'])} change(s) break a rule:"]
        lines += [f"  {v['rule']}  {v['title']}\n           {v['address']}\n           {v['problem']}"
                  for v in outcome["violations"]]
        lines += ["", "Nothing was applied. Fix the change, or record an approved exception, and run this again."]
    else:
        lines += ["", "ALLOWED. No planned change breaks a rule."]
    return "\n".join(lines)
