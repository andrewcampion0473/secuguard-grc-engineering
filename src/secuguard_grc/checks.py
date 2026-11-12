"""Checks: read collected evidence and decide pass or fail.

A check never talks to AWS. It reads the evidence files from one run, so the same
evidence can be graded again later, by a different version of a check, or against a
different framework. Each check is written once and reported against PCI DSS, SOC 2,
and FedRAMP 20x.

Statuses:
  pass            every resource the check looked at meets the rule
  fail            at least one resource does not
  not_applicable  there was nothing of that kind to look at
  error           the evidence needed is missing or could not be collected, so no
                  conclusion is drawn. A check never reports pass on evidence it lacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

ADMIN_PORTS = {22: "SSH", 3389: "Remote Desktop"}
ANYWHERE = {"0.0.0.0/0", "::/0"}
SCOPE_TAG = "secuguard:pci-scope"
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
WEAK_SIGNATURE_HASHES = {"md5", "sha1"}
CERT_EXPIRY_WARNING_DAYS = 30
MAX_ACCESS_KEY_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 12
ADMIN_POLICIES = {"AdministratorAccess", "PowerUserAccess", "IAMFullAccess"}
# TLS policies on AWS load balancers that still allow TLS 1.0 or 1.1.
WEAK_TLS_POLICIES = {
    "ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-TLS-1-1-2017-01",
    "ELBSecurityPolicy-FS-2018-06", "ELBSecurityPolicy-FS-1-1-2019-08",
    "ELBSecurityPolicy-TLS13-1-0-2021-06", "ELBSecurityPolicy-TLS13-1-1-2021-06",
    "ELBSecurityPolicy-TLS13-1-0-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-0-FIPS-2023-04", "ELBSecurityPolicy-TLS13-1-1-FIPS-2023-04",
    "ELBSecurityPolicy-TLS13-1-0-FIPS-PQ-2025-09",
}


class MissingEvidence(Exception):
    pass


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    why: str
    severity: str  # high, medium, or low
    frameworks: dict[str, list[str]]
    run: Callable[[dict, datetime], list[dict]]


def _need(evidence: dict, collector: str, key: str):
    """Fetch one part of the evidence, refusing to guess if it is missing or failed."""
    payload = evidence.get(collector)
    if payload is None:
        raise MissingEvidence(f"no evidence from the {collector} collector")
    value = payload.get(key)
    if isinstance(value, dict) and "collection_error" in value:
        raise MissingEvidence(f"{collector}.{key} could not be collected: {value['collection_error']}")
    return value


def _result(resource: str, ok: bool, detail: str) -> dict:
    return {"resource": resource, "status": "pass" if ok else "fail", "detail": detail}


def _tags(resource: dict) -> dict:
    return {t["Key"]: t["Value"] for t in resource.get("Tags", [])}


def _sg_label(group: dict) -> str:
    return f"security group {group.get('GroupName')} ({group.get('GroupId')})"


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- network

def net_admin_ports(evidence, as_of):
    results = []
    for group in _need(evidence, "network", "security_groups"):
        exposed = []
        for rule in group.get("IpPermissions", []):
            sources = {r.get("CidrIp") for r in rule.get("IpRanges", [])} | \
                      {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
            if not sources & ANYWHERE:
                continue
            low, high = rule.get("FromPort"), rule.get("ToPort")
            for port, name in ADMIN_PORTS.items():
                if rule.get("IpProtocol") == "-1" or (low is not None and low <= port <= high):
                    exposed.append(f"{name} (port {port})")
        results.append(_result(
            _sg_label(group), not exposed,
            f"open to the whole internet: {', '.join(exposed)}" if exposed
            else "no administrative port is open to the internet"))
    return results


def net_cde_sources(evidence, as_of):
    groups = _need(evidence, "network", "security_groups")
    scope_by_id = {g["GroupId"]: _tags(g).get(SCOPE_TAG) for g in groups}
    results = []
    for group in groups:
        if _tags(group).get(SCOPE_TAG) != "cde":
            continue
        problems = []
        for rule in group.get("IpPermissions", []):
            for r in rule.get("IpRanges", []) + rule.get("Ipv6Ranges", []):
                problems.append(f"accepts traffic from address range {r.get('CidrIp') or r.get('CidrIpv6')}")
            for pair in rule.get("UserIdGroupPairs", []):
                scope = scope_by_id.get(pair.get("GroupId"))
                if scope not in {"cde", "connected"}:
                    problems.append(f"accepts traffic from {pair.get('GroupId')}, tagged {scope or 'with no scope'}")
        results.append(_result(
            _sg_label(group), not problems,
            "; ".join(problems) if problems else "accepts traffic only from groups tagged cde or connected"))
    return results


def net_default_sg(evidence, as_of):
    return [
        _result(_sg_label(g), not g.get("IpPermissions"),
                "has inbound rules" if g.get("IpPermissions") else "has no inbound rules")
        for g in _need(evidence, "network", "security_groups") if g.get("GroupName") == "default"
    ]


def net_flow_logs(evidence, as_of):
    logged = {log["resource_id"] for log in _need(evidence, "audit_logging", "flow_logs")
              if log.get("status") == "ACTIVE"}
    return [
        _result(f"VPC {_tags(vpc).get('Name') or ('default' if vpc.get('IsDefault') else 'unnamed')} ({vpc['VpcId']})",
                vpc["VpcId"] in logged,
                "flow logs are on" if vpc["VpcId"] in logged else "no flow logs, so network traffic is not recorded")
        for vpc in _need(evidence, "network", "vpcs")
    ]


# ---------------------------------------------------------------- encryption

def cry_key_rotation(evidence, as_of):
    aliases = {}
    for alias in _need(evidence, "kms", "aliases"):
        aliases.setdefault(alias.get("TargetKeyId"), alias.get("AliasName"))
    results = []
    for key in _need(evidence, "kms", "keys"):
        meta = key.get("metadata") or {}
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
            continue
        if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
            continue  # automatic rotation only exists for symmetric keys
        rotation = key.get("rotation")
        if isinstance(rotation, dict) and "collection_error" in rotation:
            raise MissingEvidence(f"rotation status of key {key['key_id']} could not be collected")
        on = bool(rotation and rotation.get("KeyRotationEnabled"))
        label = f"KMS key {aliases.get(key['key_id'], key['key_id'])}"
        results.append(_result(label, on, "rotates automatically" if on else "automatic rotation is off"))
    return results


def cry_bucket_encryption(evidence, as_of):
    results = []
    for bucket in _need(evidence, "s3", "buckets"):
        rules = (bucket.get("encryption") or {}).get("Rules", [])
        default = (rules[0].get("ApplyServerSideEncryptionByDefault") or {}) if rules else {}
        ok = default.get("SSEAlgorithm") in {"aws:kms", "aws:kms:dsse"} and bool(default.get("KMSMasterKeyID"))
        results.append(_result(
            f"bucket {bucket['name']}", ok,
            "encrypted with a key SecuGuard controls" if ok
            else f"not encrypted with a customer managed key (uses {default.get('SSEAlgorithm') or 'the AWS default'})"))
    return results


def cry_bucket_public(evidence, as_of):
    results = []
    for bucket in _need(evidence, "s3", "buckets"):
        block = bucket.get("public_access_block") or {}
        off = [name for name in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
               if not block.get(name)]
        results.append(_result(
            f"bucket {bucket['name']}", not off,
            f"public access protections switched off: {', '.join(off)}" if off
            else "all four public access protections are on"))
    return results


def _certificates(evidence):
    certs = _need(evidence, "certificates", "certificates")
    for cert in certs:
        if not cert.get("parsed"):
            raise MissingEvidence(f"certificate {cert.get('domain_name')} could not be read")
    return certs


def cry_cert_strength(evidence, as_of):
    results = []
    for cert in _certificates(evidence):
        parsed = cert["parsed"]
        minimum = MIN_RSA_BITS if parsed["key_type"] == "RSA" else MIN_EC_BITS
        problems = []
        if not parsed.get("key_bits") or parsed["key_bits"] < minimum:
            problems.append(f"{parsed['key_type']} key of {parsed.get('key_bits')} bits, below the {minimum}-bit minimum")
        if parsed.get("signature_hash") in WEAK_SIGNATURE_HASHES:
            problems.append(f"signed with {parsed['signature_hash'].upper()}, which is broken")
        results.append(_result(
            f"certificate {cert.get('domain_name')}", not problems,
            "; ".join(problems) if problems
            else f"{parsed['key_type']} {parsed['key_bits']}-bit key, signed with {str(parsed.get('signature_hash')).upper()}"))
    return results


def cry_cert_expiry(evidence, as_of):
    results = []
    for cert in _certificates(evidence):
        days = (_parse_time(cert["parsed"]["not_after"]) - as_of).days
        if days < 0:
            ok, detail = False, f"expired {-days} days before this evidence was collected"
        elif days < CERT_EXPIRY_WARNING_DAYS:
            ok, detail = False, f"expires in {days} days, inside the {CERT_EXPIRY_WARNING_DAYS}-day warning window"
        else:
            ok, detail = True, f"valid for another {days} days"
        results.append(_result(f"certificate {cert.get('domain_name')}", ok, detail))
    return results


def cry_tls_policy(evidence, as_of):
    results = []
    for lb in _need(evidence, "loadbalancers", "load_balancers"):
        for listener in lb.get("listeners", []):
            label = f"load balancer {lb['name']} port {listener.get('port')}"
            if listener.get("protocol") not in {"HTTPS", "TLS"}:
                results.append(_result(label, False, f"accepts unencrypted {listener.get('protocol')} traffic"))
            elif listener.get("ssl_policy") in WEAK_TLS_POLICIES:
                results.append(_result(label, False,
                                       f"TLS policy {listener.get('ssl_policy')} still allows TLS 1.0 or 1.1"))
            else:
                results.append(_result(label, True, f"TLS policy {listener.get('ssl_policy')} requires TLS 1.2 or newer"))
    return results


# ---------------------------------------------------------------- identity

def iam_root_mfa(evidence, as_of):
    on = _need(evidence, "iam", "account_summary").get("AccountMFAEnabled") == 1
    return [_result("root user", on, "MFA is on" if on else "MFA is not on")]


def iam_root_keys(evidence, as_of):
    present = _need(evidence, "iam", "account_summary").get("AccountAccessKeysPresent") == 1
    return [_result("root user", not present, "has access keys" if present else "has no access keys")]


def iam_password_policy(evidence, as_of):
    policy = _need(evidence, "iam", "password_policy")
    if policy is None:
        return [_result("account password policy", False, "no password policy is set")]
    problems = []
    if policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
        problems.append(f"minimum length is {policy.get('MinimumPasswordLength')}, below {MIN_PASSWORD_LENGTH}")
    if not (policy.get("RequireNumbers") and (policy.get("RequireLowercaseCharacters")
                                              or policy.get("RequireUppercaseCharacters"))):
        problems.append("does not require both letters and numbers")
    return [_result("account password policy", not problems,
                    "; ".join(problems) if problems
                    else f"minimum length {policy['MinimumPasswordLength']}, letters and numbers required")]


def iam_user_mfa(evidence, as_of):
    return [
        _result(f"user {user['name']}", user["mfa_devices"] > 0,
                "has MFA" if user["mfa_devices"] else "can sign in to the console with a password and no MFA")
        for user in _need(evidence, "identities", "users") if user.get("has_console_password")
    ]


def iam_direct_admin(evidence, as_of):
    results = []
    for user in _need(evidence, "identities", "users"):
        admin = sorted(set(user.get("attached_policies", [])) & ADMIN_POLICIES)
        results.append(_result(
            f"user {user['name']}", not admin,
            f"has {', '.join(admin)} attached directly" if admin else "no administrator policy attached directly"))
    return results


def iam_access_keys(evidence, as_of):
    results = []
    for user in _need(evidence, "identities", "users"):
        for key in user.get("access_keys", []):
            if key.get("status") != "Active":
                continue
            age = (as_of - _parse_time(key["created"])).days
            label = f"user {user['name']} access key ending {key['access_key_ending']}"
            if age > MAX_ACCESS_KEY_AGE_DAYS:
                results.append(_result(label, False, f"{age} days old, past the {MAX_ACCESS_KEY_AGE_DAYS}-day limit"))
            elif not key.get("last_used"):
                results.append(_result(label, False, "active but has never been used"))
            else:
                results.append(_result(label, True, f"{age} days old and in use"))
    return results


def iam_external_trust(evidence, as_of):
    account = evidence.get("_source", {}).get("account_id")
    results = []
    for role in _need(evidence, "identities", "roles"):
        if role.get("path", "/").startswith(("/aws-service-role/", "/aws-reserved/")):
            continue  # roles AWS creates and manages for its own services
        problems, external = [], False
        statements = (role.get("trust_policy") or {}).get("Statement", [])
        for statement in statements if isinstance(statements, list) else [statements]:
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            if principal == "*":
                principals = ["*"]
            else:
                value = (principal or {}).get("AWS", [])
                principals = value if isinstance(value, list) else [value]
            for item in principals:
                if item == "*":
                    external = True
                    problems.append("can be used by any AWS account")
                    continue
                other = item.split(":")[4] if item.startswith("arn:") else item
                if other.isdigit() and other != account:
                    external = True
                    conditions = str(statement.get("Condition", {}))
                    if "sts:ExternalId" not in conditions:
                        problems.append(f"trusts outside account {other} with no external ID")
        if external:
            results.append(_result(f"role {role['name']}", not problems,
                                   "; ".join(problems) if problems else "outside account must present an external ID"))
    return results


# ---------------------------------------------------------------- logging

def log_cloudtrail(evidence, as_of):
    trails = _need(evidence, "audit_logging", "trails")
    good = [t for t in trails if t.get("multi_region") and t.get("is_logging") and t.get("log_file_validation")]
    if good:
        return [_result(f"trail {good[0]['name']}", True,
                        "records every region, is running, and validates its log files")]
    if not trails:
        return [_result("account", False, "no CloudTrail trail exists, so account activity is not being kept")]
    return [_result(f"trail {t['name']}", False, ", ".join(filter(None, [
        None if t.get("multi_region") else "does not cover every region",
        None if t.get("is_logging") else "is not running",
        None if t.get("log_file_validation") else "does not validate its log files",
    ]))) for t in trails]


def log_evidence_immutable(evidence, as_of):
    results = []
    for bucket in _need(evidence, "s3", "buckets"):
        if not bucket["name"].startswith("secuguard-evidence-"):
            continue
        retention = ((bucket.get("object_lock") or {}).get("Rule") or {}).get("DefaultRetention") or {}
        versioned = (bucket.get("versioning") or {}).get("Status") == "Enabled"
        ok = versioned and retention.get("Mode") == "COMPLIANCE"
        results.append(_result(
            f"bucket {bucket['name']}", ok,
            f"versioned, with a {retention.get('Days') or retention.get('Years')}-"
            f"{'day' if retention.get('Days') else 'year'} compliance lock" if ok
            else f"versioning {'on' if versioned else 'off'}, lock mode {retention.get('Mode') or 'none'}"))
    return results


def _fw(pci, soc2, fedramp):
    return {"pci_dss_4_0_1": pci, "soc_2": soc2, "fedramp_20x": fedramp}


CHECKS: list[Check] = [
    Check("NET-01", "No administrative port is open to the internet",
          "SSH and Remote Desktop open to everyone is one of the most common ways attackers get in.",
          "high", _fw(["1.3.1", "1.4.2"], ["CC6.6"], ["KSI-CNA-RNT", "KSI-CNA-MAT"]), net_admin_ports),
    Check("NET-02", "The card data zone accepts traffic only from in-scope systems",
          "Anything allowed to reach the cardholder data environment falls under PCI DSS. Unplanned paths widen scope.",
          "high", _fw(["1.3.1", "1.4.1"], ["CC6.1", "CC6.6"], ["KSI-CNA-ULN", "KSI-CNA-RNT"]), net_cde_sources),
    Check("NET-03", "Default security groups allow nothing",
          "AWS creates a permissive default group in every network. Resources land in it by accident.",
          "medium", _fw(["1.2.1"], ["CC6.6"], ["KSI-CNA-MAT"]), net_default_sg),
    Check("NET-04", "Network traffic is logged",
          "Without flow logs there is no record of who connected to what when investigating an incident.",
          "medium", _fw(["10.2.1"], ["CC7.2"], ["KSI-MLA-LET"]), net_flow_logs),
    Check("CRY-01", "Encryption keys rotate automatically",
          "A key that never changes protects more and more data with one secret. Rotation limits the damage if it leaks.",
          "medium", _fw(["3.7.4"], ["CC6.1"], ["KSI-SVC-ASM"]), cry_key_rotation),
    Check("CRY-02", "Storage is encrypted with keys SecuGuard controls",
          "With its own keys, SecuGuard decides who can decrypt, can see every use of the key, and can revoke access.",
          "medium", _fw(["3.5.1", "3.6.1"], ["CC6.1", "CC6.7"], ["KSI-SVC-SIN"]), cry_bucket_encryption),
    Check("CRY-03", "Storage cannot be made public",
          "Publicly readable storage buckets are a leading cause of cloud data leaks.",
          "high", _fw(["1.4.4"], ["CC6.1", "CC6.6"], ["KSI-CNA-MAT", "KSI-SVC-SIN"]), cry_bucket_public),
    Check("CRY-04", "Certificates use strong keys and signatures",
          "Short keys and outdated signature methods can be broken, letting an attacker impersonate the service.",
          "high", _fw(["4.2.1"], ["CC6.7"], ["KSI-SVC-SIN", "KSI-SVC-VCM"]), cry_cert_strength),
    Check("CRY-05", "No certificate is expired or about to expire",
          "An expired certificate causes an outage, and pushes people to click through security warnings.",
          "high", _fw(["4.2.1", "4.2.1.1"], ["CC6.7"], ["KSI-SVC-ASM"]), cry_cert_expiry),
    Check("CRY-06", "Connections require TLS 1.2 or newer",
          "TLS 1.0 and 1.1 have known weaknesses and are not accepted as strong cryptography.",
          "high", _fw(["4.2.1"], ["CC6.7"], ["KSI-SVC-VCM", "KSI-SVC-SIN"]), cry_tls_policy),
    Check("IAM-01", "The root user has MFA",
          "The root user can do anything, including closing the account. A password alone is not enough protection.",
          "high", _fw(["8.4.1"], ["CC6.1"], ["KSI-IAM-APM"]), iam_root_mfa),
    Check("IAM-02", "The root user has no access keys",
          "A root access key is a permanent, unrestricted credential that cannot be limited.",
          "high", _fw(["8.2.2"], ["CC6.1", "CC6.3"], ["KSI-IAM-ELP"]), iam_root_keys),
    Check("IAM-03", "A strong password policy is set",
          "Without a policy, users can choose short passwords that are easy to guess.",
          "medium", _fw(["8.3.6"], ["CC6.1"], ["KSI-IAM-APM"]), iam_password_policy),
    Check("IAM-04", "Every user who can sign in has MFA",
          "A stolen or guessed password should not be enough to get into the account.",
          "high", _fw(["8.4.2"], ["CC6.1"], ["KSI-IAM-APM"]), iam_user_mfa),
    Check("IAM-05", "No user holds administrator rights directly",
          "Broad rights attached to one user are easy to forget and hard to review. Rights should come from groups or roles.",
          "high", _fw(["7.2.1", "7.2.2"], ["CC6.3"], ["KSI-IAM-ELP"]), iam_direct_admin),
    Check("IAM-06", "Access keys are in use and not stale",
          "Unused and old keys are credentials nobody is watching. They should be removed or replaced.",
          "medium", _fw(["8.2.6", "8.6.3"], ["CC6.2", "CC6.3"], ["KSI-IAM-SNU", "KSI-SVC-ASM"]), iam_access_keys),
    Check("IAM-07", "Outside accounts need an external ID to use a role",
          "Without an external ID, a vendor's other customers could trick the vendor into using this role.",
          "medium", _fw(["7.2.1", "8.2.7"], ["CC6.1", "CC9.2"], ["KSI-IAM-ELP", "KSI-IAM-SNU"]), iam_external_trust),
    Check("LOG-01", "Account activity is recorded and the record is protected",
          "CloudTrail is the record of who did what. Without it, changes cannot be traced after the fact.",
          "high", _fw(["10.2.1", "10.3.4"], ["CC7.2"], ["KSI-MLA-LET", "KSI-CMT-LMC"]), log_cloudtrail),
    Check("LOG-02", "Compliance evidence cannot be altered or deleted",
          "Evidence an administrator can edit proves little. The store must refuse changes from everyone.",
          "high", _fw(["10.3.2", "10.5.1"], ["CC7.2"], ["KSI-SVC-VRI", "KSI-SVC-SIN"]), log_evidence_immutable),
]


def run_checks(evidence: dict, collected_at: str, source: dict | None = None) -> dict:
    """Run every check against one run's evidence. Returns a plain, JSON-ready result."""
    as_of = _parse_time(collected_at)
    evidence = dict(evidence, _source=source or {})
    checks = []
    for check in CHECKS:
        try:
            results = check.run(evidence, as_of)
            if not results:
                status = "not_applicable"
            elif any(r["status"] == "fail" for r in results):
                status = "fail"
            else:
                status = "pass"
            note = None
        except MissingEvidence as missing:
            results, status, note = [], "error", str(missing)
        checks.append({
            "id": check.id, "title": check.title, "why": check.why, "severity": check.severity,
            "status": status, "note": note, "frameworks": check.frameworks, "results": results,
        })
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "fail", "error", "not_applicable")}
    return {"graded_as_of": collected_at, "summary": counts, "checks": checks,
            "by_framework": by_framework(checks)}


def by_framework(checks: list[dict]) -> dict:
    """Turn check results around: for each requirement, which checks speak to it and how they came out."""
    table: dict[str, dict[str, dict]] = {}
    rank = {"fail": 3, "error": 2, "pass": 1, "not_applicable": 0}
    for check in checks:
        for framework, requirements in check["frameworks"].items():
            for requirement in requirements:
                row = table.setdefault(framework, {}).setdefault(requirement, {"status": "not_applicable", "checks": []})
                row["checks"].append(check["id"])
                if rank[check["status"]] > rank[row["status"]]:
                    row["status"] = check["status"]
    return {fw: dict(sorted(rows.items(), key=lambda item: _natural(item[0]))) for fw, rows in sorted(table.items())}


def _natural(requirement: str) -> list:
    """Sort key that puts 3.5.1 before 10.2.1, and leaves names like CC6.1 in order."""
    import re
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", requirement)]
