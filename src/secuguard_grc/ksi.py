"""FedRAMP 20x: turn check results into a statement about each Key Security Indicator.

FedRAMP 20x asks a cloud provider to show, with machine-readable evidence, that it meets
a set of Key Security Indicators (KSIs). This module takes the indicators FedRAMP
publishes, lines each one up with the checks and evidence in this project, and says
plainly which are validated, which are failing, and which are not covered at all.

The indicator names and statements are FedRAMP's own words, read from data/fedramp_ksi.json.
The format of the output is this project's own. FedRAMP has not been asked to review it.
"""

from __future__ import annotations

import json
from importlib import resources

from .checks import CHECKS
from .plan_check import FRAMEWORKS as PLAN_FRAMEWORKS
from .plan_check import RULES as PLAN_RULES

# For each indicator this project speaks to: what its checks establish, and what they leave out.
# Stating the gap matters as much as stating the coverage.
COVERAGE = {
    "KSI-CNA-RNT": ("Firewall rules are read on every run and checked for administrative ports open to the internet, for what may enter the card data zone, and for routes to the internet.",
                    "Outbound traffic rules, and anything enforced outside AWS security groups and route tables."),
    "KSI-CNA-ULN": ("The network is split into labelled zones, and the labels are compared with the real firewall rules on every run.",
                    "Network controls inside a zone, between systems that share a security group."),
    "KSI-CNA-MAT": ("Default firewall groups, internet-facing administrative ports, public storage settings, and internet routes are checked on every run.",
                    "Software and services running on servers. This environment has no servers."),
    "KSI-CNA-EIS": ("Declared PCI scope is compared with actual connectivity, and Security Hub evaluates the account against a standard.",
                    "Automatic correction. Drift is reported, not reverted."),
    "KSI-IAM-APM": ("Root user MFA, MFA for every user with a console password, and the password policy are checked on every run.",
                    "Whether the MFA in use is phishing-resistant, and identities managed in IAM Identity Center."),
    "KSI-IAM-ELP": ("Users with administrator rights attached directly, root access keys, and roles that outside accounts may use are checked on every run.",
                    "Whether each identity's rights are the minimum its job needs. That takes a review of each policy."),
    "KSI-IAM-SNU": ("Access keys that are unused or older than 90 days, and outside-account trust, are checked on every run.",
                    "Automatic disabling. Stale credentials are reported, not switched off."),
    "KSI-SVC-SIN": ("Storage encryption, public access settings, certificate strength, TLS versions, and the evidence lock are checked on every run.",
                    "Encryption inside applications and databases. This environment has none."),
    "KSI-SVC-ASM": ("Encryption key rotation, certificate expiry, and access key age are checked on every run.",
                    "Secrets held outside AWS KMS, ACM, and IAM, such as passwords in application settings."),
    "KSI-SVC-VCM": ("Certificate key strength, signature method, issuer, and the TLS policy on each listener are checked on every run.",
                    "Connections between systems inside the network, which are not inspected."),
    "KSI-SVC-VRI": ("Every evidence file is hashed, each run is chained to the one before, and the store is locked against change.",
                    "Integrity of deployed software. This environment deploys none."),
    "KSI-MLA-LET": ("CloudTrail and network flow logging are checked on every run, including whether the trail covers every region and validates its files.",
                    "A written list of which event types are logged and why."),
    "KSI-MLA-EVC": ("Every planned Terraform change is tested against rules before it is applied, and Security Hub evaluates the running account.",
                    "Enforcement on every change. The plan check is run by choice on the author's computer until it is wired into GitHub."),
    "KSI-CMT-LMC": ("AWS Config records every change to resources, CloudTrail records who made it, and scope changes are compared with an approved baseline.",
                    "Review of those logs by a person or an alerting system."),
    "KSI-CMT-VTD": ("Planned changes are validated by automated rules before deployment, and the deployed result is checked again on the next run.",
                    "Testing during deployment itself, such as staged rollouts."),
    "KSI-PIY-GIV": ("AWS Config keeps a live inventory of resources, and each run records the network, identities, keys, certificates, and storage directly from AWS.",
                    "Software, data, and anything outside this AWS account and region."),
}


def load_indicators() -> dict:
    with resources.files("secuguard_grc").joinpath("data/fedramp_ksi.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def validate(check_results: dict, evidence_files: list[dict] | None = None) -> dict:
    """Build the indicator-by-indicator validation from one run's check results."""
    catalog = load_indicators()
    results_by_id = {c["id"]: c for c in check_results["checks"]}
    checks_for: dict[str, list[str]] = {}
    for check in CHECKS:
        for indicator in check.frameworks["fedramp_20x"]:
            checks_for.setdefault(indicator, []).append(check.id)
    preventive = {indicator: [rule.id for rule in PLAN_RULES] for indicator in PLAN_FRAMEWORKS["fedramp_20x"]}

    indicators = []
    for ksi_id, info in catalog["indicators"].items():
        check_ids = checks_for.get(ksi_id, [])
        outcomes = [{"check": cid, "title": results_by_id[cid]["title"], "status": results_by_id[cid]["status"],
                     "findings": [f"{r['resource']}: {r['detail']}" for r in results_by_id[cid]["results"]
                                  if r["status"] == "fail"]}
                    for cid in check_ids if cid in results_by_id]
        statuses = {o["status"] for o in outcomes}
        if not outcomes and ksi_id not in preventive:
            status = "not_covered"
        elif "fail" in statuses:
            status = "fail"
        elif "error" in statuses:
            status = "error"
        elif outcomes:
            status = "pass"
        else:
            status = "preventive_only"
        covers, leaves_out = COVERAGE.get(ksi_id, (None, None))
        indicators.append({
            "id": ksi_id, "theme": catalog["themes"].get(info["theme"], info["theme"]), "name": info["name"],
            "statement": info["statement"], "status": status, "checks": outcomes,
            "preventive_rules": preventive.get(ksi_id, []), "covers": covers, "does_not_cover": leaves_out,
        })
    count = {s: sum(1 for i in indicators if i["status"] == s)
             for s in ("pass", "fail", "error", "preventive_only", "not_covered")}
    return {
        "framework": "FedRAMP 20x Key Security Indicators",
        "rules_version": catalog["version"], "rules_source": catalog["source"],
        "graded_as_of": check_results["graded_as_of"],
        "summary": {"total": len(indicators), "addressed": len(indicators) - count["not_covered"], **count},
        "evidence_files": evidence_files or [],
        "indicators": indicators,
    }


WORDS = {"pass": "VALIDATED", "fail": "FAILING", "error": "NO EVIDENCE",
         "preventive_only": "PREVENTIVE", "not_covered": "NOT COVERED"}


def _headline(v: dict) -> str:
    s = v["summary"]
    return (f"{s['addressed']} of {s['total']} indicators addressed: {s['pass']} validated, {s['fail']} failing, "
            f"{s['preventive_only']} covered by a preventive control only, {s['error']} without evidence. "
            f"{s['not_covered']} not covered.")


def render_text(v: dict) -> str:
    lines = [f"FedRAMP 20x Key Security Indicators, rules version {v['rules_version']}",
             f"Evidence collected {v['graded_as_of']}", "", _headline(v), "",
             f"{'Indicator':<14}{'Status':<14}Name", "-" * 96]
    for ind in v["indicators"]:
        if ind["status"] == "not_covered":
            continue
        lines.append(f"{ind['id']:<14}{WORDS[ind['status']]:<14}{ind['name']}")
        for outcome in ind["checks"]:
            lines.append(f"{'':<14}  {outcome['check']} {outcome['status'].upper():<5} {outcome['title']}")
        if ind["preventive_rules"]:
            lines.append(f"{'':<14}  plan check: {len(ind['preventive_rules'])} rules applied before any change")
    missing = [f"{i['id']} {i['name']}" for i in v["indicators"] if i["status"] == "not_covered"]
    lines += ["", f"Not covered by this project ({len(missing)}):"] + [f"  {m}" for m in missing]
    return "\n".join(lines)


def render_markdown(v: dict) -> str:
    out = ["# FedRAMP 20x Key Security Indicator validation", "",
           f"Rules version {v['rules_version']}. Evidence collected {v['graded_as_of']}.", "",
           f"**{_headline(v)}**", "",
           "Indicator names and statements are FedRAMP's own text. The validation format is this project's own.", "",
           "| Indicator | Status | Name | Checks |", "|---|---|---|---|"]
    for ind in v["indicators"]:
        if ind["status"] != "not_covered":
            checks = ", ".join(f"{o['check']} ({o['status']})" for o in ind["checks"]) or "plan check rules"
            out.append(f"| {ind['id']} | {WORDS[ind['status']]} | {ind['name']} | {checks} |")
    out += ["", "## Detail", ""]
    for ind in v["indicators"]:
        if ind["status"] == "not_covered":
            continue
        out += [f"### {ind['id']}: {ind['name']} ({WORDS[ind['status']]})", "", f"> {ind['statement']}", "",
                f"**What this project establishes.** {ind['covers']}", "",
                f"**What it does not establish.** {ind['does_not_cover']}", ""]
        for outcome in ind["checks"]:
            out.append(f"- {outcome['check']} {outcome['status'].upper()}: {outcome['title']}")
            out += [f"    - {finding}" for finding in outcome["findings"]]
        if ind["preventive_rules"]:
            out.append(f"- Plan check: {', '.join(ind['preventive_rules'])} applied to every planned change")
        out.append("")
    out += ["## Not covered", "", "These indicators need evidence this project does not collect, such as policies, "
            "training records, incident response, recovery testing, and supplier reviews.", "",
            "| Indicator | Theme | Name |", "|---|---|---|"]
    out += [f"| {i['id']} | {i['theme']} | {i['name']} |" for i in v["indicators"] if i["status"] == "not_covered"]
    return "\n".join(out) + "\n"
