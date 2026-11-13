"""Turn check results into something a person can read: a terminal table or Markdown."""

from __future__ import annotations

from .checks import _natural

FRAMEWORK_NAMES = {
    "pci_dss_4_0_1": "PCI DSS 4.0.1",
    "soc_2": "SOC 2",
    "fedramp_20x": "FedRAMP 20x",
}
WORDS = {"pass": "PASS", "fail": "FAIL", "error": "NO EVIDENCE", "not_applicable": "N/A"}


def _ordered(rows: dict) -> list:
    """Requirements in reading order: 2.2.1 before 10.2.1. Results saved to disk come back alphabetical."""
    return sorted(rows.items(), key=lambda item: _natural(item[0]))


def _summary_line(summary: dict) -> str:
    return (f"{summary['pass']} passed, {summary['fail']} failed, "
            f"{summary['error']} could not be assessed, {summary['not_applicable']} not applicable")


def render_text(results: dict, run_id: str, source: dict) -> str:
    lines = [
        f"SecuGuard check results for run {run_id}",
        f"Account {source.get('account_id')} in {source.get('region')} ({source.get('mode')} mode), "
        f"evidence collected {results['graded_as_of']}",
        "",
        _summary_line(results["summary"]),
        "",
        f"{'Check':<8}{'Result':<13}{'Severity':<10}What was checked",
        "-" * 96,
    ]
    for check in results["checks"]:
        lines.append(f"{check['id']:<8}{WORDS[check['status']]:<13}{check['severity']:<10}{check['title']}")
        if check["status"] == "error":
            lines.append(f"{'':<8}  ! {check['note']}")
        for result in check["results"]:
            if result["status"] == "fail":
                lines.append(f"{'':<8}  x {result['resource']}: {result['detail']}")
    inv = results.get("inventories") or {}
    if inv.get("scope"):
        lines += ["", "PCI scope of the network", "-" * 96,
                  f"{'Kind':<16}{'Name':<34}{'Declared':<15}{'Actually':<15}"]
        for item in inv["scope"]:
            flag = "  <-- mismatch" if item["effective"] == "connected" and item["declared"] not in {"cde", "connected"} else ""
            lines.append(f"{item['kind']:<16}{item['name']:<34}{str(item['declared'] or 'not declared'):<15}"
                         f"{item['effective']:<15}{flag}")
    if inv.get("certificates"):
        lines += ["", "Certificate inventory", "-" * 96,
                  f"{'Name':<32}{'Issuer':<14}{'Key':<10}{'Expires':<12}In use by"]
        for cert in inv["certificates"]:
            issuer = cert["issuer"] if cert["issuer"] == "self-signed" else "CA-issued"
            lines.append(f"{str(cert['name']):<32}{issuer:<14}{cert['key']:<10}{cert['expires']:<12}"
                         f"{', '.join(cert['in_use_by']) or 'nothing'}")
    lines += ["", "The same results, by framework", "-" * 96]
    for framework, rows in results["by_framework"].items():
        lines.append(FRAMEWORK_NAMES.get(framework, framework))
        for requirement, row in _ordered(rows):
            lines.append(f"  {requirement:<14}{WORDS[row['status']]:<13}{', '.join(row['checks'])}")
        lines.append("")
    return "\n".join(lines)


def render_markdown(results: dict, run_id: str, source: dict) -> str:
    out = [
        "# SecuGuard check results",
        "",
        f"Run `{run_id}`. Account `{source.get('account_id')}` in `{source.get('region')}` "
        f"({source.get('mode')} mode). Evidence collected {results['graded_as_of']}.",
        "",
        f"**{_summary_line(results['summary'])}.**",
        "",
        "## Checks",
        "",
        "| Check | Result | Severity | What was checked | PCI DSS | SOC 2 | FedRAMP 20x |",
        "|---|---|---|---|---|---|---|",
    ]
    for check in results["checks"]:
        fw = check["frameworks"]
        out.append(
            f"| {check['id']} | {WORDS[check['status']]} | {check['severity']} | {check['title']} | "
            f"{', '.join(fw['pci_dss_4_0_1'])} | {', '.join(fw['soc_2'])} | {', '.join(fw['fedramp_20x'])} |")
    failing = [c for c in results["checks"] if c["status"] in {"fail", "error"}]
    if failing:
        out += ["", "## Findings", ""]
        for check in failing:
            out.append(f"**{check['id']}: {check['title']}.** {check['why']}")
            out.append("")
            if check["status"] == "error":
                out.append(f"- Could not be assessed: {check['note']}")
            for result in check["results"]:
                if result["status"] == "fail":
                    out.append(f"- {result['resource']}: {result['detail']}")
            out.append("")
    inv = results.get("inventories") or {}
    if inv.get("scope"):
        out += ["## PCI scope of the network", "",
                "What each part of the network is declared to be, and what the firewall rules make it.", "",
                "| Kind | Name | Declared | Actually | Reaches the card data zone by |", "|---|---|---|---|---|"]
        out += [f"| {i['kind']} | {i['name']} | {i['declared'] or 'not declared'} | {i['effective']} | "
                f"{'; '.join(i['reaches_cde_by'])} |" for i in inv["scope"]]
        out.append("")
    if inv.get("certificates"):
        out += ["## Certificate inventory", "",
                "| Name | Issuer | Key | Signature | Expires | In use by |", "|---|---|---|---|---|---|"]
        out += [f"| {c['name']} | {c['issuer']} | {c['key']} | {c['signature']} | {c['expires']} | "
                f"{', '.join(c['in_use_by']) or 'nothing'} |" for c in inv["certificates"]]
        out.append("")
    out += ["## By framework", ""]
    for framework, rows in results["by_framework"].items():
        out += [f"### {FRAMEWORK_NAMES.get(framework, framework)}", "",
                "| Requirement | Result | Checks |", "|---|---|---|"]
        out += [f"| {req} | {WORDS[row['status']]} | {', '.join(row['checks'])} |" for req, row in _ordered(rows)]
        out.append("")
    return "\n".join(out)
