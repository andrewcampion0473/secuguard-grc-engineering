"""Turn check results into something a person can read: a terminal table or Markdown."""

from __future__ import annotations

FRAMEWORK_NAMES = {
    "pci_dss_4_0_1": "PCI DSS 4.0.1",
    "soc_2": "SOC 2",
    "fedramp_20x": "FedRAMP 20x",
}
WORDS = {"pass": "PASS", "fail": "FAIL", "error": "NO EVIDENCE", "not_applicable": "N/A"}


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
    lines += ["", "The same results, by framework", "-" * 96]
    for framework, rows in results["by_framework"].items():
        lines.append(FRAMEWORK_NAMES.get(framework, framework))
        for requirement, row in rows.items():
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
    out += ["## By framework", ""]
    for framework, rows in results["by_framework"].items():
        out += [f"### {FRAMEWORK_NAMES.get(framework, framework)}", "",
                "| Requirement | Result | Checks |", "|---|---|---|"]
        out += [f"| {req} | {WORDS[row['status']]} | {', '.join(row['checks'])} |" for req, row in rows.items()]
        out.append("")
    return "\n".join(out)
