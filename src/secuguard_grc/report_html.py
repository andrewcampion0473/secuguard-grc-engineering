"""One self-contained web page that shows a run's results to someone who will never open a terminal.

The page needs no internet connection: styles and the small script are inside the file, and it
loads nothing from anywhere else. Every value that came from AWS is escaped before it is written.
"""

from __future__ import annotations

from html import escape

from .checks import _natural
from .ksi import WORDS as KSI_WORDS
from .report import FRAMEWORK_NAMES, WORDS

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_CLASS = {"pass": "ok", "fail": "bad", "error": "warn", "not_applicable": "na",
                "preventive_only": "info", "not_covered": "na"}

CSS = """
:root{--bg:#f6f5f1;--card:#ffffff;--ink:#1c2430;--muted:#5d6878;--line:#dedbd2;--accent:#1f4e79;
--ok:#1e6b45;--ok-bg:#e3f1e8;--bad:#a12a22;--bad-bg:#f8e4e1;--warn:#8a5a00;--warn-bg:#f8ecd2;
--na:#5d6878;--na-bg:#eceae4;--info:#1f4e79;--info-bg:#e1ebf5}
@media (prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1a2029;--ink:#e8ebf0;--muted:#9aa5b5;
--line:#2c3542;--accent:#8fb8e0;--ok:#7fd3a4;--ok-bg:#173526;--bad:#f09a92;--bad-bg:#40201d;
--warn:#e9c06a;--warn-bg:#3b2f14;--na:#9aa5b5;--na-bg:#252d39;--info:#8fb8e0;--info-bg:#1b2c40}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 64px}
header{padding:40px 0 20px}
.eyebrow{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0 0 6px}
h1{font-size:34px;line-height:1.2;margin:0 0 10px;letter-spacing:-.01em}
h2{font-size:23px;margin:48px 0 6px}
h3{font-size:17px;margin:0 0 4px}
p{margin:0 0 12px}
.lede{color:var(--muted);max-width:70ch}
.meta{color:var(--muted);font-size:14px}
code,.mono{font-family:Consolas,"Cascadia Mono",Menlo,monospace;font-size:.88em;overflow-wrap:anywhere}
nav{display:flex;flex-wrap:wrap;gap:6px 18px;padding:12px 0;border-top:1px solid var(--line);
border-bottom:1px solid var(--line);font-size:14px}
a{color:var(--accent)}
nav a{text-decoration:none}
nav a:hover{text-decoration:underline}
.banner{margin:20px 0 0;padding:12px 16px;border-radius:8px;border-left:5px solid;font-size:15px}
.banner.ok{background:var(--ok-bg);border-color:var(--ok)}
.banner.bad{background:var(--bad-bg);border-color:var(--bad)}
.banner ul{margin:6px 0 0;padding-left:20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;margin:20px 0 0}
.tile,.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.tile .label{font-size:13px;color:var(--muted);margin:0 0 2px}
.tile .big{font-size:30px;font-weight:650;line-height:1.15;font-variant-numeric:tabular-nums}
.tile .big small{font-size:15px;font-weight:400;color:var(--muted)}
.tile .sub{font-size:13px;color:var(--muted);margin:6px 0 0}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--na-bg);margin:10px 0 0;gap:2px}
.bar span{display:block}
.bar .ok{background:var(--ok)}.bar .bad{background:var(--bad)}.bar .warn{background:var(--warn)}
.bar .info{background:var(--info)}.bar .na{background:var(--na);opacity:.45}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:650;
letter-spacing:.03em;white-space:nowrap;border:1px solid transparent}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.bad{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.na{background:var(--na-bg);color:var(--na)}
.pill.info{background:var(--info-bg);color:var(--info)}
.pill.sev{background:transparent;border-color:var(--line);color:var(--muted);font-weight:500}
.card{margin:12px 0 0}
.card .head{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 10px}
.card .id{font-weight:650;font-variant-numeric:tabular-nums}
.card ul{margin:8px 0 0;padding-left:20px}
.card li{margin:2px 0}
.refs{font-size:13px;color:var(--muted);margin:10px 0 0}
.why{color:var(--muted);margin:4px 0 0}
.scroll{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px;margin:12px 0 0}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th,td{text-align:left;padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}
tr.flag td{background:var(--bad-bg)}
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 0}
.tabs button{font:inherit;font-size:14.5px;padding:7px 14px;border-radius:8px;border:1px solid var(--line);
background:var(--card);color:var(--ink);cursor:pointer}
.tabs button[aria-selected=true]{background:var(--accent);border-color:var(--accent);color:var(--bg)}
.panel h3{margin:22px 0 0}
.js .panel h3{display:none}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0 0;padding:0 18px}
summary{cursor:pointer;padding:12px 0;display:flex;flex-wrap:wrap;gap:6px 10px;align-items:baseline}
summary .name{font-weight:600}
details[open]{padding-bottom:14px}
blockquote{margin:6px 0 12px;padding:2px 14px;border-left:3px solid var(--line);color:var(--muted)}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:4px 24px}
.two p{margin:0 0 8px}
footer{margin:56px 0 0;padding:18px 0 0;border-top:1px solid var(--line);color:var(--muted);font-size:13.5px}
@media print{body{background:#fff}nav,.tabs{display:none}.js .panel{display:block!important}
.js .panel h3{display:block}.card,.tile,details,.scroll{break-inside:avoid}}
"""

SCRIPT = """
document.documentElement.classList.add('js');
var buttons=document.querySelectorAll('.tabs button'),panels=document.querySelectorAll('.panel');
function show(id){panels.forEach(function(p){p.style.display=p.id===id?'block':'none'});
buttons.forEach(function(b){b.setAttribute('aria-selected',b.dataset.panel===id?'true':'false')})}
buttons.forEach(function(b){b.addEventListener('click',function(){show(b.dataset.panel)})});
if(buttons.length){show(buttons[0].dataset.panel)}
"""


def _frameworks_in_order(by_framework: dict) -> list:
    """PCI DSS, SOC 2, FedRAMP 20x, in that order. Results saved to disk come back alphabetical."""
    order = list(FRAMEWORK_NAMES)
    return sorted(by_framework.items(), key=lambda item: order.index(item[0]) if item[0] in order else len(order))


def e(value) -> str:
    return escape("" if value is None else str(value))


def _pill(status: str, words: dict = WORDS) -> str:
    return f'<span class="pill {STATUS_CLASS.get(status, "na")}">{e(words.get(status, status))}</span>'


def _bar(parts: list[tuple[str, int]]) -> str:
    total = sum(count for _, count in parts) or 1
    spans = "".join(f'<span class="{cls}" style="width:{count / total * 100:.2f}%"></span>'
                    for cls, count in parts if count)
    return f'<div class="bar" aria-hidden="true">{spans}</div>'


def _table(headers: list[str], rows: list[str]) -> str:
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _refs(frameworks: dict) -> str:
    parts = [f"{e(FRAMEWORK_NAMES.get(fw, fw))}: {e(', '.join(reqs))}" for fw, reqs in frameworks.items() if reqs]
    return f'<p class="refs">{" &nbsp;|&nbsp; ".join(parts)}</p>'


def _tiles(results: dict, validation: dict) -> str:
    s = results["summary"]
    total = len(results["checks"])
    out = [
        '<div class="tile"><p class="label">Checks</p>'
        f'<div class="big">{s["pass"]} <small>of {total} passing</small></div>'
        + _bar([("ok", s["pass"]), ("bad", s["fail"]), ("warn", s["error"]), ("na", s["not_applicable"])])
        + f'<p class="sub">{s["fail"]} failing, {s["error"]} without evidence, {s["not_applicable"]} not applicable</p></div>'
    ]
    for framework, rows in _frameworks_in_order(results["by_framework"]):
        met = sum(1 for row in rows.values() if row["status"] == "pass")
        failing = sum(1 for row in rows.values() if row["status"] == "fail")
        other = len(rows) - met - failing
        out.append(
            f'<div class="tile"><p class="label">{e(FRAMEWORK_NAMES.get(framework, framework))}</p>'
            f'<div class="big">{met} <small>of {len(rows)} requirements met</small></div>'
            + _bar([("ok", met), ("bad", failing), ("warn", other)])
            + f'<p class="sub">Counts only the requirements this project tests</p></div>')
    return f'<div class="tiles">{"".join(out)}</div>'


def _integrity(manifest: dict, manifest_sha256: str | None, problems: list[str]) -> str:
    count = len(manifest["files"])
    if problems:
        items = "".join(f"<li>{e(p)}</li>" for p in problems)
        return ('<div class="banner bad"><strong>Evidence failed verification.</strong> At least one file does not '
                f'match its recorded fingerprint, so these results should not be relied on.<ul>{items}</ul></div>')
    linked = ("This run is linked to the run before it."
              if manifest.get("previous_manifest_sha256") else "This is the first run in its chain.")
    return ('<div class="banner ok"><strong>Evidence verified.</strong> '
            f'All {count} evidence files matched their recorded fingerprints when this page was made. {linked} '
            f'Run fingerprint: <code>{e(manifest_sha256 or "not recorded")}</code></div>')


def _findings(results: dict) -> str:
    failing = [c for c in results["checks"] if c["status"] in {"fail", "error"}]
    if not failing:
        return '<div class="card">Nothing to fix. Every check passed.</div>'
    failing.sort(key=lambda c: (SEVERITY_ORDER.get(c["severity"], 9), _natural(c["id"])))
    cards = []
    for check in failing:
        items = [f"<li>Could not be assessed: {e(check['note'])}</li>"] if check["status"] == "error" else []
        items += [f"<li><strong>{e(r['resource'])}</strong>: {e(r['detail'])}</li>"
                  for r in check["results"] if r["status"] == "fail"]
        cards.append(
            f'<div class="card"><div class="head"><span class="id">{e(check["id"])}</span>'
            f'<h3>{e(check["title"])}</h3>{_pill(check["status"])}'
            f'<span class="pill sev">{e(check["severity"])} severity</span></div>'
            f'<p class="why">{e(check["why"])}</p><ul>{"".join(items)}</ul>{_refs(check["frameworks"])}</div>')
    return "".join(cards)


def _frameworks(results: dict) -> str:
    titles = {c["id"]: c["title"] for c in results["checks"]}
    buttons, panels = [], []
    for framework, rows in _frameworks_in_order(results["by_framework"]):
        name = FRAMEWORK_NAMES.get(framework, framework)
        buttons.append(f'<button type="button" data-panel="fw-{e(framework)}">{e(name)}</button>')
        body = []
        for requirement, row in sorted(rows.items(), key=lambda item: _natural(item[0])):
            checks = "<br>".join(f'<span class="mono">{e(cid)}</span> {e(titles.get(cid, ""))}' for cid in row["checks"])
            body.append(f'<tr><td class="mono">{e(requirement)}</td><td>{_pill(row["status"])}</td><td>{checks}</td></tr>')
        panels.append(f'<div class="panel" id="fw-{e(framework)}"><h3>{e(name)}</h3>'
                      + _table(["Requirement", "Result", "Tested by"], body) + "</div>")
    return f'<div class="tabs" role="tablist">{"".join(buttons)}</div>{"".join(panels)}'


def _scope(results: dict, baseline: dict | None) -> str:
    items = (results.get("inventories") or {}).get("scope") or []
    if not items:
        return ""
    rows = []
    for item in items:
        mismatch = item["effective"] == "connected" and item["declared"] not in {"cde", "connected"}
        note = "; ".join(item.get("reaches_cde_by") or [])
        if mismatch:
            note = f"Label is wrong. Reaches card data by {note}"
        rows.append(f'<tr{" class=\"flag\"" if mismatch else ""}><td>{e(item["kind"])}</td>'
                    f'<td class="mono">{e(item["name"])}</td><td>{e(item["declared"] or "not declared")}</td>'
                    f'<td>{e(item["effective"])}</td><td>{e(note)}</td></tr>')
    approved = ""
    record = (baseline or {}).get("baseline") if (baseline or {}).get("found", True) else None
    if record:
        approved = (f'<p class="meta">Approved baseline: {len(record.get("items", {}))} items, approved by '
                    f'{e(record.get("approved_by"))} on {e(record.get("approved_at"))}.</p>')
    drift = next((c for c in results["checks"] if c["id"] == "SCP-03"), None)
    drifted = [r for r in (drift or {}).get("results", []) if r["status"] == "fail"]
    drift_html = ""
    if drifted:
        lines = "".join(f"<li><strong>{e(r['resource'])}</strong>: {e(r['detail'])}</li>" for r in drifted)
        drift_html = (f'<div class="card"><div class="head"><h3>Drift from the approved baseline</h3>'
                      f'{_pill("fail")}</div><ul>{lines}</ul></div>')
    return (
        '<h2 id="scope">PCI scope of the network</h2>'
        '<p class="lede">What each part of the network is labelled, next to what the firewall rules make it. '
        'A highlighted row is labelled out of scope but can reach card data, so it is in scope whether or not '
        'anyone meant it to be.</p>' + approved
        + _table(["Kind", "Name", "Labelled", "Actually", "How it reaches card data"], rows) + drift_html)


def _certificates(results: dict) -> str:
    certs = (results.get("inventories") or {}).get("certificates") or []
    if not certs:
        return ""
    rows = [f'<tr><td class="mono">{e(c["name"])}</td><td>{e(c["issuer"])}</td><td>{e(c["key"])}</td>'
            f'<td>{e(c["signature"])}</td><td>{e(c["expires"])}</td>'
            f'<td>{e(", ".join(c["in_use_by"]) or "nothing")}</td></tr>' for c in certs]
    return ('<h2 id="certificates">Certificate inventory</h2>'
            '<p class="lede">Every certificate found in the account, who issued it, how strong its key is, '
            'when it expires, and what is using it.</p>'
            + _table(["Name", "Issuer", "Key", "Signature", "Expires", "In use by"], rows))


def _indicators(validation: dict) -> str:
    s = validation["summary"]
    tiles = (
        '<div class="tiles"><div class="tile"><p class="label">Indicators addressed</p>'
        f'<div class="big">{s["addressed"]} <small>of {s["total"]}</small></div>'
        + _bar([("ok", s["pass"]), ("bad", s["fail"]), ("warn", s["error"]), ("info", s["preventive_only"]),
                ("na", s["not_covered"])])
        + f'<p class="sub">{s["pass"]} validated, {s["fail"]} failing, {s["preventive_only"]} preventive only, '
          f'{s["error"]} without evidence</p></div>'
        '<div class="tile"><p class="label">Not covered</p>'
        f'<div class="big">{s["not_covered"]}</div><p class="sub">Listed below. They need evidence this project '
        'does not collect, such as policies, training records, and recovery tests.</p></div></div>')
    blocks = []
    for ind in validation["indicators"]:
        if ind["status"] == "not_covered":
            continue
        checks = []
        for outcome in ind["checks"]:
            findings = "".join(f"<li>{e(f)}</li>" for f in outcome["findings"])
            checks.append(f'<li>{_pill(outcome["status"])} <span class="mono">{e(outcome["check"])}</span> '
                          f'{e(outcome["title"])}{f"<ul>{findings}</ul>" if findings else ""}</li>')
        if ind["preventive_rules"]:
            checks.append(f'<li>{_pill("preventive_only", KSI_WORDS)} Plan check rules '
                          f'{e(", ".join(ind["preventive_rules"]))}, applied to every proposed change</li>')
        blocks.append(
            f'<details><summary><span class="mono">{e(ind["id"])}</span><span class="name">{e(ind["name"])}</span>'
            f'{_pill(ind["status"], KSI_WORDS)}</summary><blockquote>{e(ind["statement"])}</blockquote>'
            f'<div class="two"><p><strong>What the evidence establishes.</strong> {e(ind["covers"])}</p>'
            f'<p><strong>What it does not establish.</strong> {e(ind["does_not_cover"])}</p></div>'
            f'<ul>{"".join(checks)}</ul></details>')
    missing = [f'<tr><td class="mono">{e(i["id"])}</td><td>{e(i["theme"])}</td><td>{e(i["name"])}</td></tr>'
               for i in validation["indicators"] if i["status"] == "not_covered"]
    not_covered = (f'<details><summary><span class="name">The {len(missing)} indicators not covered</span></summary>'
                   + _table(["Indicator", "Theme", "Name"], missing) + "</details>") if missing else ""
    return (
        '<h2 id="fedramp">FedRAMP 20x Key Security Indicators</h2>'
        f'<p class="lede">FedRAMP 20x asks for proof against {s["total"]} indicators. This section says, for each '
        'one this project speaks to, what the evidence shows and what it leaves unproven. Indicator names and '
        f'statements are FedRAMP\'s own text, rules version {e(validation["rules_version"])}. Select an indicator '
        'to open it.</p>' + tiles + "".join(blocks) + not_covered)


def _all_checks(results: dict) -> str:
    blocks = []
    for check in results["checks"]:
        rows = [f'<tr><td>{_pill(r["status"])}</td><td>{e(r["resource"])}</td><td>{e(r["detail"])}</td></tr>'
                for r in check["results"]]
        body = _table(["Result", "What was looked at", "What was found"], rows) if rows else ""
        note = f'<p>{e(check["note"])}</p>' if check.get("note") else ""
        blocks.append(
            f'<details><summary><span class="mono">{e(check["id"])}</span><span class="name">{e(check["title"])}</span>'
            f'{_pill(check["status"])}</summary><p class="why">{e(check["why"])}</p>{note}{body}'
            f'{_refs(check["frameworks"])}</details>')
    return ('<h2 id="checks">Every check</h2><p class="lede">All checks, passing and failing, with each resource '
            'that was looked at. Select a check to open it.</p>' + "".join(blocks))


def _evidence(manifest: dict, manifest_sha256: str | None) -> str:
    rows = [f'<tr><td class="mono">{e(f["path"])}</td><td>{e(f.get("bytes"))}</td>'
            f'<td class="mono">{e(f["sha256"])}</td></tr>' for f in manifest["files"]]
    previous = manifest.get("previous_manifest_sha256")
    return (
        '<h2 id="evidence">The evidence behind this page</h2>'
        '<p class="lede">Every number above was worked out from these files, which were written by asking AWS '
        'directly. Each file has a fingerprint (a SHA-256 hash). Change one character in a file and its '
        'fingerprint no longer matches, which is how tampering is caught.</p>'
        + _table(["File", "Bytes", "Fingerprint"], rows)
        + f'<p class="meta" style="margin-top:12px">Fingerprint of this run: <code>{e(manifest_sha256 or "not recorded")}</code><br>'
          f'Fingerprint of the run before it: <code>{e(previous or "none, this is the first run in its chain")}</code></p>')


def render_html(results: dict, validation: dict, manifest: dict, manifest_sha256: str | None = None,
                problems: list[str] | None = None, baseline: dict | None = None) -> str:
    source = manifest["source"]
    mode = ("Practice mode: this is a simulated AWS account, not a real one."
            if source.get("mode") == "mock" else "Collected from a live AWS account.")
    s = results["summary"]
    sections = [
        f'<p class="eyebrow">SecuGuard, a fictional company</p><h1>Compliance evidence report</h1>'
        f'<p class="lede">{s["pass"]} of {len(results["checks"])} checks pass and {s["fail"]} fail. Each check is '
        'run once and reported against PCI DSS 4.0.1, SOC 2, and FedRAMP 20x. Most failures are deliberate: '
        'weaknesses were planted to prove the checks catch them.</p>'
        f'<p class="meta">Run <code>{e(manifest["run_id"])}</code> &nbsp;|&nbsp; Account <code>{e(source.get("account_id"))}</code> '
        f'in {e(source.get("region"))} &nbsp;|&nbsp; Evidence collected {e(results["graded_as_of"])}<br>{e(mode)}</p>',
    ]
    header = f'<header>{"".join(sections)}</header>'
    nav = ('<nav><a href="#findings">What needs fixing</a><a href="#frameworks">By framework</a>'
           '<a href="#scope">PCI scope</a><a href="#certificates">Certificates</a>'
           '<a href="#fedramp">FedRAMP 20x</a><a href="#checks">Every check</a><a href="#evidence">Evidence</a></nav>')
    body = "".join([
        header, nav, _integrity(manifest, manifest_sha256, problems or []), _tiles(results, validation),
        '<h2 id="findings">What needs fixing</h2><p class="lede">Failing checks, most serious first, with the '
        'exact resource at fault and the requirements each one affects.</p>', _findings(results),
        '<h2 id="frameworks">The same results, by framework</h2><p class="lede">One set of checks, three ways to '
        'read it. A requirement is met only when every check that tests it passes.</p>', _frameworks(results),
        _scope(results, baseline), _certificates(results), _indicators(validation), _all_checks(results),
        _evidence(manifest, manifest_sha256),
        '<footer><p>The mapping of checks to requirements is the author\'s reading of each framework. It is a '
        'starting point for discussion with an assessor, not an assessor\'s opinion. Passing these checks does '
        'not make an organisation compliant, because each framework also asks for things no script can see.</p>'
        f'<p>Made by secuguard {e(source.get("tool_version"))}. This page loads nothing from the internet.</p></footer>',
    ])
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>SecuGuard compliance evidence report, {e(manifest["run_id"])}</title>'
            f'<style>{CSS}</style></head><body><div class="wrap">{body}</div><script>{SCRIPT}</script></body></html>\n')
