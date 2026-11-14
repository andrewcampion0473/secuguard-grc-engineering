"""The web page report: complete, self-contained, safe, and honest about damaged evidence."""

import json
import re
from pathlib import Path

from secuguard_grc.cli import main
from secuguard_grc.evidence import load_run
from secuguard_grc.report_html import render_html

SAMPLE = Path(__file__).parent.parent / "examples" / "sample-run"


def _page(**changes):
    manifest, payloads = load_run(SAMPLE)
    results = changes.get("results", payloads["check-results"])
    return render_html(results, payloads["ksi-validation"], manifest, "abc123",
                       changes.get("problems", []), payloads.get("scope_baseline"))


def test_page_shows_every_check_and_every_framework():
    _, payloads = load_run(SAMPLE)
    page = _page()
    for check in payloads["check-results"]["checks"]:
        assert check["id"] in page
    for name in ("PCI DSS 4.0.1", "SOC 2", "FedRAMP 20x"):
        assert name in page
    assert page.index('data-panel="fw-pci_dss_4_0_1"') < page.index('data-panel="fw-soc_2"') \
        < page.index('data-panel="fw-fedramp_20x"')


def test_page_loads_nothing_from_the_internet():
    page = _page()
    assert not re.search(r'(src|href)="https?://', page)
    assert "<link" not in page and "@import" not in page


def test_values_from_aws_are_escaped():
    _, payloads = load_run(SAMPLE)
    results = json.loads(json.dumps(payloads["check-results"]))
    failing = next(c for c in results["checks"] if c["status"] == "fail")
    failing["results"][0]["resource"] = '<script>alert("x")</script>'
    failing["results"][0]["status"] = "fail"
    page = _page(results=results)
    assert '<script>alert("x")</script>' not in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page


def test_damaged_evidence_is_announced_at_the_top():
    assert "Evidence verified." in _page()
    page = _page(problems=["iam.json does not match its recorded hash"])
    assert "Evidence failed verification." in page
    assert "iam.json does not match its recorded hash" in page
    assert "Evidence verified." not in page


def test_command_writes_a_utf8_file(tmp_path, capsys):
    out = tmp_path / "report.html"
    assert main(["report", str(SAMPLE), "--html", "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>") and "Evidence verified." in text
    assert "Open it in a web browser" in capsys.readouterr().out
