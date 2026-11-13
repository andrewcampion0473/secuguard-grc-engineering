"""FedRAMP 20x indicator validation."""

import json

from secuguard_grc import ksi
from secuguard_grc.checks import CHECKS, run_checks
from secuguard_grc.cli import main
from secuguard_grc.evidence import list_runs


def results_with(statuses):
    """Check results where every check passes except those named."""
    checks = [{"id": c.id, "title": c.title, "status": statuses.get(c.id, "pass"), "frameworks": c.frameworks,
               "results": [{"resource": "r", "status": "fail", "detail": "d"}] if statuses.get(c.id) == "fail" else []}
              for c in CHECKS]
    return {"graded_as_of": "2026-11-12T12:00:00Z", "checks": checks}


def by_id(validation):
    return {i["id"]: i for i in validation["indicators"]}


def test_the_catalog_is_fedramps_own_and_complete():
    catalog = ksi.load_indicators()
    assert catalog["version"] == "2026.11.02.01"
    assert len(catalog["indicators"]) == 46
    assert catalog["indicators"]["KSI-CNA-RNT"]["name"] == "Restricting Network Traffic"
    assert all(entry["statement"] for entry in catalog["indicators"].values())


def test_every_indicator_a_check_names_exists_in_the_catalog():
    known = set(ksi.load_indicators()["indicators"])
    for check in CHECKS:
        assert set(check.frameworks["fedramp_20x"]) <= known, check.id
    assert set(ksi.COVERAGE) <= known


def test_every_addressed_indicator_states_what_it_covers_and_what_it_does_not():
    validation = ksi.validate(results_with({}))
    for indicator in validation["indicators"]:
        if indicator["status"] != "not_covered":
            assert indicator["covers"] and indicator["does_not_cover"], indicator["id"]


def test_statuses_follow_the_checks():
    clean = by_id(ksi.validate(results_with({})))
    assert clean["KSI-SVC-ASM"]["status"] == "pass"
    assert clean["KSI-CMT-VTD"]["status"] == "preventive_only"        # only the plan check speaks to it
    assert clean["KSI-INR-RIR"]["status"] == "not_covered" if "KSI-INR-RIR" in clean else True

    one_failing = by_id(ksi.validate(results_with({"CRY-01": "fail"})))
    assert one_failing["KSI-SVC-ASM"]["status"] == "fail"
    assert one_failing["KSI-SVC-ASM"]["checks"][0]["findings"] == ["r: d"]
    assert one_failing["KSI-IAM-APM"]["status"] == "pass"             # unrelated indicators are untouched

    unreadable = by_id(ksi.validate(results_with({"CRY-01": "error"})))
    assert unreadable["KSI-SVC-ASM"]["status"] == "error"             # missing evidence is never a pass


def test_summary_counts_add_up():
    summary = ksi.validate(results_with({"CRY-01": "fail"}))["summary"]
    assert summary["total"] == 46
    assert summary["addressed"] + summary["not_covered"] == 46
    assert summary["pass"] + summary["fail"] + summary["error"] + summary["preventive_only"] == summary["addressed"]
    assert 10 <= summary["addressed"] <= 20


def test_missing_evidence_everywhere_validates_nothing():
    validation = ksi.validate(run_checks({}, "2026-11-12T12:00:00Z"))
    assert validation["summary"]["pass"] == 0


def test_a_run_seals_its_validation_and_lists_the_evidence_behind_it(tmp_path, capsys):
    assert main(["collect", "--mock", "--output", str(tmp_path)]) == 0
    run = list_runs(tmp_path)[0]
    record = json.loads((run / "ksi-validation.json").read_text())
    validation = record["payload"]
    manifest = {f["path"]: f["sha256"] for f in json.loads((run / "manifest.json").read_text())["files"]}
    assert "ksi-validation.json" in manifest
    listed = {f["path"]: f["sha256"] for f in validation["evidence_files"]}
    assert "network.json" in listed and "check-results.json" in listed
    assert all(manifest[path] == digest for path, digest in listed.items())      # same fingerprints as the manifest

    capsys.readouterr()
    assert main(["ksi", str(tmp_path)]) == 0
    assert "indicators addressed" in capsys.readouterr().out
    assert main(["ksi", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["rules_version"] == "2026.11.02.01"
    assert main(["ksi", str(tmp_path), "--markdown"]) == 0
    assert "What it does not establish" in capsys.readouterr().out
