import json

from secuguard_grc.evidence import EvidenceRun, latest_manifest_sha256, verify_chain, verify_run

SOURCE = {"mode": "test", "account_id": "000000000000", "region": "us-east-1"}


def make_run(root, previous=None, value=1):
    run = EvidenceRun(root, SOURCE, previous)
    run.add(collector="sample", description="d", api_calls=["x:Y"],
            relevant_to={"soc_2": ["CC6.1"]}, payload={"value": value})
    run.finalize()
    return run


def test_untouched_run_verifies(tmp_path):
    run = make_run(tmp_path)
    assert verify_run(run.run_dir) == []


def test_edited_evidence_is_detected(tmp_path):
    run = make_run(tmp_path)
    path = run.run_dir / "sample.json"
    path.write_text(path.read_text().replace('"value": 1', '"value": 2'))
    problems = verify_run(run.run_dir)
    assert len(problems) == 1 and "file hash does not match" in problems[0]


def test_edit_with_recomputed_file_hash_still_fails(tmp_path):
    # An attacker who edits a file AND fixes its entry in the manifest breaks the manifest hash.
    run = make_run(tmp_path)
    manifest_path = run.run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    assert any("manifest.sha256" in p for p in verify_run(run.run_dir))


def test_extra_file_is_detected(tmp_path):
    run = make_run(tmp_path)
    (run.run_dir / "planted.json").write_text("{}")
    assert any("not listed" in p for p in verify_run(run.run_dir))


def test_missing_file_is_detected(tmp_path):
    run = make_run(tmp_path)
    (run.run_dir / "sample.json").unlink()
    assert any("missing" in p for p in verify_run(run.run_dir))


def test_runs_link_into_a_chain(tmp_path):
    first = make_run(tmp_path)
    first.run_dir.rename(tmp_path / "20260101T000000Z-aaaaaaaa")  # force a stable order
    second = make_run(tmp_path, latest_manifest_sha256(tmp_path))
    assert second.previous_manifest_sha256 == first.manifest_sha256
    assert verify_chain(tmp_path) == []


def test_rewriting_an_old_run_breaks_the_chain(tmp_path):
    first = make_run(tmp_path)
    old = tmp_path / "20260101T000000Z-aaaaaaaa"
    first.run_dir.rename(old)
    make_run(tmp_path, latest_manifest_sha256(tmp_path))
    # Replace the old run's manifest and its hash file consistently. Only the chain catches this.
    manifest = json.loads((old / "manifest.json").read_text())
    manifest["finished_at"] = "2020-01-01T00:00:00Z"
    data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (old / "manifest.json").write_bytes(data)
    import hashlib
    (old / "manifest.sha256").write_text(hashlib.sha256(data).hexdigest() + "\n")
    assert any("does not link" in p for p in verify_chain(tmp_path))


def test_runs_started_in_the_same_second_stay_in_order(tmp_path):
    # Regression test: run folders must sort by time even when created back to back.
    for _ in range(25):
        make_run(tmp_path, latest_manifest_sha256(tmp_path))
    assert verify_chain(tmp_path) == []
