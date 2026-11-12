import json

from secuguard_grc.cli import main
from secuguard_grc.scope import baseline_from_inventory, build_inventory, compare_to_baseline

TAG = "secuguard:pci-scope"


def group(name, scope=None, rules=()):
    tags = [{"Key": TAG, "Value": scope}] if scope else []
    return {"GroupId": f"sg-{name}", "GroupName": name, "VpcId": "vpc-1", "IpPermissions": list(rules), "Tags": tags}


def subnet(name, cidr, scope):
    return {"SubnetId": f"subnet-{name}", "VpcId": "vpc-1", "CidrBlock": cidr,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": TAG, "Value": scope}]}


def from_group(group_id):
    return {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": [{"GroupId": group_id}]}


def from_range(cidr):
    return {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": cidr}]}


def inventory(*cde_rules, extra=()):
    network = {
        "security_groups": [group("cde", "cde", cde_rules), group("shared", "connected"),
                            group("office", "out-of-scope"), *extra,
                            {"GroupId": "sg-default", "GroupName": "default", "VpcId": "vpc-1", "IpPermissions": []},
                            {"GroupId": "sg-other", "GroupName": "elsewhere", "VpcId": "vpc-2", "IpPermissions": []}],
        "subnets": [subnet("cde-a", "10.20.10.0/24", "cde"), subnet("office-a", "10.20.30.0/24", "out-of-scope")],
    }
    return {i["name"]: i for i in build_inventory(network)["items"]}


def test_a_group_allowed_into_the_card_data_zone_is_in_scope_whatever_its_label():
    items = inventory(from_group("sg-shared"), from_group("sg-office"))
    assert items["shared"]["effective"] == "connected" and items["shared"]["declared"] == "connected"
    assert items["office"]["declared"] == "out-of-scope" and items["office"]["effective"] == "connected"
    assert items["cde"]["effective"] == "cde"


def test_an_address_range_rule_pulls_the_matching_subnet_into_scope():
    items = inventory(from_range("10.20.30.0/24"))
    assert items["office-a"]["effective"] == "connected"
    assert inventory(from_range("192.168.0.0/24"))["office-a"]["effective"] == "out-of-scope"


def test_only_the_scoped_network_is_inventoried():
    items = inventory()
    assert "default" not in items       # AWS's own default group
    assert "elsewhere" not in items     # a group in some other network


def test_baseline_reports_added_changed_and_removed():
    before = build_inventory({"security_groups": [group("cde", "cde"), group("office", "out-of-scope"),
                                                   group("old", "connected")], "subnets": []})
    baseline = baseline_from_inventory(before, "A. Reviewer", "2026-11-10")
    assert compare_to_baseline(before, baseline) == []

    after = build_inventory({"security_groups": [group("cde", "cde"), group("office", "connected"),
                                                  group("new", "out-of-scope")], "subnets": []})
    drift = {d["item"]: d["change"] for d in compare_to_baseline(after, baseline)}
    assert drift == {"security group:office": "changed", "security group:new": "added",
                     "security group:old": "removed"}


def test_scope_command_shows_drift_and_refuses_to_approve_a_broken_network(tmp_path, capsys):
    assert main(["collect", "--mock", "--output", str(tmp_path / "ev")]) == 0
    capsys.readouterr()
    assert main(["scope", str(tmp_path / "ev")]) == 1
    out = capsys.readouterr().out
    assert "mismatch" in out and "DRIFT. 3 difference(s)" in out

    target = tmp_path / "baseline.json"
    assert main(["scope", str(tmp_path / "ev"), "--approve", "--by", "A. Reviewer", "--baseline", str(target)]) == 1
    assert "Not approved" in capsys.readouterr().out
    assert not target.exists()


def test_shipped_baseline_lists_only_the_designed_network():
    from pathlib import Path
    baseline = json.loads((Path(__file__).parent.parent / "scope-baseline.json").read_text())
    assert len(baseline["items"]) == 9
    assert not any("planted" in key for key in baseline["items"])
