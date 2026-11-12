"""PCI scope: what each part of the network is declared to be, and what it really is.

Every security group and subnet in SecuGuard's network carries a tag that declares its
place in PCI scope:

  cde           stores, processes, or transmits card data
  connected     can reach the card data zone, so PCI DSS applies to it too
  out-of-scope  has no path to the card data zone

A tag is a claim. This module works out the truth from the firewall rules, so the two
can be compared. It also compares today's network with a baseline that a person approved,
so anything new or changed is noticed the day it appears.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path

SCOPE_TAG = "secuguard:pci-scope"
VALID_SCOPES = {"cde", "connected", "out-of-scope"}
BASELINE_FILE = "scope-baseline.json"


def _tags(resource: dict) -> dict:
    return {t["Key"]: t["Value"] for t in resource.get("Tags", [])}


def _name(resource: dict, fallback: str) -> str:
    return resource.get("GroupName") or _tags(resource).get("Name") or fallback


def build_inventory(network: dict) -> dict:
    """List every security group and subnet in SecuGuard's network with its declared and effective scope."""
    groups, subnets = network.get("security_groups", []), network.get("subnets", [])
    # SecuGuard's networks are the ones where something has been given a scope tag.
    vpcs = {r.get("VpcId") for r in groups + subnets if SCOPE_TAG in _tags(r)}
    groups = [g for g in groups if g.get("VpcId") in vpcs and g.get("GroupName") != "default"]
    subnets = [s for s in subnets if s.get("VpcId") in vpcs]

    cde_groups = [g for g in groups if _tags(g).get(SCOPE_TAG) == "cde"]
    reaches_cde: dict[str, list[str]] = {}       # security group id -> how it reaches the card data zone
    cidrs_into_cde: list[tuple[str, str]] = []   # (address range, card data group it can reach)
    for target in cde_groups:
        for rule in target.get("IpPermissions", []):
            port = "all ports" if rule.get("IpProtocol") == "-1" else f"port {rule.get('FromPort')}"
            for pair in rule.get("UserIdGroupPairs", []):
                reaches_cde.setdefault(pair.get("GroupId"), []).append(f"{port} on {target['GroupName']}")
            for r in rule.get("IpRanges", []):
                cidrs_into_cde.append((r["CidrIp"], target["GroupName"]))

    items = []
    for group in groups:
        declared = _tags(group).get(SCOPE_TAG)
        paths = reaches_cde.get(group["GroupId"], [])
        effective = "cde" if declared == "cde" else ("connected" if paths else "out-of-scope")
        items.append({"kind": "security group", "name": _name(group, group["GroupId"]), "id": group["GroupId"],
                      "declared": declared, "effective": effective, "reaches_cde_by": paths})
    for subnet in subnets:
        declared = _tags(subnet).get(SCOPE_TAG)
        paths = []
        for cidr, target in cidrs_into_cde:
            try:
                if ipaddress.ip_network(cidr).overlaps(ipaddress.ip_network(subnet["CidrBlock"])):
                    paths.append(f"address range {cidr} allowed into {target}")
            except ValueError:
                continue
        # A subnet has no firewall rules of its own, so its label stands unless an address
        # range rule shows it can reach the card data zone.
        effective = "cde" if declared == "cde" else ("connected" if paths or declared == "connected" else "out-of-scope")
        items.append({"kind": "subnet", "name": _name(subnet, subnet["SubnetId"]), "id": subnet["SubnetId"],
                      "declared": declared, "effective": effective, "reaches_cde_by": paths})
    return {"items": sorted(items, key=lambda i: (i["kind"], i["name"]))}


def baseline_from_inventory(inventory: dict, approved_by: str, approved_at: str, note: str = "") -> dict:
    return {
        "approved_by": approved_by,
        "approved_at": approved_at,
        "note": note,
        "items": {f"{item['kind']}:{item['name']}": item["declared"] for item in inventory["items"]},
    }


def load_baseline(path: Path | str = BASELINE_FILE) -> dict:
    """Read the approved baseline as evidence: its contents, plus a fingerprint of the file."""
    path = Path(path)
    if not path.is_file():
        return {"file": str(path), "found": False, "sha256": None, "baseline": None}
    data = path.read_bytes()
    return {"file": path.name, "found": True, "sha256": hashlib.sha256(data).hexdigest(),
            "baseline": json.loads(data.decode("utf-8-sig"))}


def compare_to_baseline(inventory: dict, baseline: dict) -> list[dict]:
    """Everything that differs between today's network and what was approved."""
    approved = dict(baseline.get("items", {}))
    drift = []
    for item in inventory["items"]:
        key = f"{item['kind']}:{item['name']}"
        if key not in approved:
            drift.append({"item": key, "change": "added", "detail": f"not in the approved baseline "
                          f"(declared {item['declared'] or 'with no scope'})"})
        elif approved.pop(key) != item["declared"]:
            drift.append({"item": key, "change": "changed", "detail":
                          f"approved as {baseline['items'][key]}, now declared {item['declared'] or 'with no scope'}"})
        else:
            approved.pop(key, None)
    for key in approved:
        drift.append({"item": key, "change": "removed", "detail": "in the approved baseline but no longer exists"})
    return drift


def resource_name(arn: str) -> str:
    """Pull a readable name out of a load balancer or listener ARN. Falls back to the ARN."""
    parts = arn.split(":")[-1].split("/")
    for kind in ("app", "net", "gwy"):
        if kind in parts and parts.index(kind) + 1 < len(parts):
            return f"load balancer {parts[parts.index(kind) + 1]}"
    return arn
