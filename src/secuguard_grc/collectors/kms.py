"""Encryption keys: inventory, key type, state, and rotation."""

from .base import Collector, optional, paginate


def collect(session):
    kms = session.client("kms")
    keys = []
    for item in paginate(kms, "list_keys", "Keys"):
        key_id = item["KeyId"]
        metadata = optional(lambda: kms.describe_key(KeyId=key_id), set(), "KeyMetadata")
        rotation = optional(
            lambda: kms.get_key_rotation_status(KeyId=key_id),
            {"UnsupportedOperationException"},
        )
        keys.append({"key_id": key_id, "metadata": metadata, "rotation": rotation})
    return {"keys": keys, "aliases": paginate(kms, "list_aliases", "Aliases")}


COLLECTOR = Collector(
    name="kms",
    description=(
        "Every KMS key in the region: who manages it, what algorithm it uses, whether it is "
        "enabled, and whether automatic rotation is on."
    ),
    api_calls=["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus", "kms:ListAliases"],
    relevant_to={
        "pci_dss_4_0_1": ["3.6", "3.7"],
        "soc_2": ["CC6.1"],
        "fedramp_20x": ["KSI-SVC-ASM", "KSI-SVC-SIN"],
    },
    collect=collect,
)
