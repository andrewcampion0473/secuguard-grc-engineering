"""Storage: encryption, versioning, public access, and Object Lock for every bucket."""

from .base import Collector, optional


def collect(session):
    s3 = session.client("s3")
    buckets = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        buckets.append({
            "name": name,
            "created": bucket.get("CreationDate"),
            "encryption": optional(
                lambda: s3.get_bucket_encryption(Bucket=name),
                {"ServerSideEncryptionConfigurationNotFoundError"},
                "ServerSideEncryptionConfiguration",
            ),
            "versioning": optional(lambda: s3.get_bucket_versioning(Bucket=name), set()),
            "public_access_block": optional(
                lambda: s3.get_public_access_block(Bucket=name),
                {"NoSuchPublicAccessBlockConfiguration"},
                "PublicAccessBlockConfiguration",
            ),
            "object_lock": optional(
                lambda: s3.get_object_lock_configuration(Bucket=name),
                {"ObjectLockConfigurationNotFoundError"},
                "ObjectLockConfiguration",
            ),
        })
    return {"buckets": buckets}


COLLECTOR = Collector(
    name="s3",
    description=(
        "Every S3 bucket in the account with its encryption, versioning, public access block, "
        "and Object Lock settings. A null value means that protection is not configured."
    ),
    api_calls=[
        "s3:ListAllMyBuckets",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketObjectLockConfiguration",
    ],
    relevant_to={
        "pci_dss_4_0_1": ["3.5", "10.3", "10.5"],
        "soc_2": ["CC6.1", "CC6.7"],
        "fedramp_20x": ["KSI-SVC-SIN"],
    },
    collect=collect,
)
