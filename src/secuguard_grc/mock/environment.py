"""A simulated SecuGuard AWS environment for mock mode.

Mock mode uses the moto library, which answers AWS API calls from memory on your
own machine. Nothing here touches a real account and nothing costs money. The
resources mirror what terraform/ builds, so the same collectors run against both.
"""

from __future__ import annotations

PROJECT = "secuguard-grc"
SCOPE_TAG = "secuguard:pci-scope"
VPC_CIDR = "10.20.0.0/16"

# tier name -> (PCI scope, third octet of the first subnet)
TIERS = {
    "cde": ("cde", 10),
    "shared": ("connected", 20),
    "corporate": ("out-of-scope", 30),
}


def _tags(name: str, scope: str | None = None) -> list[dict]:
    tags = [{"Key": "Name", "Value": name}, {"Key": "Project", "Value": PROJECT}]
    if scope:
        tags.append({"Key": SCOPE_TAG, "Value": scope})
    return tags


def build_mock_environment(session) -> str:
    """Create the simulated environment. Returns the evidence bucket name."""
    region = session.region_name
    ec2 = session.client("ec2")
    account_id = session.client("sts").get_caller_identity()["Account"]

    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags("secuguard-vpc")}],
    )["Vpc"]["VpcId"]

    zones = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    groups = {}
    for tier, (scope, octet) in TIERS.items():
        for index, zone in enumerate(zones):
            ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.20.{octet + index}.0/24",
                AvailabilityZone=zone,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": _tags(f"secuguard-{tier}-{zone[-1]}", scope),
                }],
            )
        groups[tier] = ec2.create_security_group(
            GroupName=f"secuguard-{tier}",
            Description=f"SecuGuard {tier} tier",
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": _tags(f"secuguard-{tier}", scope),
            }],
        )["GroupId"]

    # The cardholder data environment accepts HTTPS from the shared services tier only.
    ec2.authorize_security_group_ingress(
        GroupId=groups["cde"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "UserIdGroupPairs": [{
                "GroupId": groups["shared"],
                "Description": "HTTPS from shared services",
            }],
        }],
    )
    # Shared services accept HTTPS from the corporate tier.
    ec2.authorize_security_group_ingress(
        GroupId=groups["shared"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "UserIdGroupPairs": [{
                "GroupId": groups["corporate"],
                "Description": "HTTPS from corporate",
            }],
        }],
    )

    kms = session.client("kms")
    key_id = kms.create_key(
        Description="SecuGuard evidence encryption key",
        Tags=[{"TagKey": "Project", "TagValue": PROJECT}],
    )["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)
    kms.create_alias(AliasName="alias/secuguard-evidence", TargetKeyId=key_id)

    s3 = session.client("s3")
    bucket = f"secuguard-evidence-{account_id}"
    create_args = {"Bucket": bucket, "ObjectLockEnabledForBucket": True}
    if region != "us-east-1":
        create_args["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**create_args)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object_lock_configuration(
        Bucket=bucket,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 1}},
        },
    )
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={"Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_id,
            },
            "BucketKeyEnabled": True,
        }]},
    )
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )

    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True, RequireNumbers=True,
        RequireUppercaseCharacters=True, RequireLowercaseCharacters=True,
        MaxPasswordAge=90, PasswordReusePrevention=24,
    )
    return bucket
