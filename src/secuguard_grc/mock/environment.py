"""A simulated SecuGuard AWS environment for mock mode.

Mock mode uses the moto library, which answers AWS API calls from memory on your
own machine. Nothing here touches a real account and nothing costs money. The
resources mirror what terraform/ builds, so the same collectors run against both.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

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
        # One route table per tier with no route beyond the network itself, as in Terraform.
        table = ec2.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags(f"secuguard-{tier}", scope)}],
        )["RouteTable"]["RouteTableId"]
        for index, zone in enumerate(zones):
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.20.{octet + index}.0/24",
                AvailabilityZone=zone,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": _tags(f"secuguard-{tier}-{zone[-1]}", scope),
                }],
            )["Subnet"]["SubnetId"]
            ec2.associate_route_table(RouteTableId=table, SubnetId=subnet_id)
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

    iam = session.client("iam")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True, RequireNumbers=True,
        RequireUppercaseCharacters=True, RequireLowercaseCharacters=True,
        MaxPasswordAge=90, PasswordReusePrevention=24,
    )
    _plant_findings(session, vpc_id, groups, key_id, account_id)
    _monitoring(session, vpc_id, account_id)
    return bucket


def _self_signed(common_name: str, key_bits: int, valid_days: int) -> tuple[bytes, bytes]:
    """Make a throwaway self-signed certificate. Returns (certificate PEM, private key PEM)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecuGuard (fictional)")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=valid_days))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


def _plant_findings(session, vpc_id: str, groups: dict, good_key_id: str, account_id: str) -> None:
    """The same deliberate weaknesses that terraform/planted.tf creates in a real account."""
    ec2, iam, kms, s3 = (session.client(name) for name in ("ec2", "iam", "kms", "s3"))
    planted = [{"Key": "secuguard:planted", "Value": "true"}]

    # Network: SSH open to the internet on an office-zone group.
    open_admin = ec2.create_security_group(
        GroupName="secuguard-planted-open-admin", Description="Planted finding: SSH open to the internet",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": _tags("secuguard-planted-open-admin", "out-of-scope") + planted}],
    )["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=open_admin, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH from anywhere"}]}])

    # Scope drift: a group labelled out of scope that is let straight into the card data zone,
    # and a group nobody gave a scope to.
    analytics = ec2.create_security_group(
        GroupName="secuguard-planted-analytics", Description="Planted finding: out of scope but allowed into the CDE",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": _tags("secuguard-planted-analytics", "out-of-scope") + planted}],
    )["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=groups["cde"], IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
        "UserIdGroupPairs": [{"GroupId": analytics, "Description": "Analytics straight to the card database"}]}])
    ec2.create_security_group(
        GroupName="secuguard-planted-unclassified", Description="Planted finding: no PCI scope declared",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": _tags("secuguard-planted-unclassified") + planted}])

    # Encryption: a key that never rotates, and a bucket with no key of its own and no public access block.
    legacy_key = kms.create_key(Description="Planted finding: legacy key without rotation")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName="alias/secuguard-legacy-no-rotation", TargetKeyId=legacy_key)
    legacy_bucket = f"secuguard-legacy-exports-{account_id}"
    args = {"Bucket": legacy_bucket}
    if session.region_name != "us-east-1":
        args["CreateBucketConfiguration"] = {"LocationConstraint": session.region_name}
    s3.create_bucket(**args)

    # Certificates: one weak and about to expire, one healthy.
    acm = session.client("acm")
    weak_cert, weak_key = _self_signed("legacy-api.secuguard.example", 1024, 20)
    acm.import_certificate(Certificate=weak_cert, PrivateKey=weak_key)
    good_cert, good_private = _self_signed("portal.secuguard.example", 2048, 365)
    good_arn = acm.import_certificate(Certificate=good_cert, PrivateKey=good_private)["CertificateArn"]

    # Load balancer: encrypted, but with a policy that still allows TLS 1.0.
    shared_subnets = [s["SubnetId"] for s in ec2.describe_subnets(
        Filters=[{"Name": f"tag:{SCOPE_TAG}", "Values": ["connected"]}])["Subnets"]]
    elb = session.client("elbv2")
    balancer = elb.create_load_balancer(
        Name="secuguard-portal", Subnets=shared_subnets, SecurityGroups=[groups["shared"]],
        Scheme="internal", Type="application")["LoadBalancers"][0]["LoadBalancerArn"]
    elb.create_listener(
        LoadBalancerArn=balancer, Protocol="HTTPS", Port=443, SslPolicy="ELBSecurityPolicy-2016-08",
        Certificates=[{"CertificateArn": good_arn}],
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "503", "ContentType": "text/plain"}}])

    # Identity: users and a role with access problems. In a real account these are made
    # harmless by a permissions boundary that denies everything.
    allow_all = json.dumps({"Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    deny_all = json.dumps({"Version": "2012-10-17",
                           "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    boundary = iam.create_policy(PolicyName="secuguard-planted-deny-all", PolicyDocument=deny_all)["Policy"]["Arn"]
    admin = iam.create_policy(PolicyName="AdministratorAccess", PolicyDocument=allow_all)["Policy"]["Arn"]
    read_only = iam.create_policy(PolicyName="ReadOnlyAccess", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}]
    }))["Policy"]["Arn"]

    iam.create_user(UserName="secuguard-dev-alice", PermissionsBoundary=boundary, Tags=planted)
    iam.create_login_profile(UserName="secuguard-dev-alice", Password="Mock-only-Passw0rd!", PasswordResetRequired=True)

    iam.create_user(UserName="secuguard-svc-reports", PermissionsBoundary=boundary, Tags=planted)
    iam.attach_user_policy(UserName="secuguard-svc-reports", PolicyArn=admin)
    iam.create_access_key(UserName="secuguard-svc-reports")

    iam.create_group(GroupName="secuguard-auditors")
    iam.attach_group_policy(GroupName="secuguard-auditors", PolicyArn=read_only)
    iam.create_user(UserName="secuguard-audit-carol", PermissionsBoundary=boundary)
    iam.add_user_to_group(GroupName="secuguard-auditors", UserName="secuguard-audit-carol")

    iam.create_role(
        RoleName="secuguard-legacy-vendor", PermissionsBoundary=boundary, Tags=planted,
        Description="Planted finding: trusts an outside account with no external ID",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::127311923021:root"}, "Action": "sts:AssumeRole"}]}))


def _monitoring(session, vpc_id: str, account_id: str) -> None:
    """The monitoring that terraform/monitoring.tf switches on: CloudTrail, flow logs, and AWS Config.

    Security Hub is left off here. The simulator cannot list which standards are enabled,
    so in practice mode check MON-02 reports that Security Hub is not switched on.
    """
    region = session.region_name
    kms, s3 = session.client("kms"), session.client("s3")
    logs_key = kms.create_key(Description="SecuGuard log encryption key")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=logs_key)
    kms.create_alias(AliasName="alias/secuguard-logs", TargetKeyId=logs_key)

    bucket = f"secuguard-logs-{account_id}"
    args = {"Bucket": bucket}
    if region != "us-east-1":
        args["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**args)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={"Rules": [{
        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": logs_key}}]})
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

    cloudtrail = session.client("cloudtrail")
    cloudtrail.create_trail(Name="secuguard-trail", S3BucketName=bucket, S3KeyPrefix="cloudtrail",
                            IsMultiRegionTrail=True, EnableLogFileValidation=True, IncludeGlobalServiceEvents=True)
    cloudtrail.start_logging(Name="secuguard-trail")

    session.client("ec2").create_flow_logs(
        ResourceIds=[vpc_id], ResourceType="VPC", TrafficType="ALL",
        LogDestinationType="s3", LogDestination=f"arn:aws:s3:::{bucket}")

    config = session.client("config")
    config.put_configuration_recorder(ConfigurationRecorder={
        "name": "secuguard", "roleARN": f"arn:aws:iam::{account_id}:role/secuguard-config-recorder",
        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}})
    config.put_delivery_channel(DeliveryChannel={"name": "secuguard", "s3BucketName": bucket, "s3KeyPrefix": "config"})
    config.start_configuration_recorder(ConfigurationRecorderName="secuguard")
