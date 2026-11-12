"""Whether activity in the account and on the network is being recorded."""

from .base import Collector, optional, paginate


def collect(session):
    cloudtrail = session.client("cloudtrail")
    trails = []
    for trail in cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", []):
        status = optional(lambda: cloudtrail.get_trail_status(Name=trail["TrailARN"]), set()) or {}
        trails.append({
            "name": trail.get("Name"),
            "arn": trail.get("TrailARN"),
            "home_region": trail.get("HomeRegion"),
            "multi_region": trail.get("IsMultiRegionTrail", False),
            "log_file_validation": trail.get("LogFileValidationEnabled", False),
            "s3_bucket": trail.get("S3BucketName"),
            "kms_key_id": trail.get("KmsKeyId"),
            "is_logging": status.get("IsLogging"),
        })
    flow_logs = [{
        "id": log.get("FlowLogId"),
        "resource_id": log.get("ResourceId"),
        "status": log.get("FlowLogStatus"),
        "traffic_type": log.get("TrafficType"),
        "destination": log.get("LogDestination") or log.get("LogGroupName"),
    } for log in paginate(session.client("ec2"), "describe_flow_logs", "FlowLogs")]
    return {"trails": trails, "flow_logs": flow_logs}


COLLECTOR = Collector(
    name="audit_logging",
    description=(
        "CloudTrail trails, which record who did what in the account, and VPC flow logs, which "
        "record network traffic. An empty list means that kind of logging is not set up."
    ),
    api_calls=["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "ec2:DescribeFlowLogs"],
    relevant_to={
        "pci_dss_4_0_1": ["10.2", "10.3"],
        "soc_2": ["CC7.2"],
        "fedramp_20x": ["KSI-MLA-LET", "KSI-CMT-LMC"],
    },
    collect=collect,
)
