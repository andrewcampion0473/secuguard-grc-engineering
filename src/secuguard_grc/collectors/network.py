"""Network boundaries: VPCs, subnets, route tables, and security groups."""

from .base import Collector, paginate


def collect(session):
    ec2 = session.client("ec2")
    return {
        "vpcs": paginate(ec2, "describe_vpcs", "Vpcs"),
        "subnets": paginate(ec2, "describe_subnets", "Subnets"),
        "route_tables": paginate(ec2, "describe_route_tables", "RouteTables"),
        "security_groups": paginate(ec2, "describe_security_groups", "SecurityGroups"),
    }


COLLECTOR = Collector(
    name="network",
    description=(
        "Network segmentation as configured right now: every VPC, subnet, route table, and "
        "security group rule, with the tags that mark each one as in or out of PCI scope."
    ),
    api_calls=[
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
    ],
    relevant_to={
        "pci_dss_4_0_1": ["1.2", "1.3", "1.4"],
        "soc_2": ["CC6.1", "CC6.6"],
        "fedramp_20x": ["KSI-CNA-RNT", "KSI-CNA-ULN", "KSI-CNA-MAT"],
    },
    collect=collect,
)
