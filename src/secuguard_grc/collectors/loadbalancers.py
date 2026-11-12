"""Load balancers and the encryption settings on each listener."""

from .base import Collector, paginate


def collect(session):
    elb = session.client("elbv2")
    balancers = []
    for lb in paginate(elb, "describe_load_balancers", "LoadBalancers"):
        listeners = paginate(elb, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"])
        balancers.append({
            "name": lb["LoadBalancerName"],
            "arn": lb["LoadBalancerArn"],
            "scheme": lb.get("Scheme"),
            "type": lb.get("Type"),
            "vpc_id": lb.get("VpcId"),
            "security_groups": lb.get("SecurityGroups", []),
            "listeners": [{
                "port": listener.get("Port"),
                "protocol": listener.get("Protocol"),
                "ssl_policy": listener.get("SslPolicy"),
                "certificates": [c.get("CertificateArn") for c in listener.get("Certificates", [])],
            } for listener in listeners],
        })
    return {"load_balancers": balancers}


COLLECTOR = Collector(
    name="loadbalancers",
    description=(
        "Every load balancer and, for each listener, the protocol, the TLS policy that decides "
        "which protocol versions and ciphers are allowed, and the certificate it presents."
    ),
    api_calls=["elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners"],
    relevant_to={
        "pci_dss_4_0_1": ["4.2"],
        "soc_2": ["CC6.7"],
        "fedramp_20x": ["KSI-SVC-SIN", "KSI-SVC-VCM"],
    },
    collect=collect,
)
