"""Evidence collectors. Each one makes read-only AWS calls and returns plain data."""

from . import audit_logging, certificates, iam, identities, kms, loadbalancers, network, s3
from .base import Collector

COLLECTORS: list[Collector] = [
    network.COLLECTOR,
    kms.COLLECTOR,
    s3.COLLECTOR,
    iam.COLLECTOR,
    identities.COLLECTOR,
    certificates.COLLECTOR,
    loadbalancers.COLLECTOR,
    audit_logging.COLLECTOR,
]

__all__ = ["COLLECTORS", "Collector"]
