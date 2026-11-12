"""Evidence collectors. Each one makes read-only AWS calls and returns plain data."""

from . import iam, kms, network, s3
from .base import Collector

COLLECTORS: list[Collector] = [
    network.COLLECTOR,
    kms.COLLECTOR,
    s3.COLLECTOR,
    iam.COLLECTOR,
]

__all__ = ["COLLECTORS", "Collector"]
