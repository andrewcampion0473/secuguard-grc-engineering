"""Shared pieces for collectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import boto3
from botocore.exceptions import ClientError


# The frameworks evidence is labelled against, and the exact edition of each.
# FedRAMP 20x indicator IDs come from FedRAMP's machine-readable rules:
# https://github.com/FedRAMP/rules (fedramp-consolidated-rules.json)
FRAMEWORKS = {
    "pci_dss_4_0_1": "PCI DSS v4.0.1 requirements",
    "soc_2": "SOC 2 Trust Services Criteria (2017, revised points of focus 2022)",
    "fedramp_20x": "FedRAMP 20x Key Security Indicators, Consolidated Rules for 2026, version 2026.11.02.01",
}


@dataclass(frozen=True)
class Collector:
    name: str                      # also the evidence file name
    description: str               # plain-language statement of what this evidence shows
    api_calls: list[str]           # read-only AWS API actions used, for the audit trail
    relevant_to: dict[str, list[str]]  # requirements this evidence helps answer
    collect: Callable[[boto3.Session], Any]


def paginate(client, operation: str, result_key: str, **kwargs) -> list:
    items: list = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def optional(call: Callable[[], dict], missing_codes: set[str], key: str | None = None) -> Any:
    """Run a 'get configuration' call where 'not found' is a real answer, not a failure.

    Returns the configuration, or None when AWS says it is not configured. Any other
    error is recorded in the evidence so a permissions gap is visible, not silent.
    """
    try:
        response = call()
    except ClientError as error:
        code = error.response["Error"]["Code"]
        if code in missing_codes:
            return None
        return {"collection_error": code}
    response.pop("ResponseMetadata", None)
    return response.get(key) if key else response
