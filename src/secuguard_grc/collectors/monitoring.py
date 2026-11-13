"""Whether the account is being watched: configuration recording and security standards."""

from .base import Collector, optional

# What AWS answers when Security Hub has never been switched on in this account and region.
NOT_ENABLED = {"InvalidAccessException", "ResourceNotFoundException"}


def collect(session):
    config = session.client("config")
    recorders = optional(lambda: config.describe_configuration_recorders(), set(), "ConfigurationRecorders")
    statuses = optional(lambda: config.describe_configuration_recorder_status(), set(), "ConfigurationRecordersStatus")
    channels = optional(lambda: config.describe_delivery_channels(), set(), "DeliveryChannels")

    hub = session.client("securityhub")
    described = optional(lambda: hub.describe_hub(), NOT_ENABLED)
    enabled = bool(described) and "collection_error" not in described
    standards = None
    if enabled:
        standards = optional(lambda: hub.get_enabled_standards(), set(), "StandardsSubscriptions")
        if isinstance(standards, list):
            standards = [{"standard": s.get("StandardsArn"), "status": s.get("StandardsStatus")} for s in standards]
    return {
        "config_recorders": recorders,
        "config_recorder_status": statuses,
        "config_delivery_channels": channels,
        # If Security Hub could not be read at all, the error is passed on so checks draw no conclusion.
        "security_hub": described if described and "collection_error" in described else {
            "enabled": enabled,
            "hub_arn": (described or {}).get("HubArn"),
            "subscribed_at": (described or {}).get("SubscribedAt"),
        },
        "security_hub_standards": standards,
    }


COLLECTOR = Collector(
    name="monitoring",
    description=(
        "Whether AWS Config is recording every change to the account's resources, and whether "
        "Security Hub is switched on and which security standards it is evaluating."
    ),
    api_calls=[
        "config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels", "securityhub:DescribeHub", "securityhub:GetEnabledStandards",
    ],
    relevant_to={
        "pci_dss_4_0_1": ["2.2.1", "12.5.1"],
        "soc_2": ["CC7.1"],
        "fedramp_20x": ["KSI-CMT-LMC", "KSI-MLA-EVC", "KSI-PIY-GIV"],
    },
    collect=collect,
)
