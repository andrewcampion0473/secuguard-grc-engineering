"""Account-level identity settings: root account protections and the password policy."""

from .base import Collector, optional


def collect(session):
    iam = session.client("iam")
    return {
        "account_summary": optional(lambda: iam.get_account_summary(), set(), "SummaryMap"),
        "password_policy": optional(
            lambda: iam.get_account_password_policy(), {"NoSuchEntity"}, "PasswordPolicy"
        ),
    }


COLLECTOR = Collector(
    name="iam",
    description=(
        "Account-wide identity settings: whether the root user has MFA and access keys, how "
        "many users and roles exist, and the IAM password policy. A null password policy "
        "means none is set."
    ),
    api_calls=["iam:GetAccountSummary", "iam:GetAccountPasswordPolicy"],
    relevant_to={
        "pci_dss_4_0_1": ["8.3", "8.4"],
        "soc_2": ["CC6.1"],
        "fedramp_20x": ["KSI-IAM-APM"],
    },
    collect=collect,
)
