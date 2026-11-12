"""People and machines that can act in the account: users, their credentials, and roles."""

from .base import Collector, optional, paginate


def _user(iam, summary):
    name = summary["UserName"]
    detail = optional(lambda: iam.get_user(UserName=name), set(), "User") or {}
    keys = []
    for key in paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=name):
        key_id = key["AccessKeyId"]
        used = optional(lambda: iam.get_access_key_last_used(AccessKeyId=key_id), set(), "AccessKeyLastUsed") or {}
        keys.append({
            # Only the last four characters are kept. The full ID is not needed to review the key.
            "access_key_ending": key_id[-4:],
            "status": key["Status"],
            "created": key["CreateDate"],
            "last_used": used.get("LastUsedDate"),
        })
    login = optional(lambda: iam.get_login_profile(UserName=name), {"NoSuchEntity"}, "LoginProfile")
    return {
        "name": name,
        "created": summary.get("CreateDate"),
        "password_last_used": summary.get("PasswordLastUsed"),
        "has_console_password": login is not None and "collection_error" not in login,
        "mfa_devices": len(paginate(iam, "list_mfa_devices", "MFADevices", UserName=name)),
        "access_keys": keys,
        "attached_policies": [p["PolicyName"] for p in
                              paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)],
        "inline_policies": paginate(iam, "list_user_policies", "PolicyNames", UserName=name),
        "groups": [g["GroupName"] for g in paginate(iam, "list_groups_for_user", "Groups", UserName=name)],
        "permissions_boundary": (detail.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
        "tags": {t["Key"]: t["Value"] for t in detail.get("Tags", [])},
    }


def collect(session):
    iam = session.client("iam")
    roles = [{
        "name": role["RoleName"],
        "path": role["Path"],
        "created": role.get("CreateDate"),
        "trust_policy": role.get("AssumeRolePolicyDocument"),
    } for role in paginate(iam, "list_roles", "Roles")]
    return {
        "users": [_user(iam, u) for u in paginate(iam, "list_users", "Users")],
        "roles": roles,
    }


COLLECTOR = Collector(
    name="identities",
    description=(
        "Every IAM user with its console password status, MFA devices, access keys and when "
        "each was last used, attached permissions, and groups. Every role with the rule that "
        "says who may use it."
    ),
    api_calls=[
        "iam:ListUsers", "iam:GetUser", "iam:GetLoginProfile", "iam:ListMFADevices",
        "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed", "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies", "iam:ListGroupsForUser", "iam:ListRoles",
    ],
    relevant_to={
        "pci_dss_4_0_1": ["7.2", "8.2", "8.4", "8.6"],
        "soc_2": ["CC6.1", "CC6.2", "CC6.3"],
        "fedramp_20x": ["KSI-IAM-APM", "KSI-IAM-ELP", "KSI-IAM-SNU"],
    },
    collect=collect,
)
