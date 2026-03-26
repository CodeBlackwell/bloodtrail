"""
Text utilities for bloodtrail command mappings.

String parsing and validation functions used across mapping modules.
"""

from typing import Set


def extract_domain(upn: str) -> str:
    """Extract domain from UPN format. MIKE@CORP.COM -> CORP.COM"""
    if "@" in upn:
        return upn.split("@")[1]
    return ""


def extract_username(upn: str) -> str:
    """Extract username from UPN format. MIKE@CORP.COM -> MIKE"""
    if "@" in upn:
        return upn.split("@")[0]
    return upn


def infer_dc_hostname(domain: str) -> str:
    """
    Infer DC hostname from domain name.
    CORP.COM -> DC01.CORP.COM (common pattern)

    Note: This is best-effort. User may need to adjust for non-standard DC names.
    """
    if not domain:
        return "<DC_IP>"
    # Try common DC naming patterns
    return f"DC01.{domain}"


# Common AD group patterns that should NOT be used as computer targets
GROUP_NAME_PATTERNS = [
    "DOMAIN CONTROLLERS",
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "SCHEMA ADMINS",
    "DNSADMINS",
    "CLONEABLE DOMAIN CONTROLLERS",
    "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
    "PROTECTED USERS",
    "KEY ADMINS",
    "ENTERPRISE KEY ADMINS",
    "CERT PUBLISHERS",
    "RAS AND IAS SERVERS",
    "ALLOWED RODC PASSWORD REPLICATION GROUP",
    "DENIED RODC PASSWORD REPLICATION GROUP",
    "READ-ONLY DOMAIN CONTROLLERS",
    "GROUP POLICY CREATOR OWNERS",
    "DOMAIN COMPUTERS",
    "DOMAIN GUESTS",
    "DOMAIN USERS",
    "ACCOUNT OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "BACKUP OPERATORS",
    "REPLICATOR",
]


def is_group_name(name: str) -> bool:
    """
    Detect if a name is a group (not a valid computer target).

    Groups like "DOMAIN CONTROLLERS@CORP.COM" should not be used
    as <TARGET> in attack commands.
    """
    if not name:
        return False
    upper = name.upper()
    # Check against known patterns
    for pattern in GROUP_NAME_PATTERNS:
        if pattern in upper:
            return True
    return False


# Sensitive placeholders that should never be auto-filled
SENSITIVE_PLACEHOLDERS: Set[str] = {
    "<PASSWORD>",
    "<HASH>",
    "<NTLM_HASH>",
    "<LM_HASH>",
    "<TICKET>",
    "<PRIVATE_KEY>",
    "<TARGET_USER>",  # User to DCSync - needs manual selection
}
