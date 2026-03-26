"""
Access type metadata for bloodtrail.

BloodHound edge types with rewards, phases, priorities, and reason templates.
"""

from typing import Dict, Optional

from .base import AccessTypeInfo
from .text_utils import extract_username


ACCESS_TYPE_CATALOG: Dict[Optional[str], AccessTypeInfo] = {
    # === PRIVILEGE ESCALATION (100-199) ===
    "DCSync": AccessTypeInfo(
        reward="Dump all domain password hashes including krbtgt",
        phase="Privilege Escalation",
        priority=199,
        reason_template="{user} has DCSync rights (GetChanges+GetChangesAll)",
    ),
    "GoldenCert": AccessTypeInfo(
        reward="Forge any certificate with compromised CA key",
        phase="Privilege Escalation",
        priority=198,
        reason_template="CA {target} key compromised - forge any certificate",
    ),
    "GenericAll": AccessTypeInfo(
        reward="Full control - reset passwords, modify group membership",
        phase="Privilege Escalation",
        priority=195,
        reason_template="{user} has GenericAll over {target}",
    ),
    "WriteOwner": AccessTypeInfo(
        reward="Take ownership then modify DACL for full control",
        phase="Privilege Escalation",
        priority=190,
        reason_template="{user} can take ownership of {target}",
    ),
    "WriteDacl": AccessTypeInfo(
        reward="Grant yourself additional permissions on object",
        phase="Privilege Escalation",
        priority=185,
        reason_template="{user} can modify DACL on {target}",
    ),
    "Owns": AccessTypeInfo(
        reward="Full object control - reset password or modify permissions",
        phase="Privilege Escalation",
        priority=180,
        reason_template="{user} owns {target} - full control",
    ),
    "ForceChangePassword": AccessTypeInfo(
        reward="Reset user password without knowing current",
        phase="Privilege Escalation",
        priority=175,
        reason_template="{user} can reset password for {target}",
    ),
    "AddKeyCredentialLink": AccessTypeInfo(
        reward="Add shadow credentials for certificate-based auth",
        phase="Privilege Escalation",
        priority=170,
        reason_template="{user} can add shadow credentials to {target}",
    ),
    "ReadGMSAPassword": AccessTypeInfo(
        reward="Retrieve cleartext gMSA password for authentication",
        phase="Privilege Escalation",
        priority=165,
        reason_template="{user} can read gMSA password for {target}",
    ),
    "ReadLAPSPassword": AccessTypeInfo(
        reward="Retrieve local admin password from LAPS",
        phase="Privilege Escalation",
        priority=160,
        reason_template="{user} can read LAPS password on {target}",
    ),
    "SyncLAPSPassword": AccessTypeInfo(
        reward="Domain-wide LAPS password retrieval",
        phase="Privilege Escalation",
        priority=158,
        reason_template="{user} has domain-wide LAPS sync rights",
    ),
    "AddMember": AccessTypeInfo(
        reward="Add yourself to privileged groups",
        phase="Privilege Escalation",
        priority=155,
        reason_template="{user} can add members to {target}",
    ),
    "GenericWrite": AccessTypeInfo(
        reward="Add SPN for Kerberoasting or modify attributes",
        phase="Privilege Escalation",
        priority=150,
        reason_template="{user} has GenericWrite on {target}",
    ),
    "WriteSPN": AccessTypeInfo(
        reward="Add SPN for targeted Kerberoasting attack",
        phase="Privilege Escalation",
        priority=145,
        reason_template="{user} can add SPN to {target} for targeted Kerberoasting",
    ),
    "ADCSESC1": AccessTypeInfo(
        reward="Request certificate as any user for domain admin access",
        phase="Privilege Escalation",
        priority=140,
        reason_template="{user} can request cert as any user via {target}",
    ),
    "ADCSESC3": AccessTypeInfo(
        reward="Enrollment agent abuse for user impersonation",
        phase="Privilege Escalation",
        priority=138,
        reason_template="{user} can enroll on behalf of others via {target}",
    ),
    "ADCSESC4": AccessTypeInfo(
        reward="Modify template to enable ESC1 vulnerability",
        phase="Privilege Escalation",
        priority=135,
        reason_template="{user} can modify template {target} for ESC1",
    ),
    "ADCSESC6a": AccessTypeInfo(
        reward="Request cert with arbitrary SAN for impersonation",
        phase="Privilege Escalation",
        priority=132,
        reason_template="{user} can exploit EDITF_ATTRIBUTESUBJECTALTNAME2 on {target}",
    ),
    "ADCSESC6b": AccessTypeInfo(
        reward="Bypass issuance requirements for unauthorized certs",
        phase="Privilege Escalation",
        priority=130,
        reason_template="{user} can bypass issuance requirements on {target}",
    ),
    "ADCSESC7": AccessTypeInfo(
        reward="Approve pending certificate requests as CA manager",
        phase="Privilege Escalation",
        priority=128,
        reason_template="{user} can manage CA {target} - approve pending requests",
    ),
    "ADCSESC5": AccessTypeInfo(
        reward="PKI object modification for certificate abuse",
        phase="Privilege Escalation",
        priority=125,
        reason_template="{user} can modify PKI object {target}",
    ),
    "ADCSESC9a": AccessTypeInfo(
        reward="Bypass security extension for certificate abuse",
        phase="Privilege Escalation",
        priority=122,
        reason_template="{user} can exploit no security extension on {target}",
    ),
    "ADCSESC9b": AccessTypeInfo(
        reward="Exploit weak certificate mapping for impersonation",
        phase="Privilege Escalation",
        priority=120,
        reason_template="{user} can exploit weak certificate mapping on {target}",
    ),
    "ADCSESC10a": AccessTypeInfo(
        reward="Exploit weak cert binding for authentication",
        phase="Privilege Escalation",
        priority=118,
        reason_template="{user} can exploit weak cert binding on {target}",
    ),
    "ADCSESC10b": AccessTypeInfo(
        reward="Shadow credentials via ADCS for persistent access",
        phase="Privilege Escalation",
        priority=115,
        reason_template="{user} can add shadow credentials via {target}",
    ),
    "ADCSESC13": AccessTypeInfo(
        reward="OID group link for privilege escalation",
        phase="Privilege Escalation",
        priority=112,
        reason_template="{user} can exploit OID group link on {target}",
    ),
    "Enroll": AccessTypeInfo(
        reward="Request certificates for authentication",
        phase="Privilege Escalation",
        priority=105,
        reason_template="{user} can enroll in template {target}",
    ),
    "EnrollOnBehalfOf": AccessTypeInfo(
        reward="Request certificates impersonating other users",
        phase="Privilege Escalation",
        priority=103,
        reason_template="{user} can enroll certificates on behalf of others",
    ),
    "ManageCA": AccessTypeInfo(
        reward="CA management for certificate manipulation",
        phase="Privilege Escalation",
        priority=101,
        reason_template="{user} can manage CA {target}",
    ),
    "ManageCertificates": AccessTypeInfo(
        reward="Approve/deny certificate requests",
        phase="Privilege Escalation",
        priority=100,
        reason_template="{user} can approve certificate requests on {target}",
    ),
    # === LATERAL MOVEMENT (50-99) ===
    "AdminTo": AccessTypeInfo(
        reward="SYSTEM shell for credential dumping, persistence, and pivoting",
        phase="Lateral Movement",
        priority=99,
        reason_template="{user} has local admin rights on {target}",
    ),
    "ExecuteDCOM": AccessTypeInfo(
        reward="Remote code execution via DCOM for lateral movement",
        phase="Lateral Movement",
        priority=90,
        reason_template="{user} can execute DCOM on {target}",
    ),
    "CanPSRemote": AccessTypeInfo(
        reward="PowerShell remoting for stealthy command execution",
        phase="Lateral Movement",
        priority=85,
        reason_template="{user} has PSRemote/WinRM access to {target}",
    ),
    "HasSession": AccessTypeInfo(
        reward="Harvest cached credentials from logged-in privileged user",
        phase="Lateral Movement",
        priority=80,
        reason_template="Privileged session active on {target} - credential harvest",
    ),
    "AllowedToDelegate": AccessTypeInfo(
        reward="Impersonate any user to target service via S4U",
        phase="Lateral Movement",
        priority=75,
        reason_template="{user} has constrained delegation to {target}",
    ),
    "AllowedToAct": AccessTypeInfo(
        reward="Impersonate users via RBCD for privileged access",
        phase="Lateral Movement",
        priority=73,
        reason_template="{user} can impersonate users to {target} via RBCD",
    ),
    "AddAllowedToAct": AccessTypeInfo(
        reward="Configure RBCD to enable user impersonation",
        phase="Lateral Movement",
        priority=71,
        reason_template="{user} can add RBCD principals to {target}",
    ),
    "WriteAccountRestrictions": AccessTypeInfo(
        reward="Modify RBCD settings for delegation abuse",
        phase="Lateral Movement",
        priority=70,
        reason_template="{user} can configure RBCD on {target}",
    ),
    "CanRDP": AccessTypeInfo(
        reward="Interactive desktop access for GUI tools and credential theft",
        phase="Lateral Movement",
        priority=65,
        reason_template="{user} has RDP access to {target}",
    ),
    "CoerceToTGT": AccessTypeInfo(
        reward="Capture TGT for pass-the-ticket attacks",
        phase="Lateral Movement",
        priority=60,
        reason_template="{user} can coerce {target} auth to capture TGT",
    ),
    "HasSIDHistory": AccessTypeInfo(
        reward="Inherited permissions from historical SID membership",
        phase="Lateral Movement",
        priority=55,
        reason_template="{user} has SID history granting access to {target}",
    ),
    "TrustedBy": AccessTypeInfo(
        reward="Cross-domain access via trust relationship",
        phase="Lateral Movement",
        priority=50,
        reason_template="{target} trusts {user}'s domain",
    ),
    # === QUICK WINS (0-49) ===
    None: AccessTypeInfo(
        reward="Potential attack vector identified",
        phase="Quick Wins",
        priority=10,
        reason_template="",
    ),
}


# Backward-compatible dictionary views (generated from ACCESS_TYPE_CATALOG)
ACCESS_TYPE_REWARDS: Dict[Optional[str], str] = {
    k: v.reward for k, v in ACCESS_TYPE_CATALOG.items()
}

ACCESS_TYPE_PHASES: Dict[Optional[str], str] = {
    k: v.phase for k, v in ACCESS_TYPE_CATALOG.items()
}

ACCESS_TYPE_PRIORITY: Dict[Optional[str], int] = {
    k: v.priority for k, v in ACCESS_TYPE_CATALOG.items()
}

ACCESS_TYPE_REASONS: Dict[Optional[str], str] = {
    k: v.reason_template for k, v in ACCESS_TYPE_CATALOG.items()
}


def get_reason(
    access_type: Optional[str],
    user: str,
    target: str,
    context: str = ""
) -> str:
    """
    Generate human-readable reason for command suggestion.

    Args:
        access_type: BloodHound edge type (AdminTo, CanRDP, etc.)
        user: User principal with access
        target: Target computer or user
        context: Additional context from query mapping

    Returns:
        Human-readable reason string
    """
    # Try access_type template first
    template = ACCESS_TYPE_REASONS.get(access_type, "")

    if template:
        # Format with user/target, handling missing values
        user_short = extract_username(user) if user else "User"
        target_short = target.split(".")[0] if target else "target"
        return template.format(user=user_short, target=target_short)

    # Fall back to context if no access_type reason
    if context:
        return context

    # Generic fallback
    if access_type:
        return f"{access_type} relationship"

    return "BloodHound finding"
