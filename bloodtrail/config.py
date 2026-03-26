"""
Configuration for BloodHound Edge Enhancer

Credentials should be set via environment variables:
  - NEO4J_URI:      bolt://localhost:7687 (default)
  - NEO4J_USER:     neo4j (default)
  - NEO4J_PASSWORD: (required - set via environment variable)
"""

import os
from dataclasses import dataclass
from typing import Dict, Set

# Neo4j connection defaults (password from environment only)
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

# Listener defaults (for reverse shell payloads)
# Set these to avoid passing --lhost/--lport every time
LHOST = None  # e.g., "192.168.45.200"
LPORT = None  # e.g., 443

# Batch processing
DEFAULT_BATCH_SIZE = 500

# Well-known SIDs that appear in BloodHound data
# These are consistent across all Windows domains
WELL_KNOWN_SIDS: Dict[str, tuple] = {
    # Local groups (BUILTIN)
    "S-1-5-32-544": ("BUILTIN\\Administrators", "Group"),
    "S-1-5-32-545": ("BUILTIN\\Users", "Group"),
    "S-1-5-32-546": ("BUILTIN\\Guests", "Group"),
    "S-1-5-32-547": ("BUILTIN\\Power Users", "Group"),
    "S-1-5-32-548": ("BUILTIN\\Account Operators", "Group"),
    "S-1-5-32-549": ("BUILTIN\\Server Operators", "Group"),
    "S-1-5-32-550": ("BUILTIN\\Print Operators", "Group"),
    "S-1-5-32-551": ("BUILTIN\\Backup Operators", "Group"),
    "S-1-5-32-552": ("BUILTIN\\Replicator", "Group"),
    "S-1-5-32-554": ("BUILTIN\\Pre-Windows 2000 Compatible Access", "Group"),
    "S-1-5-32-555": ("BUILTIN\\Remote Desktop Users", "Group"),
    "S-1-5-32-556": ("BUILTIN\\Network Configuration Operators", "Group"),
    "S-1-5-32-557": ("BUILTIN\\Incoming Forest Trust Builders", "Group"),
    "S-1-5-32-558": ("BUILTIN\\Performance Monitor Users", "Group"),
    "S-1-5-32-559": ("BUILTIN\\Performance Log Users", "Group"),
    "S-1-5-32-560": ("BUILTIN\\Windows Authorization Access Group", "Group"),
    "S-1-5-32-561": ("BUILTIN\\Terminal Server License Servers", "Group"),
    "S-1-5-32-562": ("BUILTIN\\Distributed COM Users", "Group"),
    "S-1-5-32-568": ("BUILTIN\\IIS_IUSRS", "Group"),
    "S-1-5-32-569": ("BUILTIN\\Cryptographic Operators", "Group"),
    "S-1-5-32-573": ("BUILTIN\\Event Log Readers", "Group"),
    "S-1-5-32-574": ("BUILTIN\\Certificate Service DCOM Access", "Group"),
    "S-1-5-32-575": ("BUILTIN\\RDS Remote Access Servers", "Group"),
    "S-1-5-32-576": ("BUILTIN\\RDS Endpoint Servers", "Group"),
    "S-1-5-32-577": ("BUILTIN\\RDS Management Servers", "Group"),
    "S-1-5-32-578": ("BUILTIN\\Hyper-V Administrators", "Group"),
    "S-1-5-32-579": ("BUILTIN\\Access Control Assistance Operators", "Group"),
    "S-1-5-32-580": ("BUILTIN\\Remote Management Users", "Group"),

    # Special identities
    "S-1-1-0": ("Everyone", "Group"),
    "S-1-5-7": ("Anonymous Logon", "User"),
    "S-1-5-9": ("Enterprise Domain Controllers", "Group"),
    "S-1-5-11": ("Authenticated Users", "Group"),
    "S-1-5-18": ("Local System", "User"),
    "S-1-5-19": ("Local Service", "User"),
    "S-1-5-20": ("Network Service", "User"),
}

# Domain-relative RIDs (append to domain SID)
DOMAIN_RIDS: Dict[int, tuple] = {
    500: ("Administrator", "User"),
    501: ("Guest", "User"),
    502: ("krbtgt", "User"),
    512: ("Domain Admins", "Group"),
    513: ("Domain Users", "Group"),
    514: ("Domain Guests", "Group"),
    515: ("Domain Computers", "Group"),
    516: ("Domain Controllers", "Group"),
    517: ("Cert Publishers", "Group"),
    518: ("Schema Admins", "Group"),
    519: ("Enterprise Admins", "Group"),
    520: ("Group Policy Creator Owners", "Group"),
    521: ("Read-only Domain Controllers", "Group"),
    522: ("Cloneable Domain Controllers", "Group"),
    525: ("Protected Users", "Group"),
    526: ("Key Admins", "Group"),
    527: ("Enterprise Key Admins", "Group"),
    553: ("RAS and IAS Servers", "Group"),
    571: ("Allowed RODC Password Replication Group", "Group"),
    572: ("Denied RODC Password Replication Group", "Group"),
}

# ACE RightName -> Neo4j relationship type mapping
ACE_EDGE_MAPPINGS: Dict[str, str] = {
    # Ownership
    "Owns": "Owns",

    # Generic permissions
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteProperty": "WriteProperty",  # GPO/object property modification

    # ACL modification
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",

    # Extended rights
    "AllExtendedRights": "AllExtendedRights",
    "ForceChangePassword": "ForceChangePassword",
    "AddKeyCredentialLink": "AddKeyCredentialLink",

    # DCSync rights (critical for attack paths)
    "GetChanges": "GetChanges",
    "GetChangesAll": "GetChangesAll",
    "GetChangesInFilteredSet": "GetChangesInFilteredSet",

    # Group membership
    "AddMember": "AddMember",
    "AddSelf": "AddSelf",

    # LAPS/GMSA credential access
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword",
    "SyncLAPSPassword": "SyncLAPSPassword",
    "DumpSMSAPassword": "DumpSMSAPassword",

    # Kerberos/SPN manipulation
    "WriteSPN": "WriteSPN",
    "WriteAccountRestrictions": "WriteAccountRestrictions",  # RBCD

    # Certificate Services
    "Enroll": "Enroll",
    "ManageCA": "ManageCA",
    "ManageCertificates": "ManageCertificates",
    "WritePKIEnrollmentFlag": "WritePKIEnrollmentFlag",
    "WritePKINameFlag": "WritePKINameFlag",

    # GPO manipulation
    "WriteGPLink": "WriteGPLink",

    # RBCD
    "AddAllowedToAct": "AddAllowedToAct",
}

# Attack-path focused edge types (--preset attack-paths)
ATTACK_PATH_EDGES: Set[str] = {
    # Computer access
    "AdminTo",
    "CanPSRemote",
    "CanRDP",
    "ExecuteDCOM",
    "HasSession",

    # ACL abuse
    "GenericAll",
    "GenericWrite",
    "WriteProperty",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "AllExtendedRights",
    "ForceChangePassword",
    "AddKeyCredentialLink",
    "AddMember",

    # DCSync
    "GetChanges",
    "GetChangesAll",

    # Membership
    "MemberOf",

    # Delegation
    "AllowedToDelegate",
    "AllowedToAct",

    # Credential access
    "ReadLAPSPassword",
    "ReadGMSAPassword",

    # Kerberos manipulation
    "WriteSPN",
    "WriteAccountRestrictions",
}

# ADCS-focused edge types (--preset adcs)
ADCS_EDGES: Set[str] = {
    # Certificate enrollment
    "Enroll",
    "ManageCA",
    "ManageCertificates",
    "WritePKIEnrollmentFlag",
    "WritePKINameFlag",

    # BloodHound CE ESC edges (computed by BH, not extracted)
    "ADCSESC1",
    "ADCSESC3",
    "ADCSESC4",
    "ADCSESC5",
    "ADCSESC6a",
    "ADCSESC6b",
    "ADCSESC7",
    "ADCSESC9a",
    "ADCSESC9b",
    "ADCSESC10a",
    "ADCSESC10b",
    "ADCSESC13",
    "GoldenCert",
    "EnrollOnBehalfOf",
}

# Coercion and trust edges
COERCION_EDGES: Set[str] = {
    "CoerceToTGT",
    "TrustedBy",
    "HasSIDHistory",
    "DCSync",  # Computed edge
}

# All supported edge types
ALL_EDGES: Set[str] = ATTACK_PATH_EDGES | ADCS_EDGES | COERCION_EDGES | {
    "AddSelf",
    "GetChangesInFilteredSet",
    "SyncLAPSPassword",
    "DumpSMSAPassword",
    "WriteGPLink",
    "AddAllowedToAct",
}

# Preset configurations
EDGE_PRESETS: Dict[str, Set[str]] = {
    "attack-paths": ATTACK_PATH_EDGES,
    "adcs": ADCS_EDGES,
    "coercion": COERCION_EDGES,
    "all": ALL_EDGES,
    "minimal": {"AdminTo", "MemberOf", "HasSession", "GenericAll"},
}


@dataclass
class Neo4jConfig:
    """Neo4j connection configuration"""
    uri: str = NEO4J_URI
    user: str = NEO4J_USER
    password: str = None  # Read from environment at runtime
    batch_size: int = DEFAULT_BATCH_SIZE

    def __post_init__(self):
        """Validate configuration - read password from env at runtime if not provided"""
        # Read from environment at runtime (not import time) if password not provided
        if self.password is None:
            self.password = os.environ.get("NEO4J_PASSWORD", "")

        if not self.password:
            import warnings
            warnings.warn(
                "NEO4J_PASSWORD not set. Set via: export NEO4J_PASSWORD='your_password'",
                UserWarning
            )
