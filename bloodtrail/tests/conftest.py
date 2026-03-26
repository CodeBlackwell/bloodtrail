"""
Pytest configuration and shared fixtures for BloodTrail tests.

Provides synthetic AD domain data for testing. All data is fictional
and models a realistic corporate Active Directory environment.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock
import base64
import json
import pytest

# Path setup for imports
bloodtrail_path = Path(__file__).parent.parent
if str(bloodtrail_path.parent) not in sys.path:
    sys.path.insert(0, str(bloodtrail_path.parent))

from bloodtrail.core.models import (
    DiscoveredCredential,
    Query,
    QueryResult,
    SecretType,
    SourceType,
    Confidence,
)
from bloodtrail.recommendation.models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
    Credential,
    CredentialType,
    AttackState,
)
from bloodtrail.recommendation.engine import RecommendationEngine
from bloodtrail.config import Neo4jConfig


# =============================================================================
# SYNTHETIC AD DOMAIN: CASCADE.LOCAL
# Modeled after real HTB/OSCP-style AD environments
# =============================================================================

DOMAIN = "CASCADE.LOCAL"
DC_IP = "10.10.10.182"
DC_HOSTNAME = "CASC-DC1"

AD_USERS = [
    {"name": "Administrator", "upn": "Administrator@cascade.local", "admincount": True},
    {"name": "krbtgt", "upn": "krbtgt@cascade.local"},
    {"name": "r.thompson", "upn": "r.thompson@cascade.local",
     "description": "IT Admin",
     "cascadeLegacyPwd": base64.b64encode(b"rY4n5eva").decode()},
    {"name": "s.smith", "upn": "s.smith@cascade.local",
     "description": "Audit user"},
    {"name": "j.wakefield", "upn": "j.wakefield@cascade.local"},
    {"name": "d.burman", "upn": "d.burman@cascade.local"},
    {"name": "svc_sql", "upn": "svc_sql@cascade.local",
     "spn": "MSSQLSvc/db01.cascade.local:1433",
     "description": "SQL Service Account - do not delete"},
    {"name": "svc_tgs", "upn": "svc_tgs@cascade.local",
     "spn": "HTTP/intranet.cascade.local",
     "description": "TGS service pwd: Ticketmaster1!"},
    {"name": "svc_backup", "upn": "svc_backup@cascade.local",
     "dontreqpreauth": True},
    {"name": "arksvc", "upn": "arksvc@cascade.local",
     "description": "AD Recycle Bin delegate"},
]

AD_GROUPS = [
    {"name": "Domain Admins", "members": ["Administrator"]},
    {"name": "Domain Users", "members": [u["name"] for u in AD_USERS]},
    {"name": "IT", "members": ["r.thompson", "s.smith"]},
    {"name": "Audit Share", "members": ["s.smith"]},
    {"name": "AD Recycle Bin", "members": ["arksvc"]},
    {"name": "Remote Management Users", "members": ["s.smith", "arksvc"]},
    {"name": "Exchange Windows Permissions", "members": []},
    {"name": "Backup Operators", "members": ["svc_backup"]},
    {"name": "Account Operators", "members": []},
]

AD_COMPUTERS = [
    {"name": "CASC-DC1.CASCADE.LOCAL", "os": "Windows Server 2019", "ip": DC_IP},
    {"name": "DB01.CASCADE.LOCAL", "os": "Windows Server 2016", "ip": "10.10.10.183"},
    {"name": "WS01.CASCADE.LOCAL", "os": "Windows 10", "ip": "10.10.10.184"},
]

SMB_SHARES = {
    "Data": {
        "IT/Temp/s.smith/VNC Install.reg": (
            b'[HKEY_LOCAL_MACHINE\\SOFTWARE\\TightVNC\\Server]\n'
            b'"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f\n'
        ),
        "IT/Email Archives/Meeting_Notes_June.html": b"<html>quarterly review</html>",
        "IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log": b"Deleted user TempAdmin",
        "Finance/budget_2025.xlsx": b"(binary)",
    },
    "Audit$": {
        "DB/Audit.db": b"SQLite format 3\x00",  # Simulated SQLite header
        "RunAudit.bat": b"CascAudit.exe /run",
        "CascAudit.exe": b"MZ...(binary)",
    },
    "NETLOGON": {},
    "SYSVOL": {
        "cascade.local/Policies/{GUID}/Machine/Preferences/Groups/Groups.xml": (
            b'<?xml version="1.0"?><Groups><User name="deploy" '
            b'cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQb'
            b'CPWHnXVVEGrU" /></Groups>'
        ),
    },
}

BLOODHOUND_EDGES = [
    {"source": "S.SMITH@CASCADE.LOCAL", "target": "CASC-DC1.CASCADE.LOCAL",
     "edge": "CanRDP", "is_acl": False},
    {"source": "ARKSVC@CASCADE.LOCAL", "target": "CASC-DC1.CASCADE.LOCAL",
     "edge": "CanRDP", "is_acl": False},
    {"source": "SVC_TGS@CASCADE.LOCAL", "target": "DB01.CASCADE.LOCAL",
     "edge": "AdminTo", "is_acl": False},
    {"source": "IT@CASCADE.LOCAL", "target": "AUDIT$@CASCADE.LOCAL",
     "edge": "GenericAll", "is_acl": True},
    {"source": "ARKSVC@CASCADE.LOCAL", "target": "CASCADE.LOCAL",
     "edge": "GetChanges", "is_acl": True},
]


# =============================================================================
# FIXTURES — Domain data
# =============================================================================

@pytest.fixture
def domain():
    return DOMAIN

@pytest.fixture
def dc_ip():
    return DC_IP

@pytest.fixture
def ad_users():
    return [dict(u) for u in AD_USERS]

@pytest.fixture
def ad_groups():
    return [dict(g, members=list(g["members"])) for g in AD_GROUPS]

@pytest.fixture
def ad_computers():
    return [dict(c) for c in AD_COMPUTERS]

@pytest.fixture
def smb_shares():
    return SMB_SHARES

@pytest.fixture
def bloodhound_edges():
    return list(BLOODHOUND_EDGES)


# =============================================================================
# FIXTURES — Credentials
# =============================================================================

@pytest.fixture
def discovered_credentials():
    """Credentials as they'd be found during enumeration."""
    return [
        DiscoveredCredential(
            username="r.thompson",
            secret="rY4n5eva",
            secret_type=SecretType.PASSWORD,
            domain=DOMAIN,
            source="ldap://10.10.10.182 cascadeLegacyPwd",
            source_type=SourceType.LDAP,
            confidence=Confidence.LIKELY,
        ),
        DiscoveredCredential(
            username="s.smith",
            secret="sT333ve2",
            secret_type=SecretType.PASSWORD,
            domain=DOMAIN,
            source="smb://10.10.10.182/Audit$/DB/Audit.db",
            source_type=SourceType.CONFIG_FILE,
            confidence=Confidence.CONFIRMED,
            validated=True,
            validation_method="smb",
        ),
        DiscoveredCredential(
            username="svc_tgs",
            secret="Ticketmaster1!",
            secret_type=SecretType.PASSWORD,
            domain=DOMAIN,
            source="LDAP description field",
            source_type=SourceType.LDAP,
            confidence=Confidence.LIKELY,
        ),
    ]


# =============================================================================
# FIXTURES — Findings & recommendations
# =============================================================================

@pytest.fixture
def ldap_password_finding():
    """Finding: base64-encoded password in LDAP attribute."""
    return Finding(
        id="finding_ldap_cascadeLegacyPwd",
        finding_type=FindingType.LDAP_ATTRIBUTE,
        source="ldap_enum",
        target="cascadeLegacyPwd",
        raw_value=base64.b64encode(b"rY4n5eva").decode(),
        decoded_value="rY4n5eva",
        decode_method="base64",
        metadata={"username": "r.thompson", "attribute": "cascadeLegacyPwd"},
        tags=["base64", "password_like"],
    )

@pytest.fixture
def vnc_file_finding():
    """Finding: VNC registry file with encrypted password."""
    return Finding(
        id="finding_vnc_install_reg",
        finding_type=FindingType.FILE,
        source="smb_crawl",
        target="IT/Temp/s.smith/VNC Install.reg",
        raw_value="6bcf2a4b6e5aca0f",
        metadata={
            "file_path": "IT/Temp/s.smith/VNC Install.reg",
            "file_name": "VNC Install.reg",
            "share": "Data",
            "inferred_user": "s.smith",
        },
        tags=["vnc", "encrypted"],
    )

@pytest.fixture
def recycle_bin_finding():
    """Finding: user is member of AD Recycle Bin group."""
    return Finding(
        id="finding_recycle_bin_arksvc",
        finding_type=FindingType.GROUP_MEMBERSHIP,
        source="bloodhound",
        target="arksvc",
        raw_value="AD Recycle Bin",
        metadata={"group": "AD Recycle Bin", "username": "arksvc"},
        tags=["privileged_group"],
    )

@pytest.fixture
def asrep_finding():
    """Finding: AS-REP roastable user."""
    return Finding(
        id="finding_asrep_svc_backup",
        finding_type=FindingType.USER_FLAG,
        source="kerbrute",
        target="svc_backup",
        raw_value="DONT_REQ_PREAUTH",
        metadata={"flag": "dontreqpreauth"},
        tags=["asrep"],
    )


@pytest.fixture
def recommendation_engine():
    """Pre-initialized engine targeting CASCADE.LOCAL."""
    return RecommendationEngine(target=DC_IP, domain=DOMAIN)


@pytest.fixture
def attack_state():
    """Attack state with target info set."""
    return AttackState(target=DC_IP, domain=DOMAIN)


# =============================================================================
# FIXTURES — Query & Neo4j
# =============================================================================

@pytest.fixture
def sample_query():
    return Query(
        id="find-asrep-roastable",
        name="AS-REP Roastable Users",
        description="Find users with Kerberos pre-auth disabled",
        cypher="MATCH (u:User {dontreqpreauth: true}) RETURN u.name",
        category="quick_wins",
        oscp_relevance="high",
        tags=["kerberos", "asrep"],
    )

@pytest.fixture
def sample_query_with_vars():
    return Query(
        id="shortest-path-to-user",
        name="Shortest Path to User",
        description="Find shortest attack path to a specific user",
        cypher="MATCH p=shortestPath((a)-[*1..]->(b:User {name: '<USER>'})) RETURN p",
        category="lateral_movement",
        variables={"USER": {"description": "Target user UPN", "required": True}},
    )

@pytest.fixture
def neo4j_config():
    return Neo4jConfig(uri="bolt://localhost:7687", user="neo4j", password="bloodtrail")

@pytest.fixture
def mock_neo4j_session():
    """Mocked Neo4j session that returns synthetic AD data."""
    session = MagicMock()

    def run_query(cypher, **params):
        result = MagicMock()
        # Return realistic data based on query content
        if "dontreqpreauth" in cypher.lower():
            result.data.return_value = [{"u.name": "SVC_BACKUP@CASCADE.LOCAL"}]
        elif "hasspn" in cypher.lower() or "serviceprincipalname" in cypher.lower():
            result.data.return_value = [
                {"u.name": "SVC_SQL@CASCADE.LOCAL", "u.serviceprincipalnames": ["MSSQLSvc/db01:1433"]},
                {"u.name": "SVC_TGS@CASCADE.LOCAL", "u.serviceprincipalnames": ["HTTP/intranet"]},
            ]
        elif "adminto" in cypher.lower():
            result.data.return_value = [
                {"u.name": "SVC_TGS@CASCADE.LOCAL", "c.name": "DB01.CASCADE.LOCAL"},
            ]
        elif "shortestpath" in cypher.lower():
            result.data.return_value = []
        else:
            result.data.return_value = []
        result.__iter__ = lambda self: iter(result.data())
        result.__len__ = lambda self: len(result.data())
        return result

    session.run = MagicMock(side_effect=run_query)
    return session


# =============================================================================
# FIXTURES — BloodHound JSON export (SharpHound format)
# =============================================================================

@pytest.fixture
def sharphound_users_json(tmp_path):
    """Synthetic SharpHound users JSON export."""
    data = {
        "data": [
            {
                "Properties": {
                    "name": u["name"].upper() + "@CASCADE.LOCAL",
                    "displayname": u["name"],
                    "enabled": True,
                    "hasspn": "spn" in u,
                    "dontreqpreauth": u.get("dontreqpreauth", False),
                    "admincount": u.get("admincount", False),
                    "description": u.get("description", ""),
                    "serviceprincipalnames": [u["spn"]] if "spn" in u else [],
                },
                "ObjectIdentifier": f"S-1-5-21-3332504370-1206983753-{3000 + i}",
                "Aces": [],
            }
            for i, u in enumerate(AD_USERS)
        ],
        "meta": {"type": "users", "count": len(AD_USERS), "version": 5},
    }
    path = tmp_path / "users.json"
    path.write_text(json.dumps(data))
    return path

@pytest.fixture
def sharphound_groups_json(tmp_path):
    """Synthetic SharpHound groups JSON export."""
    data = {
        "data": [
            {
                "Properties": {
                    "name": g["name"].upper() + "@CASCADE.LOCAL",
                },
                "Members": [
                    {"MemberId": m.upper() + "@CASCADE.LOCAL", "MemberType": "User"}
                    for m in g["members"]
                ],
                "ObjectIdentifier": f"S-1-5-21-3332504370-1206983753-{4000 + i}",
                "Aces": [],
            }
            for i, g in enumerate(AD_GROUPS)
        ],
        "meta": {"type": "groups", "count": len(AD_GROUPS), "version": 5},
    }
    path = tmp_path / "groups.json"
    path.write_text(json.dumps(data))
    return path

@pytest.fixture
def sharphound_computers_json(tmp_path):
    """Synthetic SharpHound computers JSON export."""
    data = {
        "data": [
            {
                "Properties": {
                    "name": c["name"],
                    "operatingsystem": c["os"],
                },
                "ObjectIdentifier": f"S-1-5-21-3332504370-1206983753-{5000 + i}",
                "Aces": [],
            }
            for i, c in enumerate(AD_COMPUTERS)
        ],
        "meta": {"type": "computers", "count": len(AD_COMPUTERS), "version": 5},
    }
    path = tmp_path / "computers.json"
    path.write_text(json.dumps(data))
    return path

@pytest.fixture
def sharphound_dir(tmp_path, sharphound_users_json, sharphound_groups_json, sharphound_computers_json):
    """Directory containing all SharpHound JSON exports."""
    return tmp_path
