"""
Recommendation Engine Data Models.

Core data structures for the finding → recommendation flow.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional
from datetime import datetime


class FindingType(Enum):
    """Types of findings that can trigger recommendations."""
    LDAP_ATTRIBUTE = auto()      # Custom LDAP attribute (cascadeLegacyPwd)
    FILE = auto()                # Interesting file (VNC .reg, SQLite, etc.)
    GROUP_MEMBERSHIP = auto()    # User in interesting group (AD Recycle Bin)
    CREDENTIAL = auto()          # Discovered credential (validated or not)
    USER_FLAG = auto()           # User account flag (PWNOTREQ, AS-REP, etc.)
    SERVICE = auto()             # Discovered service
    SHARE = auto()               # SMB share access
    POLICY = auto()              # Password policy info
    BLOODHOUND_PATH = auto()     # Attack path from BloodHound analysis


class CredentialType(Enum):
    """Types of credentials."""
    PASSWORD = auto()
    NTLM_HASH = auto()
    KERBEROS_TICKET = auto()
    SSH_KEY = auto()
    CERTIFICATE = auto()


class RecommendationPriority(Enum):
    """Priority levels for recommendations."""
    CRITICAL = 1    # Act immediately (valid credential discovered)
    HIGH = 2        # Strong attack vector (AS-REP roastable)
    MEDIUM = 3      # Worth investigating (interesting file)
    LOW = 4         # Background task (general enumeration)
    INFO = 5        # For reference only (domain info)


@dataclass
class Credential:
    """A discovered credential."""
    id: str
    username: str
    credential_type: CredentialType
    value: str                      # Password, hash, etc.
    domain: Optional[str] = None
    validated: bool = False
    access_level: Optional[str] = None  # "user", "admin", "service"
    source_finding: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    notes: List[str] = field(default_factory=list)

    def __hash__(self):
        return hash(self.id)


@dataclass
class Finding:
    """
    A single discovered fact from enumeration.

    Findings are the input to the recommendation engine.
    Each finding can trigger zero or more recommendations.
    """
    id: str
    finding_type: FindingType
    source: str                     # "ldap_enum", "smb_crawl", etc.
    target: str                     # User, file path, etc.
    raw_value: Any                  # The actual data
    confidence: float = 1.0         # 0.0 - 1.0
    tags: List[str] = field(default_factory=list)  # ["base64", "encrypted"]
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    # For decoded values
    decoded_value: Optional[str] = None
    decode_method: Optional[str] = None

    def __hash__(self):
        return hash(self.id)

    def add_tag(self, tag: str) -> None:
        """Add a tag if not present."""
        if tag not in self.tags:
            self.tags.append(tag)


@dataclass
class Recommendation:
    """
    A suggested next action based on findings.

    Recommendations guide the user through one action at a time.
    """
    id: str
    priority: RecommendationPriority
    trigger_finding_id: str         # What finding caused this
    action_type: str                # "run_command", "manual_step", "tool_use"
    description: str                # Human readable
    why: str                        # Explanation of WHY this matters
    command: Optional[str] = None   # Command to run (if applicable)
    requires: List[str] = field(default_factory=list)  # Prerequisite finding IDs
    invalidated_by: List[str] = field(default_factory=list)  # Skip if these exist
    on_success: List[str] = field(default_factory=list)  # Next recommendations
    on_failure: List[str] = field(default_factory=list)  # Fallback recommendations
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __lt__(self, other: "Recommendation") -> bool:
        """For priority queue ordering (lower priority value = higher priority)."""
        return self.priority.value < other.priority.value


@dataclass
class AttackState:
    """
    Current state of the engagement.

    Tracks all findings, credentials, and recommendations
    to avoid repetition and guide the attack.
    """
    # Target info
    target: str = ""
    domain: Optional[str] = None

    # Discovered data
    findings: Dict[str, Finding] = field(default_factory=dict)
    credentials: Dict[str, Credential] = field(default_factory=dict)

    # Recommendation tracking
    pending_recommendations: List[Recommendation] = field(default_factory=list)
    completed_actions: List[str] = field(default_factory=list)  # Recommendation IDs
    skipped_actions: List[str] = field(default_factory=list)    # Recommendation IDs

    # Access tracking
    current_access_level: str = "anonymous"  # "anonymous", "user", "admin"
    current_user: Optional[str] = None

    # Session tracking
    session_start: datetime = field(default_factory=datetime.now)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to state."""
        self.findings[finding.id] = finding

    def add_credential(self, credential: Credential) -> None:
        """Add a credential to state."""
        self.credentials[credential.id] = credential
        if credential.validated:
            self.current_access_level = credential.access_level or "user"
            self.current_user = credential.username

    def add_recommendation(self, rec: Recommendation) -> None:
        """Add a recommendation to pending queue (maintains priority order)."""
        # Check if already completed or skipped
        if rec.id in self.completed_actions or rec.id in self.skipped_actions:
            return

        # Check if invalidated by existing findings
        for inv_finding_id in rec.invalidated_by:
            if inv_finding_id in self.findings:
                return

        # Check if prerequisites are met
        for req_finding_id in rec.requires:
            if req_finding_id not in self.findings:
                return

        # Add if not already pending
        if not any(r.id == rec.id for r in self.pending_recommendations):
            self.pending_recommendations.append(rec)
            self.pending_recommendations.sort()  # Sort by priority

    def complete_recommendation(self, rec_id: str) -> None:
        """Mark a recommendation as completed."""
        self.completed_actions.append(rec_id)
        self.pending_recommendations = [
            r for r in self.pending_recommendations if r.id != rec_id
        ]

    def skip_recommendation(self, rec_id: str) -> None:
        """Mark a recommendation as skipped."""
        self.skipped_actions.append(rec_id)
        self.pending_recommendations = [
            r for r in self.pending_recommendations if r.id != rec_id
        ]

    def get_next_recommendation(self) -> Optional[Recommendation]:
        """Get the highest priority pending recommendation."""
        if self.pending_recommendations:
            return self.pending_recommendations[0]
        return None

    def has_finding_type(self, finding_type: FindingType) -> bool:
        """Check if we have any findings of a specific type."""
        return any(f.finding_type == finding_type for f in self.findings.values())

    def get_validated_credentials(self) -> List[Credential]:
        """Get all validated credentials."""
        return [c for c in self.credentials.values() if c.validated]
