"""
BloodTrail Core Models

Data classes for Query, QueryResult, and DiscoveredCredential.

DiscoveredCredential represents credentials found during enumeration
(config files, SMB shares, etc.) with full provenance tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from ..credential_input import ParsedCredential


class SecretType(Enum):
    """Type of credential secret - extends CredType for discovery context."""
    PASSWORD = "password"
    NTLM_HASH = "ntlm-hash"
    AES256_KEY = "aes256-key"
    KERBEROS_TICKET = "kerberos-ticket"
    CERTIFICATE = "certificate"

    def to_cred_type(self) -> "CredType":
        """Convert to CredType for pipeline compatibility."""
        from ..credential_input import CredType
        mapping = {
            SecretType.PASSWORD: CredType.PASSWORD,
            SecretType.NTLM_HASH: CredType.NTLM_HASH,
            SecretType.KERBEROS_TICKET: CredType.KERBEROS_TICKET,
            SecretType.CERTIFICATE: CredType.CERTIFICATE,
            SecretType.AES256_KEY: CredType.PASSWORD,  # Fallback
        }
        return mapping.get(self, CredType.PASSWORD)


class SourceType(Enum):
    """How the credential was discovered."""
    CONFIG_FILE = "config_file"      # Parsed from config (azure.xml, web.config)
    SMB_SHARE = "smb_share"          # Found in SMB share
    GPP = "gpp"                      # Group Policy Preferences
    SPRAY = "spray"                  # Password spray hit
    DUMP = "dump"                    # Credential dump (secretsdump, mimikatz)
    POTFILE = "potfile"              # Cracked from potfile
    MANUAL = "manual"                # User-provided
    KERBEROAST = "kerberoast"        # Cracked from Kerberoast
    ASREP = "asrep"                  # Cracked from AS-REP roast
    LDAP = "ldap"                    # Found in LDAP attribute (description, etc.)


class Confidence(Enum):
    """Confidence level in the credential."""
    CONFIRMED = "confirmed"  # Validated and working
    LIKELY = "likely"        # High confidence but not validated
    POSSIBLE = "possible"    # Needs validation


@dataclass
class DiscoveredCredential:
    """
    Credential discovered during enumeration with full provenance.

    Unlike ParsedCredential (focused on input parsing), this tracks:
    - Where the credential was found (source path, share, etc.)
    - How it was discovered (config parsing, spray, dump, etc.)
    - Confidence level and validation status
    - Timestamp for timeline reconstruction

    Example:
        # From azure.xml in SMB share
        cred = DiscoveredCredential(
            username="mhope",
            secret="4n0therD4y@n0th3r$",
            secret_type=SecretType.PASSWORD,
            domain="MEGABANK.LOCAL",
            source="smb://10.10.10.172/users$/mhope/azure.xml",
            source_type=SourceType.CONFIG_FILE,
            confidence=Confidence.LIKELY,
        )

        # Validate and mark confirmed
        if validate(cred):
            cred.validated = True
            cred.confidence = Confidence.CONFIRMED
    """
    username: str
    secret: str
    secret_type: SecretType = SecretType.PASSWORD
    domain: Optional[str] = None
    source: str = ""              # Full path: "smb://host/share/path" or "/local/path"
    source_type: SourceType = SourceType.MANUAL
    confidence: Confidence = Confidence.POSSIBLE
    discovered_at: datetime = field(default_factory=datetime.now)
    validated: bool = False
    validation_method: Optional[str] = None  # "smb", "kerberos", "winrm"
    notes: str = ""               # Additional context

    def __post_init__(self):
        """Normalize fields after initialization."""
        # Uppercase domain for consistency
        if self.domain:
            self.domain = self.domain.upper()
        # Ensure datetime
        if isinstance(self.discovered_at, str):
            self.discovered_at = datetime.fromisoformat(self.discovered_at)

    @property
    def upn(self) -> str:
        """User Principal Name format: USER@DOMAIN.COM"""
        if self.domain:
            return f"{self.username.upper()}@{self.domain}"
        return self.username.upper()

    @property
    def sam_account(self) -> str:
        """SAM account format: DOMAIN\\username"""
        if self.domain:
            # Extract NetBIOS name if full domain
            netbios = self.domain.split('.')[0] if '.' in self.domain else self.domain
            return f"{netbios}\\{self.username}"
        return self.username

    def to_creds_string(self) -> str:
        """
        Format for --creds pipeline: DOMAIN/user:secret

        Returns:
            Credential string compatible with InlineCredentialParser
        """
        if self.domain:
            # Use NetBIOS format for compatibility
            netbios = self.domain.split('.')[0] if '.' in self.domain else self.domain
            return f"{netbios}/{self.username}:{self.secret}"
        return f"{self.username}:{self.secret}"

    def to_parsed_credential(self) -> "ParsedCredential":
        """
        Convert to ParsedCredential for pipeline compatibility.

        Returns:
            ParsedCredential instance for use with CredentialValidator, etc.
        """
        from ..credential_input import ParsedCredential
        return ParsedCredential(
            username=self.username,
            value=self.secret,
            cred_type=self.secret_type.to_cred_type(),
            domain=self.domain,
            source=self.source,
        )

    def to_neo4j_props(self) -> Dict[str, Any]:
        """
        Format for Neo4j pwned tracker storage.

        Returns:
            Dict of properties for PwnedTracker.mark_pwned()
        """
        return {
            "cred_type": self.secret_type.value,
            "cred_value": self.secret,
            "cred_source": self.source,
            "cred_source_type": self.source_type.value,
            "cred_confidence": self.confidence.value,
            "cred_validated": self.validated,
            "cred_discovered_at": self.discovered_at.isoformat(),
        }

    def mark_validated(self, method: str = "smb") -> "DiscoveredCredential":
        """
        Mark credential as validated.

        Args:
            method: Validation method used (smb, kerberos, winrm, ldap)

        Returns:
            Self for chaining
        """
        self.validated = True
        self.validation_method = method
        self.confidence = Confidence.CONFIRMED
        return self

    def __repr__(self) -> str:
        """Safe repr that masks the secret."""
        masked = self.secret[:4] + "..." if len(self.secret) > 4 else "***"
        status = "validated" if self.validated else self.confidence.value
        return (
            f"DiscoveredCredential("
            f"{self.upn}:{masked}, "
            f"type={self.secret_type.value}, "
            f"status={status}, "
            f"source={self.source_type.value})"
        )

    def __hash__(self) -> int:
        """Hash for deduplication (username + domain + secret)."""
        return hash((self.username.lower(), (self.domain or "").lower(), self.secret))

    def __eq__(self, other: object) -> bool:
        """Equality based on username, domain, and secret."""
        if not isinstance(other, DiscoveredCredential):
            return False
        return (
            self.username.lower() == other.username.lower() and
            (self.domain or "").lower() == (other.domain or "").lower() and
            self.secret == other.secret
        )

    @classmethod
    def from_parsed_credential(
        cls,
        parsed: "ParsedCredential",
        source_type: SourceType = SourceType.MANUAL,
        confidence: Confidence = Confidence.POSSIBLE,
    ) -> "DiscoveredCredential":
        """
        Create from existing ParsedCredential.

        Args:
            parsed: ParsedCredential from credential_input
            source_type: How it was discovered
            confidence: Confidence level

        Returns:
            New DiscoveredCredential instance
        """
        from ..credential_input import CredType

        # Map CredType to SecretType
        secret_type_map = {
            CredType.PASSWORD: SecretType.PASSWORD,
            CredType.NTLM_HASH: SecretType.NTLM_HASH,
            CredType.KERBEROS_TICKET: SecretType.KERBEROS_TICKET,
            CredType.CERTIFICATE: SecretType.CERTIFICATE,
        }

        return cls(
            username=parsed.username,
            secret=parsed.value,
            secret_type=secret_type_map.get(parsed.cred_type, SecretType.PASSWORD),
            domain=parsed.domain,
            source=parsed.source,
            source_type=source_type,
            confidence=confidence,
        )


@dataclass
class Query:
    """
    Represents a single Cypher query from the BloodTrail query library.

    Queries are loaded from cypher_queries/*.json files and contain
    metadata for categorization, variable substitution, and OSCP relevance.
    """
    id: str
    name: str
    description: str
    cypher: str
    category: str
    variables: Dict[str, Dict] = field(default_factory=dict)
    edge_types_used: List[str] = field(default_factory=list)
    oscp_relevance: str = "medium"
    expected_results: str = ""
    example_output: str = ""
    next_steps: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def has_variables(self) -> bool:
        """Check if query requires variable substitution."""
        return bool(self.variables)

    def get_required_variables(self) -> List[str]:
        """Get list of required variable names."""
        return [
            name for name, info in self.variables.items()
            if info.get("required", True)
        ]

    def substitute_variables(self, values: Dict[str, str]) -> str:
        """
        Substitute placeholders in the query with provided values.

        Args:
            values: Dict mapping variable names to their values
                   (e.g., {"USER": "PETE@CORP.COM"})

        Returns:
            Query string with <PLACEHOLDER>s replaced
        """
        result = self.cypher
        for var_name, var_value in values.items():
            placeholder = f"<{var_name}>"
            result = result.replace(placeholder, var_value)
        return result


@dataclass
class QueryResult:
    """
    Result from executing a Cypher query.

    Contains the query results, record count, any error messages,
    and optional attack command suggestions.
    """
    query_id: str
    success: bool
    records: List[Dict] = field(default_factory=list)
    record_count: int = 0
    error: Optional[str] = None
    cypher_executed: str = ""
    suggestions: List[Any] = field(default_factory=list)  # CommandSuggestion or AttackSequence
