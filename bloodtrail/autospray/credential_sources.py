"""
Credential Sources for Auto Password Spray

Gathers passwords from multiple sources:
- Neo4j: Extract from pwned users' stored credentials
- Common: Built-in patterns (Season+Year, Company+123, etc.)
- Wordlist: User-specified password file
- Potfile: Hashcat/John cracked passwords
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set, Iterator
import re


class CredentialType(Enum):
    """Type of credential."""
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    AES_KEY = "aes_key"


@dataclass
class Credential:
    """
    Single credential with optional metadata.

    Attributes:
        value: The actual password/hash value
        cred_type: Type of credential (password, hash, etc.)
        source: Where this came from (neo4j, potfile, wordlist, common)
        username: Optional associated username (for user:pass pairs)
    """
    value: str
    cred_type: CredentialType = CredentialType.PASSWORD
    source: str = "unknown"
    username: Optional[str] = None

    def __hash__(self):
        return hash((self.value, self.cred_type))

    def __eq__(self, other):
        if not isinstance(other, Credential):
            return False
        return self.value == other.value and self.cred_type == other.cred_type


class CredentialSource(ABC):
    """Abstract base class for credential sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable source name."""
        pass

    @abstractmethod
    def get_credentials(self) -> List[Credential]:
        """Retrieve credentials from this source."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this source is accessible."""
        pass

    def get_passwords(self) -> List[str]:
        """Get just the password values (convenience method)."""
        return [c.value for c in self.get_credentials()
                if c.cred_type == CredentialType.PASSWORD]


class Neo4jCredentialSource(CredentialSource):
    """
    Extract credentials from pwned users in Neo4j.

    Queries User nodes where pwned=true and extracts passwords
    from pwned_cred_values parallel array.
    """

    def __init__(self, neo4j_config):
        """
        Initialize with Neo4j configuration.

        Args:
            neo4j_config: Neo4jConfig object with connection details
        """
        self.config = neo4j_config
        self._driver = None

    @property
    def name(self) -> str:
        return "Neo4j Pwned Users"

    def _connect(self):
        """Establish Neo4j connection."""
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
        return self._driver

    def is_available(self) -> bool:
        """Check if Neo4j is accessible."""
        try:
            driver = self._connect()
            with driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception:
            return False

    def get_credentials(self) -> List[Credential]:
        """
        Extract credentials from pwned users.

        Returns passwords stored in u.pwned_cred_values where
        the corresponding u.pwned_cred_types entry is 'password'.
        """
        credentials = []

        try:
            driver = self._connect()
            with driver.session() as session:
                result = session.run("""
                    MATCH (u:User)
                    WHERE u.pwned = true
                      AND u.pwned_cred_types IS NOT NULL
                      AND u.pwned_cred_values IS NOT NULL
                    RETURN u.name AS username,
                           u.pwned_cred_types AS types,
                           u.pwned_cred_values AS values
                """)

                for record in result:
                    username = record["username"]
                    types = record["types"] or []
                    values = record["values"] or []

                    # Parallel arrays - match type to value
                    for cred_type, cred_value in zip(types, values):
                        if cred_type == "password" and cred_value:
                            credentials.append(Credential(
                                value=cred_value,
                                cred_type=CredentialType.PASSWORD,
                                source="neo4j",
                                username=username,
                            ))
                        elif cred_type == "ntlm_hash" and cred_value:
                            credentials.append(Credential(
                                value=cred_value,
                                cred_type=CredentialType.NTLM_HASH,
                                source="neo4j",
                                username=username,
                            ))
        except Exception as e:
            # Log but don't fail - just return empty
            pass

        return credentials

    def close(self):
        """Close Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._driver = None


class WordlistSource(CredentialSource):
    """
    User-specified password wordlist file.

    Reads passwords from a text file (one per line).
    """

    def __init__(self, wordlist_path: Path, max_passwords: int = 1000):
        """
        Initialize wordlist source.

        Args:
            wordlist_path: Path to wordlist file
            max_passwords: Maximum passwords to load (default 1000)
        """
        self.path = Path(wordlist_path)
        self.max_passwords = max_passwords

    @property
    def name(self) -> str:
        return f"Wordlist ({self.path.name})"

    def is_available(self) -> bool:
        """Check if wordlist file exists and is readable."""
        return self.path.exists() and self.path.is_file()

    def get_credentials(self) -> List[Credential]:
        """Read passwords from wordlist file."""
        if not self.is_available():
            return []

        credentials = []
        count = 0

        try:
            with open(self.path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if count >= self.max_passwords:
                        break

                    password = line.strip()
                    if password and not password.startswith('#'):
                        credentials.append(Credential(
                            value=password,
                            source="wordlist",
                        ))
                        count += 1
        except Exception:
            pass

        return credentials


class PotfileSource(CredentialSource):
    """
    Parse hashcat/john potfiles for cracked passwords.

    Potfile format: hash:password (one per line)
    Extracts just the password portion after the last colon.
    """

    # Default potfile locations
    HASHCAT_POTFILE = Path.home() / ".local" / "share" / "hashcat" / "hashcat.potfile"
    HASHCAT_POTFILE_ALT = Path.home() / ".hashcat" / "hashcat.potfile"
    JOHN_POTFILE = Path.home() / ".john" / "john.pot"

    def __init__(self, potfile_path: Optional[Path] = None):
        """
        Initialize potfile source.

        Args:
            potfile_path: Custom potfile path (auto-detects if not specified)
        """
        self.custom_path = Path(potfile_path) if potfile_path else None
        self._detected_path: Optional[Path] = None

    @property
    def name(self) -> str:
        path = self._get_potfile_path()
        if path:
            return f"Potfile ({path.name})"
        return "Potfile (not found)"

    def _get_potfile_path(self) -> Optional[Path]:
        """Find the potfile to use."""
        if self.custom_path and self.custom_path.exists():
            return self.custom_path

        # Auto-detect
        for path in [self.HASHCAT_POTFILE, self.HASHCAT_POTFILE_ALT, self.JOHN_POTFILE]:
            if path.exists():
                return path

        return None

    def is_available(self) -> bool:
        """Check if a potfile exists."""
        return self._get_potfile_path() is not None

    def get_credentials(self) -> List[Credential]:
        """Parse potfile and extract passwords."""
        potfile = self._get_potfile_path()
        if not potfile:
            return []

        credentials = []
        seen_passwords: Set[str] = set()

        try:
            with open(potfile, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Format: hash:password or $format$hash:password
                    # Take everything after the last colon
                    if ':' in line:
                        # Handle complex formats like $krb5tgs$23$*...*:password
                        password = line.rsplit(':', 1)[-1]

                        # Skip if it looks like a hash component
                        if password and not self._looks_like_hash(password):
                            if password not in seen_passwords:
                                seen_passwords.add(password)
                                credentials.append(Credential(
                                    value=password,
                                    source="potfile",
                                ))
        except Exception:
            pass

        return credentials

    @staticmethod
    def _looks_like_hash(value: str) -> bool:
        """Check if value looks like a hash (hex string, starts with $)."""
        if value.startswith('$'):
            return True
        # Check if it's a hex string (32+ chars of hex)
        if len(value) >= 32 and re.match(r'^[a-fA-F0-9]+$', value):
            return True
        return False


@dataclass
class CredentialManager:
    """
    Orchestrates credential gathering from multiple sources.

    Handles:
    - Adding/removing sources
    - Deduplication across sources
    - Filtering by credential type
    - Statistics tracking
    """

    sources: List[CredentialSource] = field(default_factory=list)
    _cached_credentials: Optional[List[Credential]] = field(default=None, repr=False)

    def add_source(self, source: CredentialSource) -> None:
        """Add a credential source."""
        self.sources.append(source)
        self._cached_credentials = None  # Invalidate cache

    def remove_source(self, source_name: str) -> bool:
        """Remove a source by name."""
        for i, src in enumerate(self.sources):
            if src.name == source_name:
                self.sources.pop(i)
                self._cached_credentials = None
                return True
        return False

    def get_all_credentials(self, force_refresh: bool = False) -> List[Credential]:
        """
        Get all credentials from all sources, deduplicated.

        Args:
            force_refresh: Force re-fetching from sources

        Returns:
            List of unique Credential objects
        """
        if self._cached_credentials is not None and not force_refresh:
            return self._cached_credentials

        seen: Set[str] = set()
        credentials: List[Credential] = []

        for source in self.sources:
            if not source.is_available():
                continue

            for cred in source.get_credentials():
                # Dedupe by value (case-sensitive for passwords)
                if cred.value not in seen:
                    seen.add(cred.value)
                    credentials.append(cred)

        self._cached_credentials = credentials
        return credentials

    def get_passwords_for_spray(self) -> List[str]:
        """
        Get unique password values for spraying.

        Returns only PASSWORD type credentials as plain strings.
        """
        return [
            cred.value for cred in self.get_all_credentials()
            if cred.cred_type == CredentialType.PASSWORD
        ]

    def get_hashes_for_spray(self) -> List[str]:
        """Get NTLM hashes for pass-the-hash attacks."""
        return [
            cred.value for cred in self.get_all_credentials()
            if cred.cred_type == CredentialType.NTLM_HASH
        ]

    def get_statistics(self) -> dict:
        """
        Get statistics about available credentials.

        Returns:
            Dict with counts by source and type
        """
        all_creds = self.get_all_credentials()

        by_source: dict = {}
        by_type: dict = {}

        for cred in all_creds:
            by_source[cred.source] = by_source.get(cred.source, 0) + 1
            by_type[cred.cred_type.value] = by_type.get(cred.cred_type.value, 0) + 1

        return {
            "total": len(all_creds),
            "by_source": by_source,
            "by_type": by_type,
            "sources_available": [s.name for s in self.sources if s.is_available()],
            "sources_unavailable": [s.name for s in self.sources if not s.is_available()],
        }
