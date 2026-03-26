"""
Credential input abstraction for --creds integration.

Parses credentials from multiple sources with consistent interface.
Follows ABC pattern from enumerators/base.py.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional
import re


class CredType(Enum):
    """Credential type - maps to Neo4j storage format."""
    PASSWORD = "password"
    NTLM_HASH = "ntlm-hash"
    KERBEROS_TICKET = "kerberos-ticket"
    CERTIFICATE = "certificate"


@dataclass
class ParsedCredential:
    """
    Single credential with metadata.

    Attributes:
        username: SAM account name (without domain)
        domain: Domain name (optional, auto-detected if not provided)
        value: The credential value (password, hash, ticket path)
        cred_type: Type of credential
        source: Where this credential came from (for logging)
    """
    username: str
    value: str
    cred_type: CredType = CredType.PASSWORD
    domain: Optional[str] = None
    source: str = "inline"

    @property
    def upn(self) -> str:
        """Return UPN format: USER@DOMAIN.COM"""
        if self.domain:
            return f"{self.username.upper()}@{self.domain.upper()}"
        return self.username.upper()

    def is_hash(self) -> bool:
        """Check if credential looks like an NTLM hash."""
        return bool(re.match(r'^[a-fA-F0-9]{32}$', self.value))

    def __repr__(self) -> str:
        masked = self.value[:4] + "..." if len(self.value) > 4 else "***"
        return f"ParsedCredential({self.username}:{masked}, type={self.cred_type.value})"


class CredentialParser(ABC):
    """Abstract base for credential parsers."""

    @abstractmethod
    def parse(self) -> List[ParsedCredential]:
        """Parse and return list of credentials."""
        pass

    @abstractmethod
    def source_description(self) -> str:
        """Human-readable description of source."""
        pass


class InlineCredentialParser(CredentialParser):
    """
    Parse inline credential string.

    Formats supported:
        user:password
        domain/user:password
        user@domain:password
        user:aad3b435b51404eeaad3b435b51404ee  (auto-detected as hash)
    """

    def __init__(self, cred_string: str):
        self.cred_string = cred_string

    def parse(self) -> List[ParsedCredential]:
        if ':' not in self.cred_string:
            raise ValueError(f"Invalid credential format: {self.cred_string} (expected user:password)")

        # Split on last colon (password may contain colons)
        user_part, value = self.cred_string.rsplit(':', 1)
        domain = None
        username = user_part

        # Parse domain from user_part
        if '/' in user_part:
            # domain/user format
            domain, username = user_part.split('/', 1)
        elif '@' in user_part:
            # user@domain format
            username, domain = user_part.split('@', 1)

        cred = ParsedCredential(
            username=username,
            value=value,
            domain=domain,
            source="inline",
        )

        # Auto-detect NTLM hash (32 hex chars)
        if cred.is_hash():
            cred.cred_type = CredType.NTLM_HASH

        return [cred]

    def source_description(self) -> str:
        return "command line"


class FileCredentialParser(CredentialParser):
    """
    Parse credentials from file.

    Supports:
        - One per line: user:password
        - With domain: domain/user:password or user@domain:password
        - Hash format: user:aad3b435...
        - Comments: lines starting with #
        - Empty lines: ignored
    """

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)

    def parse(self) -> List[ParsedCredential]:
        if not self.file_path.exists():
            raise FileNotFoundError(f"Credential file not found: {self.file_path}")

        credentials = []
        with open(self.file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                try:
                    parser = InlineCredentialParser(line)
                    for cred in parser.parse():
                        cred.source = f"file:{self.file_path.name}:{line_num}"
                        credentials.append(cred)
                except ValueError:
                    # Skip invalid lines with warning (could log here)
                    pass

        return credentials

    def source_description(self) -> str:
        return f"file: {self.file_path}"


class PotfileCredentialParser(CredentialParser):
    """
    Parse credentials from hashcat/john potfile.

    Note: Potfiles only contain password values, not usernames.
    For full mapping, the pipeline needs to match these against
    users discovered during enumeration.
    """

    # Default potfile locations
    HASHCAT_POTFILE = Path.home() / ".local" / "share" / "hashcat" / "hashcat.potfile"
    HASHCAT_POTFILE_ALT = Path.home() / ".hashcat" / "hashcat.potfile"
    JOHN_POTFILE = Path.home() / ".john" / "john.pot"

    def __init__(self, potfile_path: Optional[Path] = None):
        self.potfile_path = potfile_path

    def _get_potfile_path(self) -> Optional[Path]:
        """Find the potfile to use."""
        if self.potfile_path and self.potfile_path.exists():
            return self.potfile_path

        # Auto-detect
        for path in [self.HASHCAT_POTFILE, self.HASHCAT_POTFILE_ALT, self.JOHN_POTFILE]:
            if path.exists():
                return path

        return None

    def parse(self) -> List[ParsedCredential]:
        potfile = self._get_potfile_path()
        if not potfile:
            raise FileNotFoundError("No potfile found (checked hashcat and john locations)")

        credentials = []
        seen_passwords = set()

        with open(potfile, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue

                # Potfile format: hash:password
                # For complex hashes like krb5tgs, there may be multiple colons
                # Password is after the LAST colon
                parts = line.rsplit(':', 1)
                if len(parts) != 2:
                    continue

                password = parts[1]

                # Skip if looks like a hash (probably parsing error)
                if re.match(r'^[a-fA-F0-9]{32}$', password):
                    continue

                # Skip duplicates
                if password in seen_passwords:
                    continue
                seen_passwords.add(password)

                # Potfile doesn't give us usernames - these will be resolved
                # by matching against enumerated users in the pipeline
                credentials.append(ParsedCredential(
                    username="<FROM_POTFILE>",  # Placeholder
                    value=password,
                    cred_type=CredType.PASSWORD,
                    source=f"potfile:{potfile.name}",
                ))

        return credentials

    def source_description(self) -> str:
        potfile = self._get_potfile_path()
        if potfile:
            return f"potfile: {potfile}"
        return "potfile (not found)"


def create_credential_parser(
    inline: Optional[str] = None,
    file_path: Optional[Path] = None,
    use_potfile: bool = False,
    potfile_path: Optional[Path] = None,
) -> CredentialParser:
    """
    Factory function to create appropriate parser.

    Priority: inline > file > potfile

    Args:
        inline: Credential string (user:pass)
        file_path: Path to credentials file
        use_potfile: Auto-detect and use potfile
        potfile_path: Custom potfile path

    Returns:
        Appropriate CredentialParser instance

    Raises:
        ValueError: If no credential source specified
    """
    if inline:
        # Check if it's actually a file path
        if Path(inline).exists() and ':' not in inline:
            return FileCredentialParser(Path(inline))
        return InlineCredentialParser(inline)
    elif file_path:
        return FileCredentialParser(file_path)
    elif use_potfile or potfile_path:
        return PotfileCredentialParser(potfile_path)
    else:
        raise ValueError("No credential source specified (use --creds or --potfile)")
