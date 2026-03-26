"""
Base classes for AD enumeration plugins.

Provides:
- Enumerator ABC for implementing enumeration tools
- EnumerationResult dataclass for normalized output
- ACB flag constants and decoder

Zen: "Simple is better than complex" - one ABC, one result format.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
import shutil


class AuthLevel(Enum):
    """Authentication level used for enumeration"""
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"


# ACB (Account Control Bits) - from Samba/RPC enumeration
# Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr
ACB_DISABLED = 0x00000001
ACB_HOMEDIR_REQUIRED = 0x00000002
ACB_PWNOTREQ = 0x00000004
ACB_TEMPDUP = 0x00000008
ACB_NORMAL = 0x00000010
ACB_MNS = 0x00000020
ACB_DOMTRUST = 0x00000040
ACB_WSTRUST = 0x00000080
ACB_SVRTRUST = 0x00000100
ACB_PWNOEXP = 0x00000200
ACB_AUTOLOCK = 0x00000400
ACB_DONT_REQ_PREAUTH = 0x00010000  # AS-REP Roastable!


@dataclass
class DecodedACB:
    """Decoded ACB flags with security-relevant properties"""
    raw_value: int
    enabled: bool = True
    asrep_roastable: bool = False
    password_not_required: bool = False
    password_never_expires: bool = False


def decode_acb(value: int | str) -> DecodedACB:
    """
    Decode ACB flags from enum4linux output.

    Args:
        value: ACB value (e.g., 0x00010210 or "0x00010210")

    Returns:
        DecodedACB with security-relevant properties

    Example:
        >>> decode_acb(0x00010210)
        DecodedACB(asrep_roastable=True, enabled=True, ...)
    """
    if isinstance(value, str):
        value = int(value, 16) if value.startswith("0x") else int(value)

    return DecodedACB(
        raw_value=value,
        enabled=(value & ACB_DISABLED) == 0,
        asrep_roastable=(value & ACB_DONT_REQ_PREAUTH) != 0,
        password_not_required=(value & ACB_PWNOTREQ) != 0,
        password_never_expires=(value & ACB_PWNOEXP) != 0,
    )


@dataclass
class EnumerationResult:
    """
    Common result format for all enumerators.

    All enumerators output this format, enabling the attack suggester
    to work with any enumeration source.
    """
    # Metadata
    enumerator_id: str
    success: bool
    auth_level: AuthLevel
    duration_seconds: float = 0.0
    error: Optional[str] = None

    # Domain info
    domain: Optional[str] = None
    dc_hostname: Optional[str] = None
    dc_ip: Optional[str] = None

    # Discovered entities (normalized format)
    users: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"name": "pete", "upn": "pete@corp.com", "asrep": True, "spn": False, "enabled": True}]

    computers: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"name": "DC1", "fqdn": "DC1.corp.com", "os": "Windows Server 2019"}]

    groups: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"name": "Domain Admins", "members": ["Administrator", "dave"]}]

    shares: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"name": "SYSVOL", "path": "\\\\DC1\\SYSVOL", "readable": True}]

    # Password policy
    password_policy: Optional[Dict[str, Any]] = None
    # Format: {"lockout_threshold": 5, "min_length": 8, "complexity": True}

    # Raw output for debugging
    raw_output: str = ""


class Enumerator(ABC):
    """
    Abstract base class for AD enumeration plugins.

    Each enumerator wraps a specific tool (enum4linux, ldapsearch, etc.)
    and normalizes its output to EnumerationResult.

    Example implementation:
        class Enum4linuxEnumerator(Enumerator):
            @property
            def id(self) -> str:
                return "enum4linux"

            @property
            def name(self) -> str:
                return "Enum4linux SMB/RPC"

            @property
            def required_tool(self) -> str:
                return "enum4linux"

            @property
            def supports_anonymous(self) -> bool:
                return True

            def run(self, target, username=None, password=None, timeout=300):
                # Execute enum4linux and parse output
                ...
    """

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier (e.g., 'enum4linux')"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name (e.g., 'Enum4linux SMB/RPC')"""
        pass

    @property
    @abstractmethod
    def required_tool(self) -> str:
        """Command-line tool required (e.g., 'enum4linux')"""
        pass

    @property
    @abstractmethod
    def supports_anonymous(self) -> bool:
        """Can this run without credentials?"""
        pass

    @abstractmethod
    def run(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300
    ) -> EnumerationResult:
        """
        Execute enumeration against target.

        Args:
            target: IP address or hostname
            username: Optional AD username (DOMAIN\\user or user@domain)
            password: Optional password
            timeout: Timeout in seconds

        Returns:
            EnumerationResult with discovered data
        """
        pass

    def is_available(self) -> bool:
        """Check if required tool is installed"""
        return shutil.which(self.required_tool) is not None

    def get_command(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        **kwargs,
    ) -> tuple:
        """
        Return the command that would be run and a brief explanation.

        Override in subclasses to provide command visibility for -vv mode.

        Returns:
            (command_list, explanation)
            e.g., (["enum4linux-ng", "-A", "10.10.10.161"],
                   "SMB/RPC enumeration for users, groups, shares, password policy")
        """
        return ([], "")

    def __repr__(self) -> str:
        available = "available" if self.is_available() else "NOT INSTALLED"
        return f"<{self.name} ({available})>"
