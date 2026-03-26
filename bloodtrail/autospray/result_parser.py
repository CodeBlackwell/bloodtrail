"""
Result Parser for Auto Password Spray

Parses output from spray tools to extract successful authentications.
Supports multiple tools with tool-specific regex patterns.

Supported tools:
- CrackMapExec/NetExec (SMB, WinRM)
- Kerbrute (Kerberos)
- Hydra (various protocols)
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Pattern
from enum import Enum


class SprayTool(Enum):
    """Supported spray tools."""
    CRACKMAPEXEC = "crackmapexec"
    NETEXEC = "netexec"
    KERBRUTE = "kerbrute"
    HYDRA = "hydra"


@dataclass
class ParsedResult:
    """
    Parsed result from spray tool output.

    Attributes:
        username: Authenticated username
        password: Password used
        target: Target IP/hostname
        domain: Domain (if applicable)
        is_admin: Whether user has admin access (CME: Pwn3d!)
        tool: Which tool produced this result
        raw_line: Original output line
    """
    username: str
    password: str
    target: str
    domain: Optional[str] = None
    is_admin: bool = False
    tool: str = "unknown"
    raw_line: str = ""

    def __str__(self) -> str:
        admin_marker = " (ADMIN)" if self.is_admin else ""
        if self.domain:
            return f"{self.domain}\\{self.username}:{self.password}@{self.target}{admin_marker}"
        return f"{self.username}:{self.password}@{self.target}{admin_marker}"


class ResultParser:
    """
    Parse spray tool output for successful authentications.

    Uses tool-specific regex patterns to identify successful logins
    and admin access (where supported).
    """

    # Tool-specific patterns
    # CrackMapExec/NetExec SMB success:
    # SMB  192.168.50.70   445    DC01  [+] corp.com\pete:Summer2024! (Pwn3d!)
    # SMB  192.168.50.70   445    DC01  [+] corp.com\john:Password1!
    CME_SUCCESS_PATTERN = re.compile(
        r'^\s*SMB\s+'                           # Protocol
        r'([\d.]+)\s+'                          # IP address
        r'\d+\s+'                               # Port
        r'(\S+)\s+'                             # Hostname
        r'\[\+\]\s+'                            # Success marker
        r'(?:(\S+?)\\)?'                        # Optional domain\
        r'(\S+?):(\S+)'                         # username:password
        r'(?:\s+\(Pwn3d!\))?',                  # Optional admin marker
        re.IGNORECASE
    )

    # Alternative CME pattern for different output formats
    CME_SUCCESS_ALT = re.compile(
        r'\[\+\]\s+'                            # Success marker
        r'(?:(\S+?)\\)?'                        # Optional domain\
        r'(\S+?):(\S+)\s+'                      # username:password
        r'.*?'                                  # anything
        r'([\d.]+)',                            # IP somewhere
        re.IGNORECASE
    )

    # NetExec has similar format
    NETEXEC_SUCCESS_PATTERN = CME_SUCCESS_PATTERN

    # Kerbrute success:
    # [+] VALID LOGIN:	 pete@corp.com:Summer2024!
    KERBRUTE_SUCCESS_PATTERN = re.compile(
        r'\[\+\]\s*VALID LOGIN:\s*'             # Success marker
        r'(\S+?)@(\S+?):(\S+)',                 # user@domain:password
        re.IGNORECASE
    )

    # Kerbrute alternative (older versions):
    # [+] pete@corp.com:Summer2024!
    KERBRUTE_SUCCESS_ALT = re.compile(
        r'\[\+\]\s*(\S+?)@(\S+?):(\S+)',
        re.IGNORECASE
    )

    # Hydra success:
    # [445][smb] host: 192.168.50.70   login: pete   password: Summer2024!
    HYDRA_SUCCESS_PATTERN = re.compile(
        r'\[\d+\]\[(\w+)\]\s+'                  # [port][protocol]
        r'host:\s*([\d.]+)\s+'                  # host: IP
        r'login:\s*(\S+)\s+'                    # login: username
        r'password:\s*(\S+)',                   # password: pass
        re.IGNORECASE
    )

    # Admin detection patterns
    ADMIN_PATTERNS = [
        re.compile(r'\(Pwn3d!\)', re.IGNORECASE),
        re.compile(r'\[Admin\]', re.IGNORECASE),
        re.compile(r'STATUS_ADMIN', re.IGNORECASE),
    ]

    @classmethod
    def parse_line(
        cls,
        line: str,
        tool: SprayTool,
        password: Optional[str] = None,
        target: Optional[str] = None
    ) -> Optional[ParsedResult]:
        """
        Parse single line of tool output.

        Args:
            line: Output line to parse
            tool: Which tool produced this output
            password: Password being tested (fallback if not in output)
            target: Target IP/hostname (fallback)

        Returns:
            ParsedResult if successful auth found, None otherwise
        """
        line = line.strip()
        if not line:
            return None

        # Skip non-success lines
        if '[+]' not in line.lower() and 'valid' not in line.lower():
            # Hydra uses different format
            if tool != SprayTool.HYDRA:
                return None

        result = None

        if tool in (SprayTool.CRACKMAPEXEC, SprayTool.NETEXEC):
            result = cls._parse_cme_line(line, password, target)
        elif tool == SprayTool.KERBRUTE:
            result = cls._parse_kerbrute_line(line, password, target)
        elif tool == SprayTool.HYDRA:
            result = cls._parse_hydra_line(line, password, target)

        if result:
            result.tool = tool.value
            result.raw_line = line
            # Check for admin access
            result.is_admin = cls._check_admin(line)

        return result

    @classmethod
    def _parse_cme_line(
        cls,
        line: str,
        password: Optional[str],
        target: Optional[str]
    ) -> Optional[ParsedResult]:
        """Parse CrackMapExec/NetExec output line."""
        # Try primary pattern
        match = cls.CME_SUCCESS_PATTERN.search(line)
        if match:
            ip, hostname, domain, username, pwd = match.groups()
            return ParsedResult(
                username=username,
                password=pwd,
                target=ip,
                domain=domain,
            )

        # Try alternative pattern
        match = cls.CME_SUCCESS_ALT.search(line)
        if match:
            domain, username, pwd, ip = match.groups()
            return ParsedResult(
                username=username,
                password=pwd,
                target=ip or target or "unknown",
                domain=domain,
            )

        return None

    @classmethod
    def _parse_kerbrute_line(
        cls,
        line: str,
        password: Optional[str],
        target: Optional[str]
    ) -> Optional[ParsedResult]:
        """Parse Kerbrute output line."""
        # Try primary pattern
        match = cls.KERBRUTE_SUCCESS_PATTERN.search(line)
        if match:
            username, domain, pwd = match.groups()
            return ParsedResult(
                username=username,
                password=pwd,
                target=target or "dc",
                domain=domain,
            )

        # Try alternative pattern
        match = cls.KERBRUTE_SUCCESS_ALT.search(line)
        if match:
            username, domain, pwd = match.groups()
            return ParsedResult(
                username=username,
                password=pwd,
                target=target or "dc",
                domain=domain,
            )

        return None

    @classmethod
    def _parse_hydra_line(
        cls,
        line: str,
        password: Optional[str],
        target: Optional[str]
    ) -> Optional[ParsedResult]:
        """Parse Hydra output line."""
        match = cls.HYDRA_SUCCESS_PATTERN.search(line)
        if match:
            protocol, ip, username, pwd = match.groups()
            return ParsedResult(
                username=username,
                password=pwd,
                target=ip,
            )

        return None

    @classmethod
    def _check_admin(cls, line: str) -> bool:
        """Check if line indicates admin access."""
        for pattern in cls.ADMIN_PATTERNS:
            if pattern.search(line):
                return True
        return False

    @classmethod
    def parse_output(
        cls,
        output: str,
        tool: SprayTool,
        password: Optional[str] = None,
        target: Optional[str] = None
    ) -> List[ParsedResult]:
        """
        Parse full tool output.

        Args:
            output: Complete tool output (multi-line)
            tool: Which tool produced this output
            password: Password being tested
            target: Target IP/hostname

        Returns:
            List of ParsedResult for all successful authentications
        """
        results = []
        seen = set()  # Dedupe by username

        for line in output.splitlines():
            result = cls.parse_line(line, tool, password, target)
            if result and result.username not in seen:
                seen.add(result.username)
                results.append(result)

        return results

    @classmethod
    def detect_tool_from_output(cls, output: str) -> Optional[SprayTool]:
        """
        Attempt to detect which tool produced the output.

        Args:
            output: Tool output to analyze

        Returns:
            SprayTool enum or None if undetected
        """
        output_lower = output.lower()

        # CrackMapExec/NetExec indicators
        if 'smb' in output_lower and '445' in output:
            if 'netexec' in output_lower:
                return SprayTool.NETEXEC
            return SprayTool.CRACKMAPEXEC

        # Kerbrute indicators
        if 'valid login' in output_lower or 'kerbrute' in output_lower:
            return SprayTool.KERBRUTE

        # Hydra indicators
        if 'hydra' in output_lower or re.search(r'\[\d+\]\[\w+\]', output):
            return SprayTool.HYDRA

        return None
