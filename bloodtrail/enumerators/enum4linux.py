"""
Enum4linux/Enum4linux-ng SMB/RPC Enumerator.

Discovers: users (with ACB flags), groups, shares, password policy.
Supports both enum4linux and enum4linux-ng.
"""

import re
import subprocess
import time
from typing import Optional, Dict, Any, List


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_pattern = r'\x1b\[[0-9;]*[a-zA-Z]'
    return re.sub(ansi_pattern, '', text)

from .base import (
    Enumerator,
    EnumerationResult,
    AuthLevel,
    decode_acb,
)


# Service account naming patterns (for classification)
SERVICE_ACCOUNT_PATTERNS = [
    r'^svc[_-]',
    r'^sql[_-]',
    r'^backup',
    r'^admin[_-]',
    r'^srv[_-]',
    r'service$',
    r'^iis[_-]',
    r'^mssql',
    r'^oracle',
]


def is_service_account(username: str) -> bool:
    """Detect service accounts by naming convention"""
    lower = username.lower()
    for pattern in SERVICE_ACCOUNT_PATTERNS:
        if re.match(pattern, lower):
            return True
    return False


class Enum4linuxEnumerator(Enumerator):
    """
    SMB/RPC enumeration via enum4linux or enum4linux-ng.

    Discovers:
    - Users with ACB flags (AS-REP roasting detection)
    - Groups and memberships
    - Shares
    - Password policy (lockout threshold, complexity)
    """

    @property
    def id(self) -> str:
        return "enum4linux"

    @property
    def name(self) -> str:
        return "Enum4linux SMB/RPC"

    @property
    def required_tool(self) -> str:
        # Prefer enum4linux-ng if available
        import shutil
        if shutil.which("enum4linux-ng"):
            return "enum4linux-ng"
        return "enum4linux"

    @property
    def supports_anonymous(self) -> bool:
        return True

    def get_command(self, target, username=None, password=None, domain=None, **kwargs):
        """Return the command that would be run and explanation."""
        tool = self.required_tool
        if tool == "enum4linux-ng":
            cmd = ["enum4linux-ng", "-A", target]
            if username and password:
                cmd.extend(["-u", username, "-p", "***"])
        else:
            cmd = ["enum4linux", "-a", target]
            if username and password:
                cmd.extend(["-u", username, "-p", "***"])

        auth = "authenticated" if username else "anonymous"
        desc = f"SMB/RPC enumeration for users, groups, shares, password policy ({auth})"
        return (cmd, desc)

    def run(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
        domain: Optional[str] = None,  # Accept but don't use (auto-detected from RPC)
        verbose: int = 0,  # Control output streaming
        **kwargs,  # Accept additional kwargs for compatibility
    ) -> EnumerationResult:
        start = time.time()
        auth_level = AuthLevel.AUTHENTICATED if username else AuthLevel.ANONYMOUS

        # Build command based on which tool is available
        tool = self.required_tool
        if tool == "enum4linux-ng":
            cmd = ["enum4linux-ng", "-A", target]
            if username and password:
                cmd.extend(["-u", username, "-p", password])
        else:
            cmd = ["enum4linux", "-a", target]
            if username and password:
                cmd.extend(["-u", username, "-p", password])

        try:
            # Stream output in real-time while capturing for parsing
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,  # Prevent stdin inheritance (fixes interactive input)
                text=True,
                bufsize=1,  # Line buffered
            )

            output_lines = []
            try:
                for line in proc.stdout:
                    if verbose >= 1:
                        print(f"       {line}", end='')  # Show progress indented
                    output_lines.append(line)

                    # Check timeout
                    if time.time() - start > timeout:
                        proc.kill()
                        raise subprocess.TimeoutExpired(cmd, timeout)

                proc.wait()
            except KeyboardInterrupt:
                proc.kill()
                raise

            output = ''.join(output_lines)
            output = strip_ansi(output)  # Remove ANSI escape codes

            result = self._parse_output(output, target)
            result.auth_level = auth_level
            result.duration_seconds = time.time() - start
            result.raw_output = output
            return result

        except subprocess.TimeoutExpired:
            return EnumerationResult(
                enumerator_id=self.id,
                success=False,
                auth_level=auth_level,
                duration_seconds=time.time() - start,
                error=f"Timeout after {timeout}s",
                dc_ip=target
            )
        except Exception as e:
            return EnumerationResult(
                enumerator_id=self.id,
                success=False,
                auth_level=auth_level,
                duration_seconds=time.time() - start,
                error=str(e),
                dc_ip=target
            )

    def _parse_output(self, output: str, target: str) -> EnumerationResult:
        """Parse enum4linux/enum4linux-ng output into normalized format"""
        result = EnumerationResult(
            enumerator_id=self.id,
            success=True,
            auth_level=AuthLevel.ANONYMOUS,
            dc_ip=target
        )

        # Parse domain name
        domain_match = re.search(r'Long domain name is:\s*(\S+)', output, re.I)
        if domain_match:
            result.domain = domain_match.group(1).upper()

        # Also try NetBIOS domain
        if not result.domain:
            netbios_match = re.search(r'NetBIOS domain name:\s*(\S+)', output, re.I)
            if netbios_match:
                result.domain = netbios_match.group(1).upper()

        # Parse DC hostname
        dc_match = re.search(r'NetBIOS computer name:\s*(\S+)', output, re.I)
        if dc_match:
            result.dc_hostname = dc_match.group(1)

        # Parse users - enum4linux-ng format
        result.users = self._parse_users_ng(output, result.domain)

        # Fallback to classic enum4linux format
        if not result.users:
            result.users = self._parse_users_classic(output, result.domain)

        # Parse groups
        result.groups = self._parse_groups(output)

        # Parse shares
        result.shares = self._parse_shares(output)

        # Parse password policy
        result.password_policy = self._parse_policy(output)

        return result

    def _parse_users_ng(self, output: str, domain: Optional[str]) -> List[Dict[str, Any]]:
        """
        Parse users from enum4linux-ng format.

        Format:
        '1147':
          username: svc-alfresco
          name: svc-alfresco
          acb: '0x00010210'
          description: (null)
        """
        users = []

        # More robust pattern - handle multi-line YAML format with flexible whitespace
        # Use DOTALL to allow . to match newlines within the block
        pattern = r"'(\d+)':\s*\n\s*username:\s*(\S+)\s*\n\s*name:\s*([^\n]+)\s*\n\s*acb:\s*'(0x[0-9a-fA-F]+)'"
        for match in re.finditer(pattern, output, re.MULTILINE | re.IGNORECASE):
            rid, username, display_name, acb_hex = match.groups()

            # Skip machine accounts
            if username.endswith('$'):
                continue

            # Skip system mailboxes (SM_*) but NOT HealthMailbox - those have useful ACB flags
            if username.startswith('SM_'):
                continue

            # Decode ACB flags
            decoded = decode_acb(acb_hex)

            upn = f"{username}@{domain}" if domain else username

            users.append({
                "name": username,
                "upn": upn,
                "display_name": display_name.strip() if display_name != "(null)" else "",
                "rid": int(rid),
                "enabled": decoded.enabled,
                "asrep": decoded.asrep_roastable,
                "pwnotreq": decoded.password_not_required,
                "pwnoexp": decoded.password_never_expires,
                "is_service": is_service_account(username),
                "acb_raw": acb_hex,
            })

        return users

    def _parse_users_classic(self, output: str, domain: Optional[str]) -> List[Dict[str, Any]]:
        """
        Parse users from classic enum4linux format.

        Format:
        user:[Administrator] rid:[0x1f4]
        """
        users = []

        pattern = r'user:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]'
        for match in re.finditer(pattern, output):
            username, rid_hex = match.groups()

            if username.endswith('$'):
                continue

            upn = f"{username}@{domain}" if domain else username

            users.append({
                "name": username,
                "upn": upn,
                "rid": int(rid_hex, 16),
                "enabled": True,  # Classic format doesn't have ACB
                "asrep": False,
                "is_service": is_service_account(username),
            })

        return users

    def _parse_groups(self, output: str) -> List[Dict[str, Any]]:
        """Parse groups from output"""
        groups = []

        # enum4linux-ng format
        pattern = r"'(\d+)':\s+groupname:\s+([^\n]+)\s+type:\s+(\w+)"
        for match in re.finditer(pattern, output, re.MULTILINE):
            rid, name, gtype = match.groups()
            groups.append({
                "name": name.strip(),
                "rid": int(rid),
                "type": gtype,
            })

        # Classic format fallback
        if not groups:
            pattern = r'group:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]'
            for match in re.finditer(pattern, output):
                name, rid_hex = match.groups()
                groups.append({
                    "name": name,
                    "rid": int(rid_hex, 16),
                })

        return groups

    def _parse_shares(self, output: str) -> List[Dict[str, Any]]:
        """Parse shares from output"""
        shares = []

        # Look for share listings
        pattern = r'(\S+)\s+Disk\s*(.*)?'
        for match in re.finditer(pattern, output):
            name = match.group(1)
            if name not in ['Disk', 'IPC$']:  # Filter noise
                shares.append({
                    "name": name,
                    "type": "Disk",
                })

        return shares

    def _parse_policy(self, output: str) -> Optional[Dict[str, Any]]:
        """Parse password policy from output"""
        policy: Dict[str, Any] = {}

        # Minimum password length
        min_len = re.search(r'Minimum password length:\s*(\d+)', output, re.I)
        if min_len:
            policy["min_length"] = int(min_len.group(1))

        # Password history
        history = re.search(r'Password history length:\s*(\d+)', output, re.I)
        if history:
            policy["history_length"] = int(history.group(1))

        # Lockout threshold (critical for spray)
        lockout = re.search(r'Lockout threshold:\s*(\d+|None)', output, re.I)
        if lockout:
            val = lockout.group(1)
            policy["lockout_threshold"] = 0 if val.lower() == 'none' else int(val)

        # Lockout duration
        duration = re.search(r'Lockout duration:\s*(\d+)', output, re.I)
        if duration:
            policy["lockout_duration"] = int(duration.group(1))

        # Lockout observation window
        window = re.search(r'Lockout observation window:\s*(\d+)', output, re.I)
        if window:
            policy["lockout_window"] = int(window.group(1))

        # Password complexity
        complexity = re.search(r'DOMAIN_PASSWORD_COMPLEX:\s*(true|false)', output, re.I)
        if complexity:
            policy["complexity"] = complexity.group(1).lower() == 'true'

        return policy if policy else None
