"""
RPC Client Enumerator.

Fast, lightweight RPC enumeration using rpcclient.
Runs enumdomusers/enumdomgroups for quick user list discovery.
Placed before kerbrute to provide user list for kerberos validation.
"""

import re
import subprocess
import time
from typing import Optional, Dict, Any, List

from .base import (
    Enumerator,
    EnumerationResult,
    AuthLevel,
)


# Service account naming patterns (shared with enum4linux)
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


class RpcclientEnumerator(Enumerator):
    """
    Fast RPC enumeration via rpcclient.

    Discovers:
    - Users via enumdomusers
    - Groups via enumdomgroups
    - User descriptions via querydispinfo

    Advantages over enum4linux:
    - Much faster (single RPC connection)
    - Lightweight output (easier parsing)
    - Provides user list for kerbrute validation
    """

    @property
    def id(self) -> str:
        return "rpcclient"

    @property
    def name(self) -> str:
        return "RPC Client"

    @property
    def required_tool(self) -> str:
        return "rpcclient"

    @property
    def supports_anonymous(self) -> bool:
        return True

    def get_command(self, target, username=None, password=None, domain=None, **kwargs):
        """Return the command that would be run and explanation."""
        if username and password:
            cmd = ["rpcclient", "-U", f"{username}%***", target, "-c", "enumdomusers;enumdomgroups;querydispinfo"]
        else:
            cmd = ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers;enumdomgroups;querydispinfo"]

        auth = "authenticated" if username else "anonymous"
        desc = f"RPC enumeration for users, groups, descriptions ({auth})"
        return (cmd, desc)

    def run(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 60,
        domain: Optional[str] = None,
        **kwargs,
    ) -> EnumerationResult:
        start = time.time()
        auth_level = AuthLevel.AUTHENTICATED if username else AuthLevel.ANONYMOUS

        # Build command
        rpc_commands = "enumdomusers;enumdomgroups;querydispinfo"

        if username and password:
            cmd = ["rpcclient", "-U", f"{username}%{password}", target, "-c", rpc_commands]
        else:
            cmd = ["rpcclient", "-U", "", "-N", target, "-c", rpc_commands]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = proc.stdout + proc.stderr

            # Check for access denied
            if "NT_STATUS_ACCESS_DENIED" in output or "NT_STATUS_LOGON_FAILURE" in output:
                return EnumerationResult(
                    enumerator_id=self.id,
                    success=False,
                    auth_level=auth_level,
                    duration_seconds=time.time() - start,
                    error="Anonymous RPC access denied",
                    dc_ip=target
                )

            result = self._parse_output(output, target, domain)
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

    def _parse_output(self, output: str, target: str, domain: Optional[str]) -> EnumerationResult:
        """Parse rpcclient output into normalized format"""
        result = EnumerationResult(
            enumerator_id=self.id,
            success=True,
            auth_level=AuthLevel.ANONYMOUS,
            dc_ip=target
        )

        # Use provided domain or try to detect
        result.domain = domain.upper() if domain else None

        # Parse users from enumdomusers
        # Format: user:[username] rid:[0x1f4]
        users_dict: Dict[str, Dict[str, Any]] = {}
        user_pattern = r'user:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]'
        for match in re.finditer(user_pattern, output):
            username, rid_hex = match.groups()

            # Skip machine accounts
            if username.endswith('$'):
                continue

            rid = int(rid_hex, 16)
            upn = f"{username}@{result.domain}" if result.domain else username

            users_dict[username.lower()] = {
                "name": username,
                "upn": upn,
                "rid": rid,
                "enabled": True,  # rpcclient doesn't give UAC flags
                "asrep": False,
                "is_service": is_service_account(username),
                "description": "",
            }

        # Parse descriptions from querydispinfo
        # Format: index: 0x1f4 RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering
        # Or: index: 0xXXX RID: 0xXXX acb: 0xXXXX Account: username Name: Full Name Desc: Description here
        dispinfo_pattern = r'Account:\s*(\S+)\s+Name:\s*([^\t]*)\s*Desc:\s*(.*)$'
        for match in re.finditer(dispinfo_pattern, output, re.MULTILINE):
            account, name, desc = match.groups()
            account_lower = account.lower()

            if account_lower in users_dict:
                users_dict[account_lower]["description"] = desc.strip()
                if name and name.strip() != "(null)":
                    users_dict[account_lower]["display_name"] = name.strip()

        result.users = list(users_dict.values())

        # Parse groups from enumdomgroups
        # Format: group:[Group Name] rid:[0x200]
        groups = []
        group_pattern = r'group:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]'
        for match in re.finditer(group_pattern, output):
            name, rid_hex = match.groups()
            groups.append({
                "name": name,
                "rid": int(rid_hex, 16),
            })

        result.groups = groups

        # Mark success only if we got users
        result.success = len(result.users) > 0

        return result
