"""
Kerbrute User Enumeration.

Validates usernames via Kerberos and detects AS-REP roastable accounts.
No credentials required - uses pre-authentication responses.
"""

import re
import subprocess
import time
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_pattern = r'\x1b\[[0-9;]*[a-zA-Z]'
    return re.sub(ansi_pattern, '', text)

from .base import (
    Enumerator,
    EnumerationResult,
    AuthLevel,
)


class KerbruteEnumerator(Enumerator):
    """
    Kerberos-based user enumeration via kerbrute.

    Validates usernames by sending AS-REQ and analyzing responses:
    - KDC_ERR_PREAUTH_REQUIRED = valid user, pre-auth enabled
    - Valid AS-REP response = AS-REP roastable!
    - KDC_ERR_C_PRINCIPAL_UNKNOWN = invalid user

    Note: Requires a user list to validate. If no list provided,
    uses common usernames.
    """

    # Common usernames to try if no list provided
    COMMON_USERS = [
        "administrator", "admin", "guest", "krbtgt",
        "backup", "service", "svc", "sql", "web",
        "exchange", "test", "user", "support", "helpdesk",
        "operator", "manager", "developer", "dev",
    ]

    @property
    def id(self) -> str:
        return "kerbrute"

    @property
    def name(self) -> str:
        return "Kerbrute User Enum"

    @property
    def required_tool(self) -> str:
        return "kerbrute"

    @property
    def supports_anonymous(self) -> bool:
        return True  # Uses Kerberos pre-auth, no creds needed

    def get_command(self, target, username=None, password=None, domain=None, **kwargs):
        """Return the command that would be run and explanation."""
        cmd = ["kerbrute", "userenum", "--dc", target]
        if domain:
            cmd.extend(["-d", domain])
        else:
            cmd.extend(["-d", "<auto-detected>"])
        # Show what wordlist is actually used
        cmd.append(f"(internal: {len(self.COMMON_USERS)} common usernames)")

        desc = f"Kerberos user validation via AS-REQ - detects valid users + AS-REP roastable"
        return (cmd, desc)

    def run(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 120,
        user_list: Optional[List[str]] = None,
        domain: Optional[str] = None,
    ) -> EnumerationResult:
        start = time.time()

        result = EnumerationResult(
            enumerator_id=self.id,
            success=False,
            auth_level=AuthLevel.ANONYMOUS,
            dc_ip=target
        )

        # Need domain for kerbrute
        if not domain:
            # Try to get from DNS or skip
            domain = self._resolve_domain(target)
            if not domain:
                result.error = "Could not determine domain (provide --domain)"
                result.duration_seconds = time.time() - start
                return result

        result.domain = domain

        # Create temp file with usernames
        users_to_check = user_list or self.COMMON_USERS

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(users_to_check))
            user_file = f.name

        try:
            cmd = [
                "kerbrute", "userenum",
                "--dc", target,
                "-d", domain,
                user_file
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = proc.stdout + proc.stderr
            output = strip_ansi(output)  # Remove ANSI escape codes
            result.raw_output = output

            # Parse results
            result.users = self._parse_output(output, domain)
            result.success = True
            result.duration_seconds = time.time() - start

        except subprocess.TimeoutExpired:
            result.error = f"Timeout after {timeout}s"
            result.duration_seconds = time.time() - start
        except Exception as e:
            result.error = str(e)
            result.duration_seconds = time.time() - start
        finally:
            # Cleanup temp file
            Path(user_file).unlink(missing_ok=True)

        return result

    def _resolve_domain(self, target: str) -> Optional[str]:
        """Try to resolve domain from target"""
        # Could use DNS SRV lookup or LDAP rootDSE
        # For now, return None and let caller provide domain
        return None

    def _parse_output(self, output: str, domain: str) -> List[Dict[str, Any]]:
        """
        Parse kerbrute output.

        Example lines:
        2024/01/15 10:00:00 >  [+] VALID USERNAME:       administrator@htb.local
        2024/01/15 10:00:01 >  [+] svc-alfresco has no pre auth required. Dumping hash...
        """
        users = []
        seen = set()

        # Valid username pattern
        valid_pattern = r'VALID USERNAME:\s+(\S+)@'
        for match in re.finditer(valid_pattern, output, re.I):
            username = match.group(1)
            if username.lower() not in seen:
                seen.add(username.lower())
                users.append({
                    "name": username,
                    "upn": f"{username}@{domain}",
                    "enabled": True,
                    "asrep": False,
                    "validated": True,
                })

        # AS-REP roastable pattern (no pre-auth)
        asrep_pattern = r'(\S+)\s+has no pre auth required'
        for match in re.finditer(asrep_pattern, output, re.I):
            username = match.group(1)
            # Update if exists, or add new
            found = False
            for user in users:
                if user["name"].lower() == username.lower():
                    user["asrep"] = True
                    found = True
                    break
            if not found and username.lower() not in seen:
                seen.add(username.lower())
                users.append({
                    "name": username,
                    "upn": f"{username}@{domain}",
                    "enabled": True,
                    "asrep": True,
                    "validated": True,
                })

        return users

    def run_with_user_list(
        self,
        target: str,
        user_list: List[str],
        domain: str,
        timeout: int = 300
    ) -> EnumerationResult:
        """
        Run kerbrute with a specific user list.

        Use this after getting users from enum4linux/ldapsearch
        to validate and check AS-REP status.
        """
        return self.run(
            target=target,
            user_list=user_list,
            domain=domain,
            timeout=timeout
        )
