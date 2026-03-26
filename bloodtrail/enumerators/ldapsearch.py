"""
LDAP Enumerator using ldapsearch.

Discovers: users (with userAccountControl), computers, domain info.
Supports anonymous LDAP bind.
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
)


# userAccountControl flags (different from ACB!)
UAC_ACCOUNTDISABLE = 0x00000002
UAC_DONT_REQUIRE_PREAUTH = 0x00400000  # AS-REP roastable
UAC_PASSWD_NOTREQD = 0x00000020
UAC_DONT_EXPIRE_PASSWORD = 0x00010000


class LdapsearchEnumerator(Enumerator):
    """
    LDAP enumeration via ldapsearch.

    Uses anonymous LDAP bind to discover:
    - Domain naming context
    - Users with userAccountControl (AS-REP detection)
    - Computers
    - Service Principal Names (Kerberoasting)
    """

    @property
    def id(self) -> str:
        return "ldapsearch"

    @property
    def name(self) -> str:
        return "LDAP Anonymous"

    @property
    def required_tool(self) -> str:
        return "ldapsearch"

    @property
    def supports_anonymous(self) -> bool:
        return True

    def get_command(self, target, username=None, password=None, domain=None, **kwargs):
        """Return the command that would be run and explanation."""
        cmd = ["ldapsearch", "-x", "-H", f"ldap://{target}"]
        if domain:
            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            cmd.extend(["-b", base_dn])
        else:
            cmd.extend(["-b", "<auto-detected>"])
        cmd.extend(["(objectClass=user)", "sAMAccountName", "userAccountControl"])
        if username and password:
            cmd.extend(["-D", username, "-w", "***"])

        auth = "authenticated" if username else "anonymous"
        desc = f"LDAP query for users with UAC flags - AS-REP/SPN detection ({auth})"
        return (cmd, desc)

    def run(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 120,
        domain: Optional[str] = None,  # Accept but don't use (auto-detected from LDAP)
        **kwargs,  # Accept additional kwargs for compatibility
    ) -> EnumerationResult:
        start = time.time()
        auth_level = AuthLevel.AUTHENTICATED if username else AuthLevel.ANONYMOUS

        result = EnumerationResult(
            enumerator_id=self.id,
            success=False,
            auth_level=auth_level,
            dc_ip=target
        )

        try:
            # Step 1: Get naming context (base DN)
            base_dn = self._get_naming_context(
                target, timeout, username, password, domain
            )
            if not base_dn:
                result.error = "Could not determine base DN"
                result.duration_seconds = time.time() - start
                return result

            # Extract domain from base DN
            result.domain = self._base_dn_to_domain(base_dn)

            # Step 2: Enumerate users
            result.users = self._enumerate_users(
                target, base_dn, username, password, result.domain, timeout
            )

            # Step 3: Enumerate computers
            result.computers = self._enumerate_computers(
                target, base_dn, username, password, domain, timeout
            )

            result.success = True
            result.duration_seconds = time.time() - start
            return result

        except subprocess.TimeoutExpired:
            result.error = f"Timeout after {timeout}s"
            result.duration_seconds = time.time() - start
            return result
        except Exception as e:
            result.error = str(e)
            result.duration_seconds = time.time() - start
            return result

    def _get_naming_context(
        self,
        target: str,
        timeout: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> Optional[str]:
        """Get the default naming context (base DN)"""
        # If domain is provided, compute base DN directly
        if domain:
            return ",".join(f"DC={p}" for p in domain.split("."))

        cmd = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-s", "base", "-b", "",
            "defaultNamingContext"
        ]

        # Add credentials if provided
        if username and password:
            # Format bind DN properly
            if domain:
                bind_dn = f"{username}@{domain}"
            else:
                bind_dn = username
            cmd.extend(["-D", bind_dn, "-w", password])

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = strip_ansi(proc.stdout)

        match = re.search(r'defaultNamingContext:\s*(.+)', output, re.I)
        if match:
            return match.group(1).strip()
        return None

    def _base_dn_to_domain(self, base_dn: str) -> str:
        """Convert DC=htb,DC=local to HTB.LOCAL"""
        parts = re.findall(r'DC=([^,]+)', base_dn, re.I)
        return '.'.join(parts).upper()

    def _enumerate_users(
        self,
        target: str,
        base_dn: str,
        username: Optional[str],
        password: Optional[str],
        domain: Optional[str],
        timeout: int
    ) -> List[Dict[str, Any]]:
        """Enumerate user objects"""
        cmd = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-b", base_dn,
            "(objectClass=user)",
            "sAMAccountName", "userPrincipalName", "userAccountControl",
            "servicePrincipalName", "description"
        ]

        if username and password:
            # Format bind DN for AD (UPN format: user@domain)
            bind_dn = f"{username}@{domain}" if domain else username
            cmd.extend(["-D", bind_dn, "-w", password])

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = strip_ansi(proc.stdout)

        users = []
        current_user: Dict[str, Any] = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('dn:'):
                if current_user.get('name'):
                    users.append(current_user)
                current_user = {}

            elif line.startswith('sAMAccountName:'):
                name = line.split(':', 1)[1].strip()
                # Skip machine accounts and system accounts
                if not name.endswith('$') and not name.startswith('SM_'):
                    current_user['name'] = name
                    current_user['upn'] = f"{name}@{domain}" if domain else name

            elif line.startswith('userAccountControl:'):
                uac = int(line.split(':', 1)[1].strip())
                current_user['enabled'] = (uac & UAC_ACCOUNTDISABLE) == 0
                current_user['asrep'] = (uac & UAC_DONT_REQUIRE_PREAUTH) != 0
                current_user['pwnotreq'] = (uac & UAC_PASSWD_NOTREQD) != 0
                current_user['pwnoexp'] = (uac & UAC_DONT_EXPIRE_PASSWORD) != 0
                current_user['uac_raw'] = uac

            elif line.startswith('servicePrincipalName:'):
                spn = line.split(':', 1)[1].strip()
                if 'spns' not in current_user:
                    current_user['spns'] = []
                current_user['spns'].append(spn)
                current_user['spn'] = True  # Has at least one SPN

            elif line.startswith('description:'):
                current_user['description'] = line.split(':', 1)[1].strip()

        # Don't forget the last user
        if current_user.get('name'):
            users.append(current_user)

        return users

    def _enumerate_computers(
        self,
        target: str,
        base_dn: str,
        username: Optional[str],
        password: Optional[str],
        domain: Optional[str],
        timeout: int
    ) -> List[Dict[str, Any]]:
        """Enumerate computer objects"""
        cmd = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-b", base_dn,
            "(objectClass=computer)",
            "dNSHostName", "operatingSystem", "operatingSystemVersion"
        ]

        if username and password:
            # Format bind DN for AD (UPN format: user@domain)
            bind_dn = f"{username}@{domain}" if domain else username
            cmd.extend(["-D", bind_dn, "-w", password])

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = strip_ansi(proc.stdout)

        computers = []
        current: Dict[str, Any] = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('dn:'):
                if current.get('fqdn'):
                    computers.append(current)
                current = {}

            elif line.startswith('dNSHostName:'):
                current['fqdn'] = line.split(':', 1)[1].strip()
                current['name'] = current['fqdn'].split('.')[0]

            elif line.startswith('operatingSystem:'):
                current['os'] = line.split(':', 1)[1].strip()

            elif line.startswith('operatingSystemVersion:'):
                current['os_version'] = line.split(':', 1)[1].strip()

        if current.get('fqdn'):
            computers.append(current)

        return computers
