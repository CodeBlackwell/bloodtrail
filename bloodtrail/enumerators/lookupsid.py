"""
Lookupsid Enumerator using impacket-lookupsid.

Discovers users via RID cycling - brute forces Windows Security Identifiers
to enumerate all domain users, even when LDAP/RPC enumeration fails.
"""

import re
import subprocess
import time
from typing import Optional, List, Dict, Any

from .base import (
    Enumerator,
    EnumerationResult,
    AuthLevel,
)


class LookupsidEnumerator(Enumerator):
    """
    RID cycling enumeration via impacket-lookupsid.

    This is highly effective when:
    - Anonymous LDAP is disabled
    - RPC enumeration is blocked
    - Guest account has minimal access

    Uses SID brute forcing to discover all domain users.
    """

    @property
    def id(self) -> str:
        return "lookupsid"

    @property
    def name(self) -> str:
        return "Lookupsid RID Cycling"

    @property
    def required_tool(self) -> str:
        return "impacket-lookupsid"

    @property
    def supports_anonymous(self) -> bool:
        return True  # Works with guest:'' or anonymous

    def get_command(self, target, username=None, password=None, domain=None, **kwargs):
        """Return the command that would be run and explanation."""
        if domain:
            if username and password:
                user_spec = f"{domain}/{username}:{password}"
            elif username:
                user_spec = f"{domain}/{username}"
            else:
                user_spec = f"{domain}/guest"
        else:
            user_spec = "guest"

        cmd = ["impacket-lookupsid", f"'{user_spec}'@{target}"]
        if not password:
            cmd.append("-no-pass")

        auth = "authenticated" if (username and password) else "guest/anonymous"
        desc = f"RID cycling to enumerate all domain users via SID brute force ({auth})"
        return (cmd, desc)

    def run(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 120,
        domain: Optional[str] = None,
        max_rid: int = 4000,
        **kwargs,
    ) -> EnumerationResult:
        start = time.time()
        auth_level = AuthLevel.AUTHENTICATED if (username and password) else AuthLevel.ANONYMOUS

        result = EnumerationResult(
            enumerator_id=self.id,
            success=False,
            auth_level=auth_level,
            dc_ip=target
        )

        try:
            # Build user specification
            if domain:
                if username and password:
                    user_spec = f"{domain}/{username}:{password}"
                elif username:
                    user_spec = f"{domain}/{username}"
                else:
                    user_spec = f"{domain}/guest"
            else:
                if username and password:
                    user_spec = f"{username}:{password}"
                elif username:
                    user_spec = username
                else:
                    user_spec = "guest"

            # Build command
            cmd = [
                "impacket-lookupsid",
                f"{user_spec}@{target}",
                "-maxRid", str(max_rid),
            ]

            if not password:
                cmd.append("-no-pass")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = proc.stdout + proc.stderr

            # Check for errors
            if "STATUS_ACCESS_DENIED" in output:
                result.error = "Access denied - try with credentials"
                result.duration_seconds = time.time() - start
                return result

            if "LOGON_FAILURE" in output:
                result.error = "Logon failure - invalid credentials"
                result.duration_seconds = time.time() - start
                return result

            # Extract domain SID
            sid_match = re.search(r'Domain SID is:\s*(S-[\d-]+)', output)
            if sid_match:
                result.metadata["domain_sid"] = sid_match.group(1)

            # Parse users, groups, and aliases
            users = []
            groups = []

            # Pattern: RID: DOMAIN\name (SidType)
            # Example: 1104: CICADA\john.smoulder (SidTypeUser)
            pattern = r'(\d+):\s+(\w+)\\([^\s]+)\s+\((\w+)\)'

            for match in re.finditer(pattern, output):
                rid, domain_name, name, sid_type = match.groups()

                if sid_type == "SidTypeUser":
                    # Skip machine accounts and built-in
                    if name.endswith('$'):
                        continue
                    if name.lower() in ['krbtgt']:
                        # Include krbtgt but mark as system
                        users.append({
                            "name": name,
                            "rid": int(rid),
                            "domain": domain_name,
                            "is_system": True,
                            "enabled": True,
                        })
                    else:
                        users.append({
                            "name": name,
                            "rid": int(rid),
                            "domain": domain_name,
                            "enabled": True,
                        })

                elif sid_type in ["SidTypeGroup", "SidTypeAlias"]:
                    groups.append({
                        "name": name,
                        "rid": int(rid),
                        "domain": domain_name,
                        "type": sid_type,
                    })

            result.users = users
            result.groups = groups
            result.domain = domain or (users[0]["domain"] if users else None)
            result.success = len(users) > 0
            result.duration_seconds = time.time() - start

            if not result.success:
                result.error = "No users found via RID cycling"

            return result

        except subprocess.TimeoutExpired:
            result.error = f"Timeout after {timeout}s"
            result.duration_seconds = time.time() - start
            return result
        except FileNotFoundError:
            result.error = "impacket-lookupsid not found"
            result.duration_seconds = time.time() - start
            return result
        except Exception as e:
            result.error = str(e)
            result.duration_seconds = time.time() - start
            return result
