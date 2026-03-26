"""
Parse command output to extract actionable data for recommendation chaining.

This module provides parsers for common pentesting tool outputs:
- AS-REP roast (GetNPUsers) → Extract Kerberos hash
- Hashcat → Extract cracked password
- WinRM (evil-winrm) → Detect successful shell
- CrackMapExec → Detect valid credentials
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class ParseResult:
    """Result of parsing command output.

    Attributes:
        success: Whether actionable data was extracted
        extracted_data: Dictionary of extracted values (hash, password, etc.)
        next_action: Suggested next action template name
    """
    success: bool
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    next_action: Optional[str] = None


class OutputParser:
    """Parse command outputs to extract data for recommendation chaining."""

    @staticmethod
    def parse_asrep_output(output: str) -> ParseResult:
        """Parse GetNPUsers output to extract AS-REP hash.

        Args:
            output: Raw output from impacket-GetNPUsers

        Returns:
            ParseResult with hash if found

        Example output:
            [*] Getting TGT for svc-alfresco
            $krb5asrep$23$svc-alfresco@HTB.LOCAL:abc123...
        """
        # Pattern matches: $krb5asrep$23$user@DOMAIN:salt$hash
        match = re.search(r'(\$krb5asrep\$\d+\$[^\s]+)', output)
        if match:
            hash_value = match.group(1)
            # Extract username from hash
            user_match = re.search(r'\$krb5asrep\$\d+\$([^@]+)@', hash_value)
            username = user_match.group(1) if user_match else None

            return ParseResult(
                success=True,
                extracted_data={
                    "hash": hash_value,
                    "hash_type": "asrep",
                    "username": username,
                },
                next_action="crack_hash",
            )
        return ParseResult(success=False, extracted_data={})

    @staticmethod
    def parse_kerberoast_output(output: str) -> ParseResult:
        """Parse GetUserSPNs output to extract TGS hash.

        Args:
            output: Raw output from impacket-GetUserSPNs

        Returns:
            ParseResult with hash if found

        Example output:
            $krb5tgs$23$*user$DOMAIN$spn*$salt$hash...
        """
        match = re.search(r'(\$krb5tgs\$\d+\$[^\s]+)', output)
        if match:
            hash_value = match.group(1)
            # Extract username from hash
            user_match = re.search(r'\$krb5tgs\$\d+\$\*([^$]+)\$', hash_value)
            username = user_match.group(1) if user_match else None

            return ParseResult(
                success=True,
                extracted_data={
                    "hash": hash_value,
                    "hash_type": "kerberoast",
                    "username": username,
                },
                next_action="crack_hash",
            )
        return ParseResult(success=False, extracted_data={})

    @staticmethod
    def parse_hashcat_output(output: str) -> ParseResult:
        """Parse hashcat output to extract cracked password.

        Args:
            output: Raw output from hashcat

        Returns:
            ParseResult with password if found

        Example output:
            $krb5asrep$23$svc-alfresco@HTB.LOCAL:salt:s3rvice

        Or with --show:
            $krb5asrep$23$user@DOMAIN:s3rvice
        """
        # Pattern 1: hash:password at end of line (hashcat cracked output)
        # Look for the last colon-separated value that isn't part of hash
        lines = output.strip().split('\n')
        for line in lines:
            # Skip status lines
            if line.startswith('[') or ':' not in line:
                continue

            # Check if it's a krb5asrep or krb5tgs hash with cracked password
            if '$krb5asrep$' in line or '$krb5tgs$' in line:
                # Format: $krb5asrep$23$user@DOMAIN:salt$hash:password
                # The password is after the last colon
                parts = line.rsplit(':', 1)
                if len(parts) == 2:
                    potential_password = parts[1].strip()
                    # Validate it's not part of the hash (hashes have $ and are long)
                    if potential_password and '$' not in potential_password and len(potential_password) < 100:
                        return ParseResult(
                            success=True,
                            extracted_data={"password": potential_password},
                            next_action="test_cracked_credential",
                        )

        # Pattern 2: "Cracked" status in hashcat
        if "Status...........: Cracked" in output or "Status..........: Cracked" in output:
            return ParseResult(
                success=True,
                extracted_data={"needs_show": True},
                next_action="show_cracked",
            )

        return ParseResult(success=False, extracted_data={})

    @staticmethod
    def parse_john_output(output: str) -> ParseResult:
        """Parse John the Ripper output to extract cracked password.

        Args:
            output: Raw output from john

        Returns:
            ParseResult with password if found

        Example output:
            s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
        """
        # Pattern: password (hash) - John shows password first
        match = re.search(r'^(\S+)\s+\(\$krb5', output, re.MULTILINE)
        if match:
            return ParseResult(
                success=True,
                extracted_data={"password": match.group(1)},
                next_action="test_cracked_credential",
            )

        # Pattern for NTLM: password (username)
        match = re.search(r'^(\S+)\s+\([^)]+\)$', output, re.MULTILINE)
        if match:
            return ParseResult(
                success=True,
                extracted_data={"password": match.group(1)},
                next_action="test_cracked_credential",
            )

        return ParseResult(success=False, extracted_data={})

    @staticmethod
    def parse_winrm_output(output: str) -> ParseResult:
        """Parse evil-winrm output to detect successful login.

        Args:
            output: Raw output from evil-winrm

        Returns:
            ParseResult with access_level if successful

        Example output:
            Evil-WinRM shell v3.7
            *Evil-WinRM* PS C:\\Users\\svc-alfresco\\Documents>
        """
        # Check for error messages FIRST (before success indicators)
        if "WinRM::WinRMAuthorizationError" in output or "Bad credentials" in output:
            return ParseResult(success=False, extracted_data={"error": "auth_failed"})

        if "Evil-WinRM shell" in output or "*Evil-WinRM*" in output:
            return ParseResult(
                success=True,
                extracted_data={"access_level": "user", "shell_type": "winrm"},
                next_action="collect_bloodhound",
            )

        return ParseResult(success=False, extracted_data={})

    @staticmethod
    def parse_crackmapexec_output(output: str) -> ParseResult:
        """Parse CrackMapExec output to detect valid credentials.

        Args:
            output: Raw output from crackmapexec

        Returns:
            ParseResult with access_level if successful

        Example output:
            SMB  10.10.10.161  445  FOREST  [+] HTB.LOCAL\\svc-alfresco:s3rvice
            SMB  10.10.10.161  445  FOREST  [+] HTB.LOCAL\\admin:password (Pwn3d!)
        """
        if "[+]" in output:
            if "Pwn3d!" in output:
                return ParseResult(
                    success=True,
                    extracted_data={"access_level": "admin", "pwned": True},
                    next_action="enumerate_smb_shares",
                )
            else:
                return ParseResult(
                    success=True,
                    extracted_data={"access_level": "user", "pwned": False},
                    next_action="check_winrm",
                )

        if "[-]" in output:
            return ParseResult(success=False, extracted_data={"error": "invalid_creds"})

        return ParseResult(success=False, extracted_data={})

    @staticmethod
    def parse_secretsdump_output(output: str) -> ParseResult:
        """Parse secretsdump output to extract NTLM hashes.

        Args:
            output: Raw output from impacket-secretsdump

        Returns:
            ParseResult with admin hash if found

        Example output:
            Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
        """
        # Look for Administrator hash
        match = re.search(
            r'Administrator:500:[a-f0-9]{32}:([a-f0-9]{32}):::',
            output,
            re.IGNORECASE
        )
        if match:
            return ParseResult(
                success=True,
                extracted_data={
                    "admin_hash": match.group(1),
                    "full_hash": f"aad3b435b51404eeaad3b435b51404ee:{match.group(1)}",
                    "hash_type": "ntlm",
                },
                next_action="pass_the_hash",
            )

        # Check for any successful hash extraction
        if "Dumping Domain Credentials" in output and ":::" in output:
            return ParseResult(
                success=True,
                extracted_data={"hashes_dumped": True},
                next_action=None,  # Manual review needed
            )

        return ParseResult(success=False, extracted_data={})

    @staticmethod
    def parse_bloodhound_output(output: str) -> ParseResult:
        """Parse bloodhound-python output to detect successful collection.

        Args:
            output: Raw output from bloodhound-python

        Returns:
            ParseResult indicating collection success

        Example output:
            INFO: Found AD domain: htb.local
            INFO: Done in 00:00:45
        """
        if "Done in" in output or "Compressing output" in output:
            # Count JSON files mentioned
            json_count = len(re.findall(r'\w+\.json', output))
            return ParseResult(
                success=True,
                extracted_data={
                    "collection_complete": True,
                    "json_files": json_count,
                },
                next_action="analyze_bloodhound",
            )

        if "Error" in output or "failed" in output.lower():
            return ParseResult(success=False, extracted_data={"error": "collection_failed"})

        return ParseResult(success=False, extracted_data={})

    @classmethod
    def parse_output(cls, command: str, output: str, attack_type: str = "") -> ParseResult:
        """Auto-detect and parse command output.

        Args:
            command: The command that was run
            output: The command's output
            attack_type: Optional hint for parser selection

        Returns:
            ParseResult from the appropriate parser
        """
        command_lower = command.lower() if command else ""

        # Select parser based on command or attack type
        if attack_type == "asrep_roast" or "getnpusers" in command_lower:
            return cls.parse_asrep_output(output)
        elif attack_type == "kerberoast" or "getuserspns" in command_lower:
            return cls.parse_kerberoast_output(output)
        elif "hashcat" in command_lower:
            return cls.parse_hashcat_output(output)
        elif "john" in command_lower:
            return cls.parse_john_output(output)
        elif "evil-winrm" in command_lower:
            return cls.parse_winrm_output(output)
        elif "crackmapexec" in command_lower or "cme " in command_lower:
            return cls.parse_crackmapexec_output(output)
        elif "secretsdump" in command_lower:
            return cls.parse_secretsdump_output(output)
        elif "bloodhound" in command_lower:
            return cls.parse_bloodhound_output(output)

        # Default: assume success if command ran
        return ParseResult(success=True, extracted_data={})
