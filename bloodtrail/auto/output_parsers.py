"""
Output parsers for various pentesting tool outputs.

Detects success/failure indicators and extracts relevant data
from command output for use by the auto-orchestrator.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class ParsedOutput:
    """Parsed command output with extracted data."""
    success: bool
    message: str = ""
    access_level: Optional[str] = None
    credentials: List[Dict[str, str]] = field(default_factory=list)
    shares: List[Dict[str, str]] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)


def parse_crackmapexec(output: str, expected_user: str = "") -> ParsedOutput:
    """
    Parse CrackMapExec/NetExec output for credential validation.

    Detects:
    - [+] Valid credential
    - (Pwn3d!) Admin access
    - [-] Invalid credential
    - SAM hashes if dumped

    Args:
        output: Command stdout + stderr
        expected_user: Expected username for validation

    Returns:
        ParsedOutput with success status and access level
    """
    result = ParsedOutput(success=False)

    # Check for success indicators
    if "[+]" in output:
        result.success = True

        # Check for admin access
        if "(Pwn3d!)" in output:
            result.access_level = "admin"
            result.message = "Valid credential with admin privileges"
        else:
            result.access_level = "user"
            result.message = "Valid credential (user access)"

        # Extract SAM hashes if present
        # Format: username:rid:lmhash:nthash:::
        hash_pattern = r'([A-Za-z0-9_\.\-\\]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
        matches = re.findall(hash_pattern, output)
        for match in matches:
            username, rid, lm, nt = match
            result.hashes.append(f"{username}:{rid}:{lm}:{nt}:::")

        # Extract usernames from enumeration
        # CME format: domain\username
        user_pattern = r'[\w\.\-]+\\([\w\.\-]+)\s+'
        result.users = list(set(re.findall(user_pattern, output)))

    elif "[-]" in output or "STATUS_LOGON_FAILURE" in output:
        result.success = False
        result.message = "Invalid credential"

    elif "STATUS_PASSWORD_EXPIRED" in output:
        result.success = True  # Password valid, just expired
        result.access_level = "expired"
        result.message = "Valid credential but password expired"

    elif "STATUS_ACCOUNT_LOCKED_OUT" in output:
        result.success = False
        result.message = "Account locked out"
        result.extra["locked"] = True

    elif "STATUS_PASSWORD_MUST_CHANGE" in output:
        result.success = True
        result.access_level = "must_change"
        result.message = "Valid credential but password must change"

    return result


def parse_smbmap(output: str) -> ParsedOutput:
    """
    Parse SMBMap output for share access information.

    Detects readable/writable shares from the output table.

    Args:
        output: smbmap command output

    Returns:
        ParsedOutput with discovered shares
    """
    result = ParsedOutput(success=False, shares=[])

    # SMBMap output format:
    #   ShareName     Type   Comment
    #   ---------     ----   -------
    #   ADMIN$        Disk   Remote Admin
    #   Data          Disk   READ ONLY
    # Or with permissions:
    #   Disk        Permissions     Comment
    #   ----        -----------     -------
    #   Data        READ            Data share

    # Pattern 1: Standard format with READ/WRITE
    share_pattern1 = r'^\s*(\S+)\s+Disk\s+.*?(READ|WRITE|READ,\s*WRITE)'
    matches1 = re.findall(share_pattern1, output, re.MULTILINE | re.IGNORECASE)

    # Pattern 2: Table format
    share_pattern2 = r'^\s*(\S+)\s+(READ|WRITE|READ ONLY|READ, WRITE)\s+'
    matches2 = re.findall(share_pattern2, output, re.MULTILINE | re.IGNORECASE)

    # Pattern 3: [+] format from newer versions
    share_pattern3 = r'\[\+\]\s+(\S+)\s+.*?(READ|WRITE)'
    matches3 = re.findall(share_pattern3, output, re.IGNORECASE)

    all_matches = matches1 + matches2 + matches3

    seen = set()
    for share_name, access in all_matches:
        if share_name.lower() in seen:
            continue
        seen.add(share_name.lower())

        # Normalize access
        access_norm = access.upper().replace(" ", "").replace(",", ", ")

        result.shares.append({
            "name": share_name,
            "access": access_norm,
            "writable": "WRITE" in access_norm,
        })

    # Filter out default shares that are usually not interesting
    default_shares = {"ipc$", "print$"}
    result.shares = [s for s in result.shares if s["name"].lower() not in default_shares]

    result.success = len(result.shares) > 0
    result.message = f"Found {len(result.shares)} accessible shares"

    return result


def parse_ldapsearch(output: str) -> ParsedOutput:
    """
    Parse ldapsearch output for interesting attributes.

    Detects:
    - Password-like attributes (cascadeLegacyPwd, userPassword, etc.)
    - Service account SPNs
    - Group memberships

    Args:
        output: ldapsearch command output

    Returns:
        ParsedOutput with extracted credentials and users
    """
    result = ParsedOutput(success=False, credentials=[], users=[])

    # Password-like attributes
    pwd_attributes = [
        "cascadelegacypwd",
        "userpassword",
        "unixuserpassword",
        "unicodepwd",
        "msmcsadmpwd",
        "ms-mcs-admpwd",
        "laps",
    ]

    # Find password attributes
    for attr in pwd_attributes:
        pattern = rf'^{attr}:\s*(.+)$'
        matches = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
        for value in matches:
            result.credentials.append({
                "attribute": attr,
                "value": value.strip(),
                "needs_decode": True,
            })

    # Extract usernames (sAMAccountName)
    sam_pattern = r'^sAMAccountName:\s*(.+)$'
    result.users = [m.strip() for m in re.findall(sam_pattern, output, re.MULTILINE)]

    # Extract SPNs for Kerberoasting
    spn_pattern = r'^servicePrincipalName:\s*(.+)$'
    spns = re.findall(spn_pattern, output, re.MULTILINE)
    if spns:
        result.extra["spns"] = [s.strip() for s in spns]

    # Extract group memberships
    member_pattern = r'^memberOf:\s*(.+)$'
    members = re.findall(member_pattern, output, re.MULTILINE)
    if members:
        result.extra["groups"] = [m.strip() for m in members]

    result.success = len(result.credentials) > 0 or len(result.users) > 0
    result.message = f"Found {len(result.credentials)} password attributes, {len(result.users)} users"

    return result


def parse_getnpusers(output: str) -> ParsedOutput:
    """
    Parse GetNPUsers output for AS-REP hashes.

    Args:
        output: impacket-GetNPUsers output

    Returns:
        ParsedOutput with AS-REP hashes
    """
    result = ParsedOutput(success=False, hashes=[])

    # AS-REP hash format: $krb5asrep$23$user@DOMAIN:salt$hash
    hash_pattern = r'\$krb5asrep\$[^\s]+'
    result.hashes = re.findall(hash_pattern, output)

    result.success = len(result.hashes) > 0
    result.message = f"Found {len(result.hashes)} AS-REP hashes"

    return result


def parse_getuserspns(output: str) -> ParsedOutput:
    """
    Parse GetUserSPNs output for Kerberoast hashes.

    Args:
        output: impacket-GetUserSPNs output

    Returns:
        ParsedOutput with TGS hashes
    """
    result = ParsedOutput(success=False, hashes=[])

    # TGS hash format: $krb5tgs$23$*user$DOMAIN$...
    hash_pattern = r'\$krb5tgs\$[^\s]+'
    result.hashes = re.findall(hash_pattern, output)

    result.success = len(result.hashes) > 0
    result.message = f"Found {len(result.hashes)} TGS hashes"

    return result


def parse_secretsdump(output: str) -> ParsedOutput:
    """
    Parse secretsdump output for credentials.

    Args:
        output: impacket-secretsdump output

    Returns:
        ParsedOutput with extracted hashes
    """
    result = ParsedOutput(success=False, hashes=[], credentials=[])

    # SAM hashes: user:rid:lm:nt:::
    sam_pattern = r'^([^:\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$'
    sam_matches = re.findall(sam_pattern, output, re.MULTILINE)
    for user, rid, lm, nt in sam_matches:
        result.hashes.append(f"{user}:{rid}:{lm}:{nt}:::")

    # NTDS.dit format: domain\user:rid:lm:nt:::
    ntds_pattern = r'^([^:\s]+\\[^:\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$'
    ntds_matches = re.findall(ntds_pattern, output, re.MULTILINE)
    for user, rid, lm, nt in ntds_matches:
        result.hashes.append(f"{user}:{rid}:{lm}:{nt}:::")

    # Cleartext passwords from DPAPI/LSA
    cleartext_pattern = r'Cleartext password:\s*(.+)$'
    cleartexts = re.findall(cleartext_pattern, output, re.MULTILINE)
    for pwd in cleartexts:
        result.credentials.append({"password": pwd.strip(), "type": "cleartext"})

    result.success = len(result.hashes) > 0 or len(result.credentials) > 0
    result.message = f"Found {len(result.hashes)} hashes, {len(result.credentials)} cleartext"

    return result


def parse_bloodhound_python(output: str) -> ParsedOutput:
    """
    Parse bloodhound-python output for collection status.

    Args:
        output: bloodhound-python output

    Returns:
        ParsedOutput with collection status
    """
    result = ParsedOutput(success=False)

    # Look for success indicators
    if "Done in" in output or "Compressing" in output:
        result.success = True
        result.message = "BloodHound collection completed"

        # Extract output file
        zip_pattern = r'Compressing output into\s+(\S+\.zip)'
        match = re.search(zip_pattern, output)
        if match:
            result.extra["output_file"] = match.group(1)

    elif "error" in output.lower() or "failed" in output.lower():
        result.success = False
        result.message = "BloodHound collection failed"

    return result


def detect_tool(command: str) -> str:
    """
    Detect which tool a command is using.

    Args:
        command: Command string

    Returns:
        Tool identifier string
    """
    cmd_lower = command.lower()

    tool_patterns = [
        ("crackmapexec", "cme"),
        ("netexec", "cme"),
        ("smbmap", "smbmap"),
        ("ldapsearch", "ldapsearch"),
        ("getnpusers", "getnpusers"),
        ("getuserspns", "getuserspns"),
        ("secretsdump", "secretsdump"),
        ("bloodhound-python", "bloodhound"),
        ("bloodhound.py", "bloodhound"),
    ]

    for pattern, tool_id in tool_patterns:
        if pattern in cmd_lower:
            return tool_id

    return "unknown"


def parse_output(command: str, output: str) -> ParsedOutput:
    """
    Auto-detect tool and parse output accordingly.

    Args:
        command: Original command string
        output: Command output

    Returns:
        ParsedOutput from appropriate parser
    """
    tool = detect_tool(command)

    parsers = {
        "cme": parse_crackmapexec,
        "smbmap": parse_smbmap,
        "ldapsearch": parse_ldapsearch,
        "getnpusers": parse_getnpusers,
        "getuserspns": parse_getuserspns,
        "secretsdump": parse_secretsdump,
        "bloodhound": parse_bloodhound_python,
    }

    parser = parsers.get(tool)
    if parser:
        return parser(output)

    # Default: simple success check
    return ParsedOutput(
        success="error" not in output.lower(),
        message="Command completed",
    )
