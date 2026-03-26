"""
Guest Account SMB Probe.

Tests if guest account (guest:'') has access to SMB shares.
This is a common fallback when anonymous access is denied.
"""

import subprocess
import time
from typing import Optional, List, Dict, Any

from .base import EnumerationResult, AuthLevel


def probe_guest_smb(
    target: str,
    domain: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Probe SMB with guest:'' credentials.

    Returns:
        Dict with:
            - success: bool
            - shares: list of accessible shares
            - username: 'guest' if successful
            - password: '' if successful
    """
    # ANSI colors
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    D = "\033[90m"
    C = "\033[96m"
    X = "\033[0m"

    result = {
        "success": False,
        "shares": [],
        "username": None,
        "password": None,
        "error": None,
    }

    try:
        # Try crackmapexec with guest:''
        cmd = [
            "crackmapexec", "smb", target,
            "-u", "guest",
            "-p", "",
            "--shares",
        ]

        # Verbose: Show command
        if verbose:
            print(f"       {D}Command:{X} {' '.join(cmd)}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = proc.stdout + proc.stderr

        # Verbose: Show output
        if verbose and output.strip():
            print(f"       {D}Output:{X}")
            for line in output.strip().split('\n')[:10]:
                if '[+]' in line:
                    print(f"       {G}│ {line}{X}")
                elif '[-]' in line:
                    print(f"       {R}│ {line}{X}")
                else:
                    print(f"       {D}│ {line}{X}")

        # Check for success
        if "[+]" in output and "guest:" in output.lower():
            result["success"] = True
            result["username"] = "guest"
            result["password"] = ""

            # Extract shares with READ/WRITE access
            # Format: SMB ... Share Permissions Remark
            # Then: SMB ... HR READ
            import re
            share_pattern = r'SMB\s+\S+\s+\d+\s+\S+\s+(\S+)\s+(READ|WRITE|READ,\s*WRITE)'
            matches = re.findall(share_pattern, output, re.IGNORECASE)

            for share_name, access in matches:
                if share_name.lower() not in ['-----', 'share']:
                    result["shares"].append({
                        "name": share_name,
                        "access": access.upper(),
                    })

        elif "[-]" in output or "STATUS_LOGON_FAILURE" in output:
            result["error"] = "Guest access denied"

        elif "STATUS_ACCOUNT_DISABLED" in output:
            result["error"] = "Guest account disabled"

        else:
            result["error"] = "Unknown response"

    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except FileNotFoundError:
        result["error"] = "crackmapexec not found"
    except Exception as e:
        result["error"] = str(e)

    return result


def probe_guest_smb_smbclient(
    target: str,
    domain: Optional[str] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Alternative probe using smbclient -L.

    Falls back to this if crackmapexec not available.
    """
    result = {
        "success": False,
        "shares": [],
        "username": None,
        "password": None,
        "error": None,
    }

    try:
        cmd = [
            "smbclient", "-L", f"//{target}",
            "-U", "guest%",
            "-N",
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = proc.stdout + proc.stderr

        # Check for share listing
        if "Sharename" in output and "Type" in output:
            result["success"] = True
            result["username"] = "guest"
            result["password"] = ""

            # Extract shares
            import re
            # Pattern: sharename   Disk/IPC   comment
            share_pattern = r'^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)$'
            for line in output.split('\n'):
                match = re.match(share_pattern, line, re.IGNORECASE)
                if match:
                    share_name = match.group(1)
                    share_type = match.group(2)
                    if share_name.lower() not in ['sharename', '--------']:
                        result["shares"].append({
                            "name": share_name,
                            "type": share_type,
                        })

        elif "NT_STATUS_ACCESS_DENIED" in output:
            result["error"] = "Guest access denied"

        elif "NT_STATUS_LOGON_FAILURE" in output:
            result["error"] = "Guest logon failure"

        else:
            result["error"] = "Could not list shares"

    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except FileNotFoundError:
        result["error"] = "smbclient not found"
    except Exception as e:
        result["error"] = str(e)

    return result


def try_guest_access(
    target: str,
    domain: Optional[str] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Try guest access using available tools.

    Returns best result from available methods.
    """
    # Try crackmapexec first (more detailed output)
    result = probe_guest_smb(target, domain, timeout)

    if result["success"]:
        return result

    # Fall back to smbclient
    if "not found" in (result.get("error") or ""):
        result = probe_guest_smb_smbclient(target, domain, timeout)

    return result
