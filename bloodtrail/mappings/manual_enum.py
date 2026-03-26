"""Manual enumeration command templates for pwned users without BloodHound edges.

When BloodHound doesn't detect AdminTo/CanRDP/CanPSRemote edges, these commands
help discover access that may exist but wasn't captured during collection:
- Service accounts with local admin on machines where they run
- Local group memberships not enumerable during BH collection
- Access via SPNs (service accounts)
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ManualEnumCommand:
    """A manual enumeration command template."""
    id: str
    name: str
    description: str
    priority: str  # "high" or "medium"
    templates: Dict[str, str]  # cred_type -> command template
    spn_only: bool = False  # Only show if user has SPNs


# Command templates for manual enumeration
MANUAL_ENUM_COMMANDS: List[ManualEnumCommand] = [
    ManualEnumCommand(
        id="smb_admin_test",
        name="Test Admin Access",
        description="Check if user has local admin on machines (look for Pwn3d!)",
        priority="high",
        templates={
            "password": "crackmapexec smb <TARGET_SUBNET> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>",
            "ntlm-hash": "crackmapexec smb <TARGET_SUBNET> -u '<USERNAME>' -H '<HASH>' -d <DOMAIN>",
            "kerberos-ticket": "crackmapexec smb <TARGET_SUBNET> -k --kdcHost <DC_IP>",
        }
    ),
    ManualEnumCommand(
        id="smb_shares",
        name="Enumerate Shares",
        description="Find accessible shares across the network",
        priority="high",
        templates={
            "password": "crackmapexec smb <TARGET_SUBNET> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --shares",
            "ntlm-hash": "crackmapexec smb <TARGET_SUBNET> -u '<USERNAME>' -H '<HASH>' -d <DOMAIN> --shares",
        }
    ),
    ManualEnumCommand(
        id="spn_machine_test",
        name="Test SPN Machine",
        description="Service accounts often have admin where they run",
        priority="high",
        spn_only=True,
        templates={
            "password": "crackmapexec smb <SPN_TARGET> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>",
            "ntlm-hash": "crackmapexec smb <SPN_TARGET> -u '<USERNAME>' -H '<HASH>' -d <DOMAIN>",
        }
    ),
    ManualEnumCommand(
        id="winrm_test",
        name="Test WinRM",
        description="Check for PowerShell Remoting access",
        priority="medium",
        templates={
            "password": "crackmapexec winrm <TARGET_SUBNET> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>",
            "ntlm-hash": "crackmapexec winrm <TARGET_SUBNET> -u '<USERNAME>' -H '<HASH>' -d <DOMAIN>",
        }
    ),
    ManualEnumCommand(
        id="rdp_test",
        name="Test RDP",
        description="Check for Remote Desktop access",
        priority="medium",
        templates={
            "password": "crackmapexec rdp <TARGET_SUBNET> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>",
        }
    ),
    ManualEnumCommand(
        id="sessions_enum",
        name="Enum Sessions",
        description="Find where users are logged in",
        priority="medium",
        templates={
            "password": "crackmapexec smb <TARGET_SUBNET> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --sessions",
            "ntlm-hash": "crackmapexec smb <TARGET_SUBNET> -u '<USERNAME>' -H '<HASH>' -d <DOMAIN> --sessions",
        }
    ),
]


def fill_manual_enum_command(
    template: str,
    username: str,
    domain: str,
    cred_value: str,
    target_subnet: str = "<TARGET_SUBNET>",
    spn_target: str = None,
    dc_ip: str = None,
) -> str:
    """Fill placeholders in a manual enumeration command template.

    Args:
        template: Command template with placeholders
        username: Username (without domain)
        domain: Domain name
        cred_value: Password or hash value
        target_subnet: Network subnet (e.g., 192.168.249.0/24)
        spn_target: Specific SPN target machine
        dc_ip: Domain Controller IP

    Returns:
        Filled command string
    """
    cmd = template
    cmd = cmd.replace("<USERNAME>", username)
    cmd = cmd.replace("<DOMAIN>", domain.lower() if domain else "<DOMAIN>")
    cmd = cmd.replace("<PASSWORD>", cred_value)
    cmd = cmd.replace("<HASH>", cred_value)
    cmd = cmd.replace("<TARGET_SUBNET>", target_subnet)
    cmd = cmd.replace("<DC_IP>", dc_ip or "<DC_IP>")

    if spn_target:
        cmd = cmd.replace("<SPN_TARGET>", spn_target)

    return cmd


def extract_machine_from_spn(spn: str) -> Optional[str]:
    """Extract machine name from an SPN.

    Examples:
        HTTP/web04.corp.com -> web04.corp.com
        HTTP/web04.corp.com:80 -> web04.corp.com
        MSSQLSvc/sql01.corp.com:1433 -> sql01.corp.com

    Args:
        spn: Service Principal Name string

    Returns:
        Machine hostname or None if not parseable
    """
    if "/" not in spn:
        return None

    # Get part after service type
    machine_part = spn.split("/", 1)[1]

    # Remove port if present
    if ":" in machine_part:
        machine_part = machine_part.split(":")[0]

    return machine_part


def derive_subnet_from_ip(ip: str) -> str:
    """Derive /24 subnet from IP address.

    Args:
        ip: IP address (e.g., 192.168.249.70)

    Returns:
        Subnet string (e.g., 192.168.249.0/24)
    """
    if not ip:
        return "<TARGET_SUBNET>"

    parts = ip.split(".")
    if len(parts) != 4:
        return "<TARGET_SUBNET>"

    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
