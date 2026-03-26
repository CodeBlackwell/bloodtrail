"""
Pre-flight Domain Detection.

Fast, lightweight domain detection before running enumerators.
Provides domain name for tools like Kerbrute that need it upfront.

Detection methods (in order of preference):
1. LDAP RootDSE - fastest, anonymous query
2. rpcclient lsaquery - returns domain name and SID
3. SMB/NetBIOS - nmblookup
"""

import re
import subprocess
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class DomainInfo:
    """Detected domain information."""
    domain: Optional[str] = None
    netbios_name: Optional[str] = None
    domain_sid: Optional[str] = None
    dc_hostname: Optional[str] = None
    detection_method: Optional[str] = None


def detect_domain(target: str, timeout: int = 10) -> DomainInfo:
    """
    Detect domain name from target using multiple methods.

    Tries methods in order of speed/reliability:
    1. LDAP RootDSE query (fastest)
    2. rpcclient lsaquery (also gets SID)
    3. SMB NetBIOS lookup

    Args:
        target: IP address or hostname
        timeout: Timeout per method in seconds

    Returns:
        DomainInfo with detected values
    """
    info = DomainInfo()

    # Method 1: LDAP RootDSE (fastest, most reliable)
    ldap_result = _detect_via_ldap(target, timeout)
    if ldap_result:
        info.domain = ldap_result
        info.detection_method = "LDAP RootDSE"
        return info

    # Method 2: rpcclient lsaquery (also gets SID)
    rpc_result = _detect_via_rpcclient(target, timeout)
    if rpc_result:
        info.domain, info.netbios_name, info.domain_sid = rpc_result
        info.detection_method = "RPC lsaquery"
        return info

    # Method 3: SMB/NetBIOS
    smb_result = _detect_via_smb(target, timeout)
    if smb_result:
        info.netbios_name = smb_result
        # NetBIOS name isn't FQDN, but better than nothing
        info.domain = smb_result
        info.detection_method = "SMB NetBIOS"
        return info

    return info


def _detect_via_ldap(target: str, timeout: int) -> Optional[str]:
    """
    Detect domain via LDAP RootDSE anonymous query.

    Query: ldapsearch -x -H ldap://IP -s base namingContexts
    Returns: DC=cascade,DC=local -> CASCADE.LOCAL
    """
    try:
        cmd = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-s", "base", "defaultNamingContext"
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = proc.stdout

        # Parse: defaultNamingContext: DC=cascade,DC=local
        match = re.search(r'defaultNamingContext:\s*(.+)', output, re.I)
        if match:
            dn = match.group(1).strip()
            # Convert DC=cascade,DC=local to cascade.local
            domain = _dn_to_domain(dn)
            if domain:
                return domain.upper()

    except (subprocess.TimeoutExpired, Exception):
        pass

    return None


def _detect_via_rpcclient(target: str, timeout: int) -> Optional[Tuple[str, str, str]]:
    """
    Detect domain via rpcclient lsaquery.

    Returns: (domain_fqdn, netbios_name, domain_sid)
    """
    try:
        cmd = ["rpcclient", "-U", "", "-N", target, "-c", "lsaquery"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = proc.stdout + proc.stderr

        if "NT_STATUS_ACCESS_DENIED" in output:
            return None

        # Parse: Domain Name: CASCADE
        # Parse: Domain Sid: S-1-5-21-...
        netbios_match = re.search(r'Domain Name:\s*(\S+)', output, re.I)
        sid_match = re.search(r'Domain Sid:\s*(S-[\d-]+)', output, re.I)

        if netbios_match:
            netbios = netbios_match.group(1)
            sid = sid_match.group(1) if sid_match else None

            # Try to get FQDN from DNS or construct it
            fqdn = _resolve_fqdn(target, netbios, timeout)

            return (fqdn or netbios, netbios, sid)

    except (subprocess.TimeoutExpired, Exception):
        pass

    return None


def _detect_via_smb(target: str, timeout: int) -> Optional[str]:
    """
    Detect domain via SMB/NetBIOS lookup.

    Uses nmblookup or crackmapexec for NetBIOS name.
    """
    try:
        # Try nmblookup first
        cmd = ["nmblookup", "-A", target]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = proc.stdout

        # Parse: CASCADE         <00> - <GROUP> ...
        # Look for the <00> GROUP entry which is the domain
        match = re.search(r'^\s*(\S+)\s+<00>\s+-\s+<GROUP>', output, re.MULTILINE)
        if match:
            return match.group(1).upper()

    except (subprocess.TimeoutExpired, Exception):
        pass

    return None


def _dn_to_domain(dn: str) -> Optional[str]:
    """
    Convert Distinguished Name to domain.

    DC=cascade,DC=local -> cascade.local
    """
    parts = []
    for component in dn.split(','):
        component = component.strip()
        if component.upper().startswith('DC='):
            parts.append(component[3:])

    if parts:
        return '.'.join(parts)
    return None


def _resolve_fqdn(target: str, netbios: str, timeout: int) -> Optional[str]:
    """
    Try to resolve FQDN from NetBIOS name.

    Attempts DNS reverse lookup or LDAP query.
    """
    try:
        # Quick LDAP check for domain suffix
        cmd = [
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-s", "base", "dnsHostName"
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = proc.stdout

        # Parse: dnsHostName: CASC-DC1.cascade.local
        match = re.search(r'dnsHostName:\s*(\S+)', output, re.I)
        if match:
            hostname = match.group(1)
            # Extract domain from FQDN
            parts = hostname.split('.', 1)
            if len(parts) > 1:
                return parts[1].upper()

    except (subprocess.TimeoutExpired, Exception):
        pass

    return None
