"""
Command placeholder filling for bloodtrail.

Universal command template filling with IP preference logic.
"""

from typing import Optional

from .text_utils import extract_username, infer_dc_hostname


def fill_command(
    template: str,
    username: str = "",
    target: str = "",
    target_ip: str = "",
    domain: str = "",
    dc_ip: str = "",
    password: str = "",
    ntlm_hash: str = "",
    cred_value: str = "",
    listener_ip: str = "",
) -> str:
    """
    Universal command placeholder filler with IP preference.

    Fills all standard placeholders plus optional credentials.
    Credentials only fill if non-empty string provided.

    IP Preference Logic:
        - If target_ip is provided, use it for <TARGET>, <COMPUTER>, and <TARGET_IP>
        - Otherwise, fallback to target (FQDN)
        - This allows commands to use IP addresses when available

    Args:
        template: Command template with <PLACEHOLDERS>
        username: Username (UPN format OK - will extract just username)
        target: Target computer FQDN (e.g., FILES04.CORP.COM)
        target_ip: Resolved IP address (e.g., 10.0.0.15) - PREFERRED over target
        domain: Domain name
        dc_ip: Domain controller IP/hostname (auto-inferred if not provided)
        password: Password credential (fills <PASSWORD>)
        ntlm_hash: NTLM hash credential (fills <HASH>, <NTLM_HASH>)
        cred_value: Generic credential value (fills <CRED_VALUE>)
        listener_ip: Listener IP for coercion commands (fills <LISTENER_IP>)

    Returns:
        Filled command string

    Examples:
        >>> # With IP (preferred)
        >>> fill_command(
        ...     "psexec <TARGET>",
        ...     target="FILES04.CORP.COM",
        ...     target_ip="10.0.0.15"
        ... )
        'psexec 10.0.0.15'

        >>> # Without IP (fallback to FQDN)
        >>> fill_command(
        ...     "psexec <TARGET>",
        ...     target="FILES04.CORP.COM"
        ... )
        'psexec FILES04.CORP.COM'

        >>> # Coercion command with listener
        >>> fill_command(
        ...     "petitpotam.py <LISTENER_IP> <TARGET_IP>",
        ...     target_ip="10.0.0.1",
        ...     listener_ip="10.0.0.50"
        ... )
        'petitpotam.py 10.0.0.50 10.0.0.1'
    """
    result = template

    # === User placeholders ===
    if username:
        # Handle UPN format (MIKE@CORP.COM -> MIKE)
        clean_user = extract_username(username) if "@" in username else username
        result = result.replace("<USERNAME>", clean_user)
        result = result.replace("<USER>", clean_user)

    # === Target placeholders - PREFER IP OVER FQDN ===
    # Use IP if available, otherwise fallback to FQDN
    effective_target = target_ip if target_ip else target
    if effective_target:
        result = result.replace("<TARGET>", effective_target)
        result = result.replace("<COMPUTER>", effective_target)
        result = result.replace("<TARGET_IP>", effective_target)

    # === Listener placeholder (for coercion commands) ===
    if listener_ip:
        result = result.replace("<LISTENER_IP>", listener_ip)

    # === Domain placeholders ===
    if domain:
        result = result.replace("<DOMAIN>", domain.lower())

    # === DC placeholders ===
    dc = dc_ip or (infer_dc_hostname(domain) if domain else "")
    if dc:
        result = result.replace("<DC_IP>", dc)
        result = result.replace("<DC>", dc)

    # === Credential placeholders (only if provided) ===
    if password:
        result = result.replace("<PASSWORD>", password)

    if ntlm_hash:
        result = result.replace("<HASH>", ntlm_hash)
        result = result.replace("<NTLM_HASH>", ntlm_hash)

    if cred_value:
        result = result.replace("<CRED_VALUE>", cred_value)

    return result


def fill_pwned_command(
    template: str,
    username: str,
    domain: str,
    target: str,
    cred_value: str,
    dc_ip: Optional[str] = None,
    target_ip: str = ""
) -> str:
    """
    Fill a command template with pwned user credentials.

    DEPRECATED: Use fill_command() instead for new code.
    This function is kept for backward compatibility.

    Args:
        template: Command template with placeholders
        username: Username
        domain: Domain name
        target: Target computer FQDN
        cred_value: Credential value
        dc_ip: Domain controller IP
        target_ip: Resolved IP address (preferred over target FQDN)
    """
    return fill_command(
        template=template,
        username=username,
        domain=domain,
        target=target,
        target_ip=target_ip,
        dc_ip=dc_ip or "",
        cred_value=cred_value,
    )
