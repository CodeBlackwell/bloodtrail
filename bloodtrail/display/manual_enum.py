"""Display manual enumeration suggestions for pwned users without BloodHound edges.

When BloodHound doesn't show AdminTo/CanRDP/CanPSRemote edges, these suggestions
help users discover access that may exist but wasn't captured during collection.
"""

from typing import List, Tuple

from .base import Colors, NoColors
from ..mappings.manual_enum import (
    MANUAL_ENUM_COMMANDS,
    fill_manual_enum_command,
    extract_machine_from_spn,
    derive_subnet_from_ip,
)


def generate_manual_enumeration_suggestions(
    username: str,
    domain: str,
    cred_type: str,
    cred_value: str,
    spns: List[str] = None,
    dc_ip: str = None,
    use_colors: bool = True,
) -> Tuple[List[str], List[str]]:
    """Generate manual enumeration suggestions for users without BloodHound edges.

    Shows targeted commands to discover access that BloodHound may have missed:
    - SPN-based targets (service accounts likely have admin where they run)
    - Network-wide testing (admin/WinRM/RDP/shares)
    - Session enumeration

    Args:
        username: Username (without domain)
        domain: Domain name
        cred_type: Credential type (password, ntlm-hash, etc.)
        cred_value: Credential value (password or hash)
        spns: List of SPNs for this user (if any)
        dc_ip: Domain Controller IP for subnet derivation
        use_colors: Enable ANSI colors

    Returns:
        Tuple of (console_lines, markdown_lines)
    """
    c = Colors if use_colors else NoColors
    spns = spns or []

    console_lines = []
    markdown_lines = []

    # Derive subnet from DC IP
    target_subnet = derive_subnet_from_ip(dc_ip)

    # Header
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}MANUAL ENUMERATION{c.RESET} {c.DIM}(BloodHound edges may be incomplete){c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*60}{c.RESET}")
    console_lines.append("")

    markdown_lines.append("#### Manual Enumeration (BloodHound edges may be incomplete)")
    markdown_lines.append("")
    markdown_lines.append("> BloodHound may not capture all access:")
    markdown_lines.append("> - Service accounts often have local admin where they run")
    markdown_lines.append("> - Local group memberships require SMB enumeration during collection")
    if spns:
        markdown_lines.append("> - SPNs indicate machines where this account runs services")
    markdown_lines.append("")

    # Why this matters
    console_lines.append(f"  {c.DIM}BloodHound may not capture all access:{c.RESET}")
    console_lines.append(f"  {c.DIM}  - Service accounts often have local admin where they run{c.RESET}")
    console_lines.append(f"  {c.DIM}  - Local group memberships require SMB enumeration during collection{c.RESET}")
    if spns:
        console_lines.append(f"  {c.DIM}  - SPNs indicate machines where this account runs services{c.RESET}")
    console_lines.append("")

    # SPN-based targets (highest priority for service accounts)
    if spns:
        spn_machines = []
        for spn in spns:
            machine = extract_machine_from_spn(spn)
            if machine and machine not in spn_machines:
                spn_machines.append(machine)

        if spn_machines:
            console_lines.append(f"  {c.CYAN}{c.BOLD}SPN-Based Targets{c.RESET} {c.DIM}(service accounts often have admin here){c.RESET}")
            console_lines.append("")

            markdown_lines.append("**SPN-Based Targets** (service accounts often have admin here)")
            markdown_lines.append("")
            markdown_lines.append("| Target | Command |")
            markdown_lines.append("|--------|---------|")

            for machine in spn_machines[:5]:  # Limit to 5
                template = MANUAL_ENUM_COMMANDS[2].templates.get(cred_type)  # spn_machine_test
                if template:
                    cmd = fill_manual_enum_command(
                        template,
                        username=username,
                        domain=domain,
                        cred_value=cred_value,
                        spn_target=machine,
                        dc_ip=dc_ip,
                    )
                    console_lines.append(f"    {c.BOLD}{machine:<30}{c.RESET} {c.GREEN}{cmd}{c.RESET}")
                    markdown_lines.append(f"| {machine} | `{cmd}` |")

            console_lines.append("")
            markdown_lines.append("")

    # Network-wide testing
    console_lines.append(f"  {c.CYAN}{c.BOLD}Network-Wide Testing{c.RESET}")
    console_lines.append("")

    markdown_lines.append("**Network-Wide Testing**")
    markdown_lines.append("")
    markdown_lines.append("| Test | Command |")
    markdown_lines.append("|------|---------|")

    # Show high priority commands first
    high_priority = [cmd for cmd in MANUAL_ENUM_COMMANDS if cmd.priority == "high" and not cmd.spn_only]
    medium_priority = [cmd for cmd in MANUAL_ENUM_COMMANDS if cmd.priority == "medium"]

    for cmd_def in high_priority:
        template = cmd_def.templates.get(cred_type)
        if template:
            cmd = fill_manual_enum_command(
                template,
                username=username,
                domain=domain,
                cred_value=cred_value,
                target_subnet=target_subnet,
                dc_ip=dc_ip,
            )
            console_lines.append(f"    {c.BOLD}{cmd_def.name:<18}{c.RESET} {c.GREEN}{cmd}{c.RESET}")
            markdown_lines.append(f"| {cmd_def.name} | `{cmd}` |")

    console_lines.append("")
    markdown_lines.append("")

    # Medium priority (optional)
    if medium_priority:
        console_lines.append(f"  {c.DIM}Optional (medium priority):{c.RESET}")

        markdown_lines.append("**Optional (medium priority)**")
        markdown_lines.append("")
        markdown_lines.append("| Test | Command |")
        markdown_lines.append("|------|---------|")

        for cmd_def in medium_priority:
            template = cmd_def.templates.get(cred_type)
            if template:
                cmd = fill_manual_enum_command(
                    template,
                    username=username,
                    domain=domain,
                    cred_value=cred_value,
                    target_subnet=target_subnet,
                    dc_ip=dc_ip,
                )
                console_lines.append(f"    {c.DIM}{cmd_def.name:<18}{c.RESET} {c.GREEN}{cmd}{c.RESET}")
                markdown_lines.append(f"| {cmd_def.name} | `{cmd}` |")

        console_lines.append("")
        markdown_lines.append("")

    # Tip
    console_lines.append(f"  {c.YELLOW}Tip:{c.RESET} Look for {c.GREEN}(Pwn3d!){c.RESET} in output - that means admin access BloodHound missed!")
    console_lines.append("")

    markdown_lines.append("> **Tip:** Look for `(Pwn3d!)` in output - that means admin access BloodHound missed!")
    markdown_lines.append("")

    return console_lines, markdown_lines


def print_manual_enumeration_suggestions(
    username: str,
    domain: str,
    cred_type: str,
    cred_value: str,
    spns: List[str] = None,
    dc_ip: str = None,
    use_colors: bool = True,
) -> None:
    """Print manual enumeration suggestions for users without BloodHound edges.

    Wrapper around generate_manual_enumeration_suggestions() that prints to stdout.

    Args:
        username: Username (without domain)
        domain: Domain name
        cred_type: Credential type (password, ntlm-hash, etc.)
        cred_value: Credential value (password or hash)
        spns: List of SPNs for this user (if any)
        dc_ip: Domain Controller IP for subnet derivation
        use_colors: Enable ANSI colors
    """
    console_lines, _ = generate_manual_enumeration_suggestions(
        username=username,
        domain=domain,
        cred_type=cred_type,
        cred_value=cred_value,
        spns=spns,
        dc_ip=dc_ip,
        use_colors=use_colors,
    )
    for line in console_lines:
        print(line)
