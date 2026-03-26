"""
Authenticated attack display for bloodtrail.

Shows attack templates that any authenticated domain user can run.
"""

from typing import List

from .base import Colors, NoColors, truncate


def generate_authenticated_attacks(
    username: str,
    domain: str,
    cred_type: str,
    cred_value: str,
    dc_ip: str = None,
    use_colors: bool = True
) -> tuple:
    """
    Generate authenticated user attack commands.

    These attacks work for ANY authenticated domain user,
    regardless of BloodHound edges.

    Args:
        username: Username (without domain)
        domain: Domain name
        cred_type: password, ntlm-hash, kerberos-ticket
        cred_value: The credential value
        dc_ip: DC IP/hostname (optional, inferred from domain if not provided)
        use_colors: Enable ANSI colors

    Returns:
        Tuple of (console_lines: List[str], markdown_lines: List[str])
    """
    from ..mappings.authenticated import (
        AUTHENTICATED_USER_TEMPLATES,
        AUTHENTICATED_ATTACKS,
    )
    from ..mappings.command_fill import fill_pwned_command
    from ..mappings.text_utils import infer_dc_hostname

    c = Colors if use_colors else NoColors

    # Get templates for this cred type
    templates = AUTHENTICATED_USER_TEMPLATES.get(cred_type, {})
    if not templates:
        return [], []

    dc = dc_ip or infer_dc_hostname(domain)

    console_lines = []
    markdown_lines = []

    # Section header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}AUTHENTICATED USER ATTACKS{c.RESET} (Any domain user can run these)")
    console_lines.append("")

    # Table header (DRY format matching other command tables)
    console_lines.append(f"  {'Attack':<25} {'Objective':<45} {'Ready Command'}")
    console_lines.append(f"  {'-'*25} {'-'*45} {'-'*60}")

    markdown_lines.append("#### Authenticated User Attacks")
    markdown_lines.append("| Attack | Objective | Command |")
    markdown_lines.append("|--------|-----------|---------|")

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if not template:
            continue

        # Fill the command template
        cmd = fill_pwned_command(template, username, domain, dc, cred_value, dc)

        # Priority indicator
        priority = attack.get("priority", "medium")
        priority_indicator = " ⚡" if priority == "high" else ""

        # Truncate for table display
        name_display = truncate(attack['name'] + priority_indicator, 23)
        objective_display = truncate(attack['objective'], 43)

        # Console: tabular row
        console_lines.append(
            f"  {c.BOLD}{name_display:<25}{c.RESET} "
            f"{c.YELLOW}{objective_display:<45}{c.RESET} "
            f"{c.GREEN}{cmd}{c.RESET}"
        )

        # Markdown
        markdown_lines.append(f"| {attack['name']}{priority_indicator} | {attack['objective']} | `{cmd}` |")

    console_lines.append("")
    markdown_lines.append("")

    return console_lines, markdown_lines


def print_authenticated_attacks_template(use_colors: bool = True, dc_ip: str = None) -> None:
    """
    Print authenticated user attacks in template form (once, at end of output).

    Shows placeholders instead of filled credentials since these attacks
    are generic and work for ANY authenticated domain user.

    Args:
        use_colors: Enable ANSI colors
        dc_ip: Domain Controller IP (replaces <DC_IP> placeholder if provided)
    """
    from ..mappings.authenticated import AUTHENTICATED_USER_TEMPLATES, AUTHENTICATED_ATTACKS

    c = Colors if use_colors else NoColors

    print(f"\n{c.CYAN}{c.BOLD}AUTHENTICATED USER ATTACKS{c.RESET} (Any domain user can run these)")
    print(f"{c.DIM}Replace placeholders with your credentials:{c.RESET}")
    print()

    # Show password templates (most common)
    templates = AUTHENTICATED_USER_TEMPLATES.get("password", {})

    print(f"  {'Attack':<25} {'Command Template'}")
    print(f"  {'-'*25} {'-'*80}")

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if template:
            # Replace DC_IP if stored
            if dc_ip:
                template = template.replace("<DC_IP>", dc_ip)
            priority = " ⚡" if attack.get("priority") == "high" else ""
            name_display = f"{attack['name']}{priority}"
            print(f"  {c.BOLD}{name_display:<25}{c.RESET} {c.GREEN}{template}{c.RESET}")

    print()


def generate_authenticated_attacks_template_markdown() -> str:
    """Generate markdown version of authenticated attacks template."""
    from ..mappings.authenticated import AUTHENTICATED_USER_TEMPLATES, AUTHENTICATED_ATTACKS

    lines = []
    lines.append("#### Authenticated User Attacks (Any Domain User)")
    lines.append("")
    lines.append("Replace placeholders with your credentials:")
    lines.append("")
    lines.append("| Attack | Command Template |")
    lines.append("|--------|------------------|")

    templates = AUTHENTICATED_USER_TEMPLATES.get("password", {})

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if template:
            priority = " ⚡" if attack.get("priority") == "high" else ""
            lines.append(f"| {attack['name']}{priority} | `{template}` |")

    lines.append("")
    return "\n".join(lines)


# Backward compatibility alias
_generate_authenticated_attacks = generate_authenticated_attacks
