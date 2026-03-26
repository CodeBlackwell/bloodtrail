"""
Display utilities for BloodTrail Interactive Mode.

Formats findings and recommendations for terminal output.
"""

from typing import Optional

from ..recommendation.models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
)

# ANSI color codes
R = "\033[91m"   # Red
G = "\033[92m"   # Green
Y = "\033[93m"   # Yellow
B = "\033[94m"   # Blue
M = "\033[95m"   # Magenta
C = "\033[96m"   # Cyan
W = "\033[97m"   # White
D = "\033[90m"   # Dim
BOLD = "\033[1m"
X = "\033[0m"    # Reset

# Box drawing characters
BOX_TL = "┌"
BOX_TR = "┐"
BOX_BL = "└"
BOX_BR = "┘"
BOX_H = "─"
BOX_V = "│"


def box(title: str, content: str, width: int = 74, color: str = C) -> str:
    """Create a box around content."""
    lines = content.split('\n')
    inner_width = width - 4  # Account for borders and padding

    result = []
    result.append(f"{color}{BOX_TL}{BOX_H} {title} {BOX_H * (width - len(title) - 5)}{BOX_TR}{X}")

    for line in lines:
        # Truncate or pad line to fit
        display_line = line[:inner_width].ljust(inner_width)
        result.append(f"{color}{BOX_V}{X} {display_line} {color}{BOX_V}{X}")

    result.append(f"{color}{BOX_BL}{BOX_H * (width - 2)}{BOX_BR}{X}")

    return '\n'.join(result)


def display_finding(finding: Finding, show_details: bool = True) -> str:
    """
    Format a finding for display.

    Returns formatted string for terminal output.
    """
    lines = []

    # Header with icon based on type
    type_icons = {
        FindingType.LDAP_ATTRIBUTE: "🔑",
        FindingType.FILE: "📄",
        FindingType.GROUP_MEMBERSHIP: "👥",
        FindingType.CREDENTIAL: "🔐",
        FindingType.USER_FLAG: "🚩",
        FindingType.SERVICE: "🔌",
        FindingType.SHARE: "📁",
        FindingType.POLICY: "📋",
    }
    icon = type_icons.get(finding.finding_type, "⚡")

    lines.append(f"\n{'═' * 76}")
    lines.append(f" {icon} {Y}FINDING:{X} {finding.finding_type.name.replace('_', ' ').title()}")
    lines.append(f"{'═' * 76}\n")

    # Main content based on type
    if finding.finding_type == FindingType.LDAP_ATTRIBUTE:
        username = finding.metadata.get("username", "unknown")
        attr_name = finding.target
        lines.append(f"  {D}User:{X}        {B}{username}{X}")
        lines.append(f"  {D}Attribute:{X}   {C}{attr_name}{X}")
        lines.append(f"  {D}Raw Value:{X}   {W}{finding.raw_value}{X}")

        if finding.decoded_value:
            lines.append(f"  {D}Decoded:{X}     {G}{finding.decoded_value}{X} {D}({finding.decode_method}){X}")
            if "likely_password" in finding.tags:
                lines.append(f"\n  {Y}⚠ This appears to be a password stored in a custom LDAP attribute{X}")

    elif finding.finding_type == FindingType.FILE:
        lines.append(f"  {D}Path:{X}        {C}{finding.target}{X}")
        if finding.metadata.get("encrypted_hex"):
            lines.append(f"  {D}Extracted:{X}   {W}{finding.metadata['encrypted_hex']}{X}")
        if finding.decoded_value:
            lines.append(f"  {D}Decrypted:{X}  {G}{finding.decoded_value}{X}")

    elif finding.finding_type == FindingType.GROUP_MEMBERSHIP:
        username = finding.metadata.get("username", "unknown")
        lines.append(f"  {D}User:{X}        {B}{username}{X}")
        lines.append(f"  {D}Group:{X}       {C}{finding.target}{X}")
        if "privileged_group" in finding.tags:
            lines.append(f"\n  {R}⚠ This is a privileged group with special access{X}")

    elif finding.finding_type == FindingType.USER_FLAG:
        username = finding.target
        flag = finding.raw_value
        lines.append(f"  {D}User:{X}        {B}{username}{X}")
        lines.append(f"  {D}Flag:{X}        {R}{flag}{X}")

    elif finding.finding_type == FindingType.CREDENTIAL:
        username = finding.metadata.get("username", finding.target)
        lines.append(f"  {D}User:{X}        {B}{username}{X}")
        if "validated" in finding.tags:
            access = finding.metadata.get("access_level", "user")
            lines.append(f"  {D}Status:{X}      {G}✓ VALIDATED{X}")
            lines.append(f"  {D}Access:{X}      {access}")
        else:
            lines.append(f"  {D}Status:{X}      {Y}Not yet tested{X}")

    # Show tags if present
    if show_details and finding.tags:
        tag_str = ' '.join([f"{D}[{t}]{X}" for t in finding.tags])
        lines.append(f"\n  {D}Tags:{X} {tag_str}")

    return '\n'.join(lines)


def display_recommendation(
    rec: Recommendation,
    show_why: bool = True,
    show_options: bool = True,
) -> str:
    """
    Format a recommendation for display.

    Returns formatted string for terminal output.
    """
    # Priority colors
    priority_colors = {
        RecommendationPriority.CRITICAL: R,
        RecommendationPriority.HIGH: Y,
        RecommendationPriority.MEDIUM: C,
        RecommendationPriority.LOW: D,
        RecommendationPriority.INFO: D,
    }
    color = priority_colors.get(rec.priority, C)

    content_lines = []

    # Description
    content_lines.append(f"{BOLD}{rec.description}{X}")
    content_lines.append("")

    # Command if present
    if rec.command:
        content_lines.append(f"  {D}${X} {G}{rec.command}{X}")
        content_lines.append("")

    # WHY explanation
    if show_why and rec.why:
        content_lines.append(f"  {D}Why:{X} {rec.why}")
        content_lines.append("")

    # Options
    if show_options:
        content_lines.append(f"  {D}[{W}R{D}]un  [{W}S{D}]kip  [{W}?{D}]Help{X}")

    content = '\n'.join(content_lines)

    return box(
        f"RECOMMENDED ACTION ({rec.priority.name})",
        content,
        color=color,
    )


def display_credential_validated(
    username: str,
    password: str,
    access_level: str,
    winrm: bool = False,
) -> str:
    """Display credential validation success."""
    lines = []
    lines.append(f"\n{'═' * 76}")
    lines.append(f" {G}✓ CREDENTIAL VALIDATED:{X} {B}{username}{X}:{password}")
    lines.append(f"{'═' * 76}\n")
    lines.append(f"  {D}Access Level:{X}  {access_level.title()}")
    lines.append(f"  {D}WinRM:{X}         {'✓ Yes' if winrm else '✗ No'}")

    return '\n'.join(lines)


def display_stats(stats: dict) -> str:
    """Display engine statistics."""
    lines = []
    lines.append(f"\n{D}{'─' * 40}{X}")
    lines.append(f"  {D}Target:{X}        {stats.get('target', 'unknown')}")
    lines.append(f"  {D}Domain:{X}        {stats.get('domain', 'unknown')}")
    lines.append(f"  {D}Access:{X}        {stats.get('access_level', 'anonymous')}")
    if stats.get('current_user'):
        lines.append(f"  {D}User:{X}          {stats['current_user']}")
    lines.append(f"  {D}Findings:{X}      {stats.get('findings', 0)}")
    lines.append(f"  {D}Credentials:{X}   {stats.get('validated_credentials', 0)}")
    lines.append(f"  {D}Pending:{X}       {stats.get('pending_recommendations', 0)}")
    lines.append(f"  {D}Completed:{X}     {stats.get('completed_actions', 0)}")
    lines.append(f"{D}{'─' * 40}{X}")

    return '\n'.join(lines)


def prompt_user(message: str, options: str = "ynq") -> str:
    """
    Prompt user for input.

    Args:
        message: The prompt message
        options: Valid single-char options (default: y/n/q)

    Returns:
        Single character response (lowercase)
    """
    while True:
        try:
            response = input(f"\n{message} [{'/'.join(options)}]: ").strip().strip('\r\n').lower()
            if response and response[0] in options.lower():
                return response[0]
            # Empty input (Enter) defaults to first option
            if not response:
                return options[0].lower()
            print(f"{Y}Please enter one of: {'/'.join(options)}{X}")
        except (EOFError, KeyboardInterrupt):
            return 'q'
