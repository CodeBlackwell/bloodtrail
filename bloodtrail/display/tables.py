"""
Table rendering and formatting for bloodtrail display.

Handles command table rendering, deduplication, and markdown conversion.
"""

from typing import List, Dict

from .base import Colors, NoColors, truncate
from ..command_suggester import CommandTable, TargetEntry, AttackSequence
from ..mappings.access_types import ACCESS_TYPE_PHASES


def deduplicate_command_tables(tables: List[CommandTable]) -> List[CommandTable]:
    """
    Merge command tables with the same command_id, deduplicating targets.

    Multiple queries can produce the same command (e.g., "impacket-psexec")
    with overlapping targets. This function merges them into a single table.

    Args:
        tables: List of CommandTable objects (may have duplicates)

    Returns:
        List of deduplicated CommandTable objects with merged targets
    """
    if not tables:
        return []

    # Group tables by command_id (the true unique identifier)
    merged: Dict[str, CommandTable] = {}

    for table in tables:
        key = table.command_id

        if key not in merged:
            # First occurrence - make a copy to avoid mutating original
            merged[key] = CommandTable(
                command_id=table.command_id,
                name=table.name,
                template=table.template,
                access_type=table.access_type,
                targets=list(table.targets),  # Copy targets list
                variables_needed=list(table.variables_needed),
                context=table.context,
                domain_level=table.domain_level,
                example=table.example,
                objective=table.objective,
                rewards=table.rewards,
                post_success=list(table.post_success),
                permissions_required=table.permissions_required,
                is_discovery=table.is_discovery,
                is_coercion=table.is_coercion,
            )
        else:
            # Merge targets into existing table
            existing = merged[key]
            seen_targets = {(t.user, t.target) for t in existing.targets}

            for target in table.targets:
                target_key = (target.user, target.target)
                if target_key not in seen_targets:
                    existing.targets.append(target)
                    seen_targets.add(target_key)

            # Keep the access_type that's most specific (non-empty wins)
            if table.access_type and not existing.access_type:
                existing.access_type = table.access_type

    return list(merged.values())


def print_command_tables(
    tables: List[CommandTable],
    use_colors: bool = True,
    max_targets: int = 20
) -> None:
    """
    Print DRY tabular output for command tables.

    Each command shows:
    - Name + access type badge
    - Template (shown ONCE)
    - Variables needed (if any)
    - Table of targets with ready-to-run commands

    Args:
        tables: List of CommandTable objects
        use_colors: Enable ANSI colors
        max_targets: Maximum targets to show per table
    """
    c = Colors if use_colors else NoColors

    for table in tables:
        if not table.targets:
            continue

        # Access type badge
        badge = f"[{table.access_type}]" if table.access_type else ""

        # Header: Command name + badge
        print(f"\n{c.BOLD}{table.name}{c.RESET} {c.CYAN}{badge}{c.RESET}")

        # Objective (what the command achieves)
        if table.objective:
            print(f"Objective: {table.objective}")

        # Rewards (practical application)
        if table.rewards:
            print(f"Rewards:   {c.YELLOW}{table.rewards}{c.RESET}")

        # Template (shown ONCE)
        print(f"{c.DIM}Template:  {table.template}{c.RESET}")

        # Example (if available and different from template)
        if table.example and table.example != table.template:
            print(f"{c.GREEN}Example:   {table.example}{c.RESET}")

        # Variables needed
        if table.variables_needed:
            print(f"{c.YELLOW}Need: {', '.join(table.variables_needed)}{c.RESET}")

        # Permissions required (new field)
        if table.permissions_required:
            print(f"{c.CYAN}Requires: {table.permissions_required}{c.RESET}")

        # Table header - adjust columns based on command type
        if table.is_discovery:
            # Discovery commands find targets, attacker provides their own creds
            print(f"\n  {'Discovered':<25} {'Domain':<20} {'Info':<40} {'Ready Command'}")
        elif table.is_coercion:
            # Coercion commands: listener is unconstrained host, target is what we coerce
            print(f"\n  {'Listener (Unconstrained)':<25} {'Coerce Target':<20} {'Reason':<40} {'Ready Command'}")
        else:
            print(f"\n  {'User':<25} {'Target':<20} {'Reason':<40} {'Ready Command'}")
        print(f"  {'-'*25} {'-'*20} {'-'*40} {'-'*50}")

        # Target rows
        displayed = 0
        for entry in table.targets[:max_targets]:
            user_short = truncate(entry.user, 23)
            target_short = truncate(entry.target, 18)

            # Build reason with warnings prefix
            warning_str = " ".join(entry.warnings) if entry.warnings else ""
            if warning_str:
                reason_display = f"{c.RED}{warning_str}{c.RESET} {entry.reason}"
                reason_short = truncate(f"{warning_str} {entry.reason}", 38)
            else:
                reason_display = entry.reason
                reason_short = truncate(entry.reason, 38) if entry.reason else ""

            # Color reason yellow, but warnings are red (handled above)
            if warning_str:
                print(f"  {user_short:<25} {target_short:<20} {c.RED}{truncate(warning_str, 15):<16}{c.RESET}{c.YELLOW}{truncate(entry.reason, 22):<24}{c.RESET} {c.GREEN}{entry.ready_command}{c.RESET}")
            else:
                print(f"  {user_short:<25} {target_short:<20} {c.YELLOW}{reason_short:<40}{c.RESET} {c.GREEN}{entry.ready_command}{c.RESET}")
            displayed += 1

        # Show truncation notice
        if len(table.targets) > max_targets:
            remaining = len(table.targets) - max_targets
            print(f"  {c.DIM}... and {remaining} more targets{c.RESET}")

        print()  # Spacing between tables


def print_command_tables_by_phase(
    tables: List[CommandTable],
    use_colors: bool = True
) -> None:
    """
    Print command tables grouped by attack phase, sorted by impact priority.

    Phases (in order):
    - Quick Wins (Kerberoast, AS-REP, etc.)
    - Lateral Movement (AdminTo > DCOM > PSRemote > RDP)
    - Privilege Escalation (DCSync > GenericAll > WriteDacl > ...)

    Within each phase, commands are sorted by ACCESS_TYPE_PRIORITY (highest first).
    Duplicate tables (same name+access_type) are merged before display.
    """
    c = Colors if use_colors else NoColors

    # Deduplicate tables: merge tables with same name+access_type
    tables = deduplicate_command_tables(tables)

    # Define phase order (most actionable first)
    PHASE_ORDER = ["Quick Wins", "Lateral Movement", "Privilege Escalation", "Other"]

    # Group by phase
    phases: Dict[str, List[CommandTable]] = {phase: [] for phase in PHASE_ORDER}

    for table in tables:
        if not table.targets:
            continue
        phase = table.phase
        if phase not in phases:
            phase = "Other"
        phases[phase].append(table)

    # Print each phase in defined order
    for phase_name in PHASE_ORDER:
        phase_tables = phases[phase_name]
        if not phase_tables:
            continue

        # Sort by priority within phase (highest impact first)
        phase_tables.sort(key=lambda t: t.priority_score, reverse=True)

        # Phase header with counts
        total_targets = sum(len(t.targets) for t in phase_tables)
        print(f"\n{c.BOLD}{c.CYAN}{'='*70}")
        print(f"  {phase_name.upper()} ({len(phase_tables)} techniques, {total_targets} targets)")
        print(f"{'='*70}{c.RESET}")

        print_command_tables(phase_tables, use_colors)


def print_domain_level_table(
    table: CommandTable,
    principals: List[str],
    use_colors: bool = True
) -> None:
    """
    Print domain-level command (DCSync, etc.) with both formats:
    1. Single ready command template
    2. Expandable list of principals with this right

    Args:
        table: CommandTable for domain-level command
        principals: List of principals with this right (not groups)
        use_colors: Enable ANSI colors
    """
    c = Colors if use_colors else NoColors

    print(f"\n{c.BOLD}{table.name}{c.RESET} {c.CYAN}[{table.access_type}]{c.RESET}")

    # Objective (what the command achieves)
    if table.objective:
        print(f"Objective: {table.objective}")

    # Rewards (practical application)
    if table.rewards:
        print(f"Rewards:   {c.YELLOW}{table.rewards}{c.RESET}")

    print(f"{c.DIM}Template:  {table.template}{c.RESET}")

    # Example (if available and different from template)
    if table.example and table.example != table.template:
        print(f"{c.GREEN}Example:   {table.example}{c.RESET}")

    if table.variables_needed:
        print(f"{c.YELLOW}Need: {', '.join(table.variables_needed)}{c.RESET}")

    print(f"{c.DIM}Access: Domain-level{c.RESET}")

    # Single ready command (example)
    if table.targets:
        print(f"\n  {c.GREEN}Ready: {table.targets[0].ready_command}{c.RESET}")

    # Principals with this right
    if principals:
        print(f"\n  Principals with DCSync rights:")
        print(f"  {c.DIM}{'+'*40}{c.RESET}")
        for p in principals[:10]:
            print(f"  {c.DIM}|{c.RESET} {p}")
        if len(principals) > 10:
            print(f"  {c.DIM}| ... and {len(principals) - 10} more{c.RESET}")
        print(f"  {c.DIM}{'+'*40}{c.RESET}")

    print()


def format_table_markdown(table: CommandTable) -> str:
    """
    Format CommandTable as markdown for report output.

    Returns:
        Markdown string
    """
    lines = []

    badge = f"[{table.access_type}]" if table.access_type else ""
    lines.append(f"### {table.name} {badge}")
    lines.append("")

    if table.objective:
        lines.append(f"**Objective:** {table.objective}")

    if table.rewards:
        lines.append(f"**Rewards:** {table.rewards}")

    lines.append(f"**Template:** `{table.template}`")

    if table.example and table.example != table.template:
        lines.append(f"**Example:** `{table.example}`")

    if table.variables_needed:
        lines.append(f"**Need:** {', '.join(table.variables_needed)}")

    if table.permissions_required:
        lines.append(f"**Requires:** {table.permissions_required}")

    lines.append("")
    # Adjust column headers for discovery commands
    if table.is_discovery:
        lines.append("| Discovered | Domain | Warnings | Info | Ready Command |")
    else:
        lines.append("| User | Target | Warnings | Reason | Ready Command |")
    lines.append("|------|--------|----------|--------|---------------|")

    for entry in table.targets[:20]:
        user_safe = entry.user.replace("|", "\\|")
        target_safe = entry.target.replace("|", "\\|")
        warnings_safe = " ".join(entry.warnings).replace("|", "\\|") if entry.warnings else ""
        reason_safe = (entry.reason or "").replace("|", "\\|")
        cmd_safe = entry.ready_command.replace("|", "\\|")
        lines.append(f"| {user_safe} | {target_safe} | {warnings_safe} | {reason_safe} | `{cmd_safe}` |")

    if len(table.targets) > 20:
        lines.append(f"| ... | ... | ... | ... | *{len(table.targets) - 20} more* |")

    lines.append("")
    return "\n".join(lines)


def format_tables_markdown(tables: List[CommandTable]) -> str:
    """Format all command tables as markdown grouped by phase"""
    lines = ["## Attack Commands", ""]

    # Group by phase
    phases = {"Quick Wins": [], "Lateral Movement": [], "Privilege Escalation": [], "Other": []}
    for table in tables:
        if table.targets:
            phase = table.phase if table.phase in phases else "Other"
            phases[phase].append(table)

    for phase_name, phase_tables in phases.items():
        if not phase_tables:
            continue
        lines.append(f"### {phase_name}")
        lines.append("")
        for table in phase_tables:
            lines.append(format_table_markdown(table))

    return "\n".join(lines)
