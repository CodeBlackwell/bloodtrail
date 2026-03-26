"""
Statistics calculation and display for bloodtrail.

Provides summary statistics for command tables.
"""

from typing import List, Dict

from .base import Colors, NoColors


def get_table_stats(tables: List) -> Dict:
    """Get statistics about command tables"""
    total_commands = len(tables)
    total_targets = sum(len(t.targets) for t in tables)

    by_phase = {}
    for table in tables:
        phase = table.phase
        if phase not in by_phase:
            by_phase[phase] = {"commands": 0, "targets": 0}
        by_phase[phase]["commands"] += 1
        by_phase[phase]["targets"] += len(table.targets)

    return {
        "total_commands": total_commands,
        "total_targets": total_targets,
        "by_phase": by_phase,
    }


def print_stats(tables: List, use_colors: bool = True) -> None:
    """Print summary statistics"""
    c = Colors if use_colors else NoColors
    stats = get_table_stats(tables)

    print(f"{c.DIM}Commands: {stats['total_commands']} | Targets: {stats['total_targets']}{c.RESET}")

    for phase, data in stats["by_phase"].items():
        print(f"  {phase}: {data['commands']} commands, {data['targets']} targets")
