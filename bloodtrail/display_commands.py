"""
Blood-trail DRY Command Display - Backward Compatibility Wrapper

This module re-exports all functions from the modularized display package.
All display functionality has been moved to bloodtrail/display/ subpackage.

For new code, import directly from bloodtrail.display:
    from bloodtrail.display import print_command_tables, Colors

This wrapper ensures existing imports continue to work.
"""

# Re-export everything from the display package
from .display import (
    # Base utilities
    Colors,
    NoColors,
    truncate,
    extract_creds_from_pwned_users,
    fill_spray_template,
    # Tables
    deduplicate_command_tables,
    print_command_tables,
    print_command_tables_by_phase,
    print_domain_level_table,
    format_table_markdown,
    format_tables_markdown,
    # Statistics
    get_table_stats,
    print_stats,
    # Post-success
    print_post_success,
    # Techniques
    print_technique_legend,
    generate_technique_legend_console,
    generate_technique_legend_markdown,
    # Pwned display
    print_pwned_users_table,
    print_machines_ip_table,
    print_cred_harvest_targets,
    # Authenticated
    generate_authenticated_attacks,
    print_authenticated_attacks_template,
    generate_authenticated_attacks_template_markdown,
    # Post-exploit
    print_post_exploit_commands,
    print_pwned_followup_commands,
    # Attack paths
    generate_pwned_attack_paths,
    generate_post_exploit_section,
    # Spray
    print_spray_recommendations,
    generate_spray_section,
    # Spray tailored
    print_spray_tailored,
    # Backward compatibility aliases
    _NoColors,
    _truncate,
    _generate_authenticated_attacks,
)

__all__ = [
    # Base
    "Colors",
    "NoColors",
    "truncate",
    "extract_creds_from_pwned_users",
    "fill_spray_template",
    # Tables
    "deduplicate_command_tables",
    "print_command_tables",
    "print_command_tables_by_phase",
    "print_domain_level_table",
    "format_table_markdown",
    "format_tables_markdown",
    # Statistics
    "get_table_stats",
    "print_stats",
    # Post-success
    "print_post_success",
    # Techniques
    "print_technique_legend",
    "generate_technique_legend_console",
    "generate_technique_legend_markdown",
    # Pwned display
    "print_pwned_users_table",
    "print_machines_ip_table",
    "print_cred_harvest_targets",
    # Authenticated
    "generate_authenticated_attacks",
    "print_authenticated_attacks_template",
    "generate_authenticated_attacks_template_markdown",
    # Post-exploit
    "print_post_exploit_commands",
    "print_pwned_followup_commands",
    # Attack paths
    "generate_pwned_attack_paths",
    "generate_post_exploit_section",
    # Spray
    "print_spray_recommendations",
    "generate_spray_section",
    # Spray tailored
    "print_spray_tailored",
    # Backward compatibility
    "_NoColors",
    "_truncate",
    "_generate_authenticated_attacks",
]
