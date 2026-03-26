"""
bloodtrail.display - Display and output formatting for bloodtrail.

This package provides all display functions for bloodtrail output including:
- Table rendering and formatting
- Attack path visualization
- Credential display
- Password spray recommendations
- Post-exploitation commands
"""

# Base utilities (shared across modules)
from .base import (
    Colors,
    NoColors,
    truncate,
    extract_creds_from_pwned_users,
    fill_spray_template,
)

# Table rendering
from .tables import (
    deduplicate_command_tables,
    print_command_tables,
    print_command_tables_by_phase,
    print_domain_level_table,
    format_table_markdown,
    format_tables_markdown,
)

# Statistics
from .statistics import (
    get_table_stats,
    print_stats,
)

# Post-success suggestions
from .post_success import (
    print_post_success,
)

# Technique legend and comparison
from .techniques import (
    print_technique_legend,
    generate_technique_legend_console,
    generate_technique_legend_markdown,
)

# Pwned user display
from .pwned_display import (
    print_pwned_users_table,
    print_machines_ip_table,
    print_cred_harvest_targets,
)

# Authenticated attacks
from .authenticated import (
    generate_authenticated_attacks,
    print_authenticated_attacks_template,
    generate_authenticated_attacks_template_markdown,
)

# Post-exploitation commands
from .post_exploit import (
    print_post_exploit_commands,
    print_pwned_followup_commands,
)

# Manual enumeration (for users without BloodHound edges)
from .manual_enum import (
    generate_manual_enumeration_suggestions,
    print_manual_enumeration_suggestions,
)

# Attack paths (Neo4j integration)
from .attack_paths import (
    generate_pwned_attack_paths,
    generate_post_exploit_section,
)

# Password spray recommendations
from .spray import (
    print_spray_recommendations,
    generate_spray_section,
)

# BloodHound-based tailored spray
from .spray_tailored import (
    print_spray_tailored,
)


# Backward compatibility aliases
_NoColors = NoColors
_truncate = truncate

# Private function aliases for backward compatibility
_generate_authenticated_attacks = generate_authenticated_attacks


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
    # Manual enumeration
    "generate_manual_enumeration_suggestions",
    "print_manual_enumeration_suggestions",
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
