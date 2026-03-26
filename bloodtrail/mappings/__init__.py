"""
Bloodtrail mappings package.

Modular organization of command mappings, access types, techniques, and attack templates.
Re-exports all public symbols for backward compatibility with existing imports.
"""

# Dataclasses
from .base import (
    TechniqueInfo,
    AccessTypeInfo,
    SprayTechniqueInfo,
)

# Text utilities
from .text_utils import (
    extract_domain,
    extract_username,
    infer_dc_hostname,
    is_group_name,
    GROUP_NAME_PATTERNS,
    SENSITIVE_PLACEHOLDERS,
)

# Query loader
from .query_loader import (
    _load_query_mappings,
    QUERY_COMMAND_MAPPINGS,
)

# Command filling
from .command_fill import (
    fill_command,
    fill_pwned_command,
)

# Access types and metadata
from .access_types import (
    ACCESS_TYPE_CATALOG,
    ACCESS_TYPE_REWARDS,
    ACCESS_TYPE_PHASES,
    ACCESS_TYPE_PRIORITY,
    ACCESS_TYPE_REASONS,
    get_reason,
)

# Lateral movement techniques
from .lateral import (
    LATERAL_TECHNIQUES,
    CREDENTIAL_CONVERSION,
    TICKET_ATTACKS,
    get_techniques_for_access,
    get_technique_command,
    needs_overpass_the_hash,
)

# Edge and credential type mappings
from .edge_mappings import (
    CRED_TYPE_COMMANDS,
    CRED_TYPE_TEMPLATES,
    EDGE_COMMAND_MAPPINGS,
    get_commands_for_cred_type,
    get_command_template,
)

# Authenticated user attacks
from .authenticated import (
    AUTHENTICATED_USER_TEMPLATES,
    AUTHENTICATED_ATTACKS,
    get_authenticated_attack_template,
    get_authenticated_attacks,
)

# Post-exploitation
from .post_exploit import (
    POST_EXPLOITATION_COMMANDS,
    HARVEST_TIPS,
    PTT_WORKFLOW,
    DCOM_WORKFLOW,
    ARG_ACQUISITION,
    get_post_exploit_commands,
    get_harvest_tips,
    get_arg_acquisition,
)

# Manual enumeration (for users without BloodHound edges)
from .manual_enum import (
    MANUAL_ENUM_COMMANDS,
    ManualEnumCommand,
    fill_manual_enum_command,
    extract_machine_from_spn,
    derive_subnet_from_ip,
)

# Spray techniques
from .spray import (
    SPRAY_TECHNIQUES,
    ALL_TARGETS_PROTOCOLS,
    ALL_TARGETS_IP_THRESHOLD,
    SPRAY_SCENARIOS,
    USER_ENUM_COMMANDS,
    PASSWORD_LIST_COMMANDS,
    PASSWORD_LIST_SCENARIOS,
    SPRAY_ONELINERS,
    get_spray_technique,
    get_all_spray_techniques,
    get_spray_scenarios,
    get_user_enum_commands,
    get_password_list_commands,
    get_password_list_scenarios,
    get_spray_oneliners,
)

__all__ = [
    # Dataclasses
    "TechniqueInfo",
    "AccessTypeInfo",
    "SprayTechniqueInfo",
    # Text utilities
    "extract_domain",
    "extract_username",
    "infer_dc_hostname",
    "is_group_name",
    "GROUP_NAME_PATTERNS",
    "SENSITIVE_PLACEHOLDERS",
    # Query loader
    "_load_query_mappings",
    "QUERY_COMMAND_MAPPINGS",
    # Command filling
    "fill_command",
    "fill_pwned_command",
    # Access types
    "ACCESS_TYPE_CATALOG",
    "ACCESS_TYPE_REWARDS",
    "ACCESS_TYPE_PHASES",
    "ACCESS_TYPE_PRIORITY",
    "ACCESS_TYPE_REASONS",
    "get_reason",
    # Lateral movement
    "LATERAL_TECHNIQUES",
    "CREDENTIAL_CONVERSION",
    "TICKET_ATTACKS",
    "get_techniques_for_access",
    "get_technique_command",
    "needs_overpass_the_hash",
    # Edge mappings
    "CRED_TYPE_COMMANDS",
    "CRED_TYPE_TEMPLATES",
    "EDGE_COMMAND_MAPPINGS",
    "get_commands_for_cred_type",
    "get_command_template",
    # Authenticated attacks
    "AUTHENTICATED_USER_TEMPLATES",
    "AUTHENTICATED_ATTACKS",
    "get_authenticated_attack_template",
    "get_authenticated_attacks",
    # Post-exploitation
    "POST_EXPLOITATION_COMMANDS",
    "HARVEST_TIPS",
    "PTT_WORKFLOW",
    "DCOM_WORKFLOW",
    "ARG_ACQUISITION",
    "get_post_exploit_commands",
    "get_harvest_tips",
    "get_arg_acquisition",
    # Manual enumeration
    "MANUAL_ENUM_COMMANDS",
    "ManualEnumCommand",
    "fill_manual_enum_command",
    "extract_machine_from_spn",
    "derive_subnet_from_ip",
    # Spray
    "SPRAY_TECHNIQUES",
    "ALL_TARGETS_PROTOCOLS",
    "ALL_TARGETS_IP_THRESHOLD",
    "SPRAY_SCENARIOS",
    "USER_ENUM_COMMANDS",
    "PASSWORD_LIST_COMMANDS",
    "PASSWORD_LIST_SCENARIOS",
    "SPRAY_ONELINERS",
    "get_spray_technique",
    "get_all_spray_techniques",
    "get_spray_scenarios",
    "get_user_enum_commands",
    "get_password_list_commands",
    "get_password_list_scenarios",
    "get_spray_oneliners",
]
