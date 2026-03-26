"""
BloodTrail CLI Commands Package

Command group modules for the BloodTrail CLI.
Each module handles a logical group of related commands.

Command Groups:
- query: Query library commands (--list-queries, --run-query, etc.)
- pwned: Pwned user tracking (--pwn, --list-pwned, etc.)
- config: Domain configuration (--set-dc-ip, --show-config, etc.)
- policy: Password policy (--set-policy, --show-policy, etc.)
- spray: Password spraying (--spray, --auto-spray, etc.)
- creds: Credential pipeline (--creds, --use-potfile, etc.)
- wizard: Guided wizard mode (--wizard, --wizard-resume, etc.)
- enumerate: Live enumeration (IP address input)
- import_data: BloodHound data import (positional path argument)
- analyze: Attack vector detection and analysis (--detect, --analyze-svc, etc.)
"""

from .query import QueryCommands
from .pwned import PwnedCommands
from .config import ConfigCommands
from .policy import PolicyCommands
from .spray import SprayCommands
from .creds import CredsCommands
from .wizard import WizardCommands
from .enumerate import EnumerateCommands
from .import_data import ImportDataCommands
from .analyze import AnalyzeCommands
from ..parser import InputMode, detect_input_mode

# All command groups in order of priority for handling
COMMAND_GROUPS = [
    QueryCommands,
    PwnedCommands,
    ConfigCommands,
    PolicyCommands,
    SprayCommands,
    CredsCommands,
    AnalyzeCommands,  # New analysis commands
    WizardCommands,  # Wizard mode - BEFORE EnumerateCommands for priority
    EnumerateCommands,
    ImportDataCommands,
]

__all__ = [
    # Command groups
    "QueryCommands",
    "PwnedCommands",
    "ConfigCommands",
    "PolicyCommands",
    "SprayCommands",
    "CredsCommands",
    "AnalyzeCommands",
    "WizardCommands",
    "EnumerateCommands",
    "ImportDataCommands",
    # Utilities
    "InputMode",
    "detect_input_mode",
    # Collection
    "COMMAND_GROUPS",
]
