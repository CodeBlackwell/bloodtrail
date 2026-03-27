"""
BloodTrail CLI Package

Modular command-line interface for BloodTrail.
Commands are organized into logical groups for maintainability.

This package provides:
- BaseCommandGroup: Abstract base class for command handlers
- Parser: Argument parser with all command flags
- Command groups for each functional area
- Interactive helpers for credential entry
"""

from .base import BaseCommandGroup, CommandRegistry
from .parser import create_parser
from .interactive import interactive_pwn, fetch_neo4j_list, select_from_list
from .commands import (
    COMMAND_GROUPS,
    QueryCommands,
    PwnedCommands,
    ConfigCommands,
    PolicyCommands,
    SprayCommands,
    CredsCommands,
    EnumerateCommands,
    ImportDataCommands,
    UICommands,
    InputMode,
    detect_input_mode,
)


__all__ = [
    # Entry point
    "main",
    # Base classes
    "BaseCommandGroup",
    "CommandRegistry",
    # Parser
    "create_parser",
    # Interactive helpers
    "interactive_pwn",
    "fetch_neo4j_list",
    "select_from_list",
    # Command groups
    "COMMAND_GROUPS",
    "QueryCommands",
    "PwnedCommands",
    "ConfigCommands",
    "PolicyCommands",
    "SprayCommands",
    "CredsCommands",
    "EnumerateCommands",
    "ImportDataCommands",
    "UICommands",
    # Utilities
    "InputMode",
    "detect_input_mode",
]


def main() -> int:
    """
    Main CLI entry point.

    Dispatches to appropriate command group based on arguments.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = create_parser()
    args = parser.parse_args()

    # Initialize debug logging if --debug flag is passed
    if getattr(args, 'debug', None) is not None:
        from ..logger import init_debug
        init_debug(args.debug)

    # Handle --quiet flag: override verbose to 0
    if getattr(args, 'quiet', False):
        args.verbose = 0

    # Dispatch to command groups in priority order
    # Each group's handle() returns -1 if it doesn't handle the command
    for group_class in COMMAND_GROUPS:
        result = group_class.handle(args)
        if result != -1:
            return result

    # No command group handled - show help
    parser.print_help()
    return 0
