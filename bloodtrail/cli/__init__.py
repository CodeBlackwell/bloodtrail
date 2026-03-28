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


def _is_subcommand(arg: str) -> bool:
    """Check if first argument is a known subcommand."""
    from .app import SUBCOMMANDS
    return arg in SUBCOMMANDS


def _run_subcommand() -> int:
    """Route through new subcommand-based CLI."""
    from .app import create_subcommand_parser

    parser = create_subcommand_parser()

    # Enable shell completion if argcomplete is available
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    if getattr(args, 'debug', None) is not None:
        from ..logger import init_debug
        init_debug(args.debug)

    if getattr(args, 'quiet', False):
        args.verbose = 0

    handler = getattr(args, '_handler', None)
    if handler:
        return handler(args)

    parser.print_help()
    return 0


def _run_legacy() -> int:
    """Route through original flat-flag CLI (backward compat)."""
    parser = create_parser()
    args = parser.parse_args()

    if getattr(args, 'debug', None) is not None:
        from ..logger import init_debug
        init_debug(args.debug)

    if getattr(args, 'quiet', False):
        args.verbose = 0

    # Apply persistent config defaults to legacy args
    from ..settings import get_effective_config
    cfg = get_effective_config(args)
    if not getattr(args, 'uri', None) or args.uri == 'bolt://localhost:7687':
        args.uri = cfg['neo4j_uri']
    if not getattr(args, 'user', None) or args.user == 'neo4j':
        args.user = cfg['neo4j_user']
    if not getattr(args, 'neo4j_password', None):
        args.neo4j_password = cfg['neo4j_password']
    if not getattr(args, 'dc_ip', None) and cfg.get('dc_ip'):
        args.dc_ip = cfg['dc_ip']

    for group_class in COMMAND_GROUPS:
        result = group_class.handle(args)
        if result != -1:
            return result

    parser.print_help()
    return 0


def main() -> int:
    """
    Main CLI entry point.

    Uses subcommand routing if first arg is a known subcommand,
    otherwise falls back to legacy flat-flag parser for backward compat.
    """
    import sys

    argv = sys.argv[1:]

    # Subcommand routing: if first arg is a known subcommand, use new router
    if argv and not argv[0].startswith('-') and _is_subcommand(argv[0]):
        return _run_subcommand()

    # Legacy flat-flag routing
    return _run_legacy()
