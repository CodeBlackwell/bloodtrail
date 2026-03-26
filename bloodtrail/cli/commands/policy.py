"""
BloodTrail Policy Commands

Handles password policy commands:
- --set-policy: Import password policy from 'net accounts' output
- --show-policy: Show stored password policy
- --clear-policy: Clear stored password policy
"""

import sys
import os
from argparse import Namespace

from ..base import BaseCommandGroup
from ...config import Neo4jConfig
from ...pwned_tracker import PwnedTracker


class PolicyCommands(BaseCommandGroup):
    """Password policy command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add policy arguments."""
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle policy commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        if getattr(args, 'set_policy', None) is not None:
            return cls._handle_set_policy(args)

        if getattr(args, 'show_policy', False):
            return cls._handle_show_policy(args)

        if getattr(args, 'clear_policy', False):
            return cls._handle_clear_policy(args)

        return -1

    @classmethod
    def _handle_set_policy(cls, args: Namespace) -> int:
        """Handle --set-policy command - import password policy."""
        from ...policy_parser import parse_net_accounts, format_policy_display

        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            # Get policy text from stdin, file, or interactive
            policy_text = ""

            if args.set_policy == "-":
                # Read from stdin
                cls.print_info("Reading 'net accounts' output from stdin (Ctrl+D when done):")
                policy_text = sys.stdin.read()
            elif args.set_policy and args.set_policy != "-":
                # Read from file if it exists
                if os.path.isfile(args.set_policy):
                    with open(args.set_policy, 'r') as f:
                        policy_text = f.read()
                    cls.print_info(f"Read policy from: {args.set_policy}")
                else:
                    # Treat as the text itself
                    policy_text = args.set_policy
            else:
                # Interactive input
                cls.print_info("Paste 'net accounts' output (empty line to finish):")
                print()
                lines = []
                while True:
                    try:
                        line = input()
                        if not line and lines:
                            break
                        lines.append(line)
                    except EOFError:
                        break
                policy_text = "\n".join(lines)

            if not policy_text.strip():
                cls.print_error("No policy text provided")
                return 1

            # Parse the policy
            policy = parse_net_accounts(policy_text)

            # Store in Neo4j
            result = tracker.set_password_policy(policy)

            if not result.success:
                cls.print_error(f"Failed to store policy: {result.error}")
                return 1

            # Show what was stored
            print()
            cls.print_success("Password policy stored successfully!")
            print()
            print(format_policy_display(policy))

            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_show_policy(cls, args: Namespace) -> int:
        """Handle --show-policy command - display stored password policy."""
        from ...policy_parser import format_policy_display

        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            policy = tracker.get_password_policy()

            if not policy:
                cls.print_warning("No password policy stored")
                print("    Import with: crack bloodtrail --set-policy")
                return 0

            print()
            print(format_policy_display(policy))
            print()

            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_clear_policy(cls, args: Namespace) -> int:
        """Handle --clear-policy command - clear stored password policy."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            result = tracker.clear_password_policy()

            if not result.success:
                cls.print_error(f"Failed to clear policy: {result.error}")
                return 1

            cls.print_success("Password policy cleared")
            return 0

        finally:
            tracker.close()
