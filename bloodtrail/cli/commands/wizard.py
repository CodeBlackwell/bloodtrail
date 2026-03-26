"""
BloodTrail Wizard Commands

Handles wizard mode commands:
- --wizard: Launch guided wizard mode for new users
- --wizard-resume TARGET: Resume from saved checkpoint
- --wizard-target TARGET: Alternative to positional arg for wizard mode

Wizard mode provides a guided, step-by-step interface for:
1. Detecting AD services
2. Choosing enumeration mode (auto/guided/skip)
3. Running enumeration
4. Analyzing findings
5. Presenting recommendations one at a time
"""

from argparse import Namespace
from typing import Optional

from ..base import BaseCommandGroup


class WizardCommands(BaseCommandGroup):
    """Wizard mode command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add wizard mode arguments - arguments defined in cli/parser.py."""
        pass  # Arguments added via parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle wizard mode commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        # Check if wizard mode requested
        if getattr(args, 'wizard', False):
            return cls._handle_wizard(args)

        # Check if resume requested
        if getattr(args, 'wizard_resume', None):
            return cls._handle_wizard_resume(args)

        # Not a wizard command
        return -1

    @classmethod
    def _handle_wizard(cls, args: Namespace) -> int:
        """Handle --wizard command - launch fresh wizard session."""
        from ...wizard import WizardFlow

        # Ensure terminal is in a sane state for interactive input
        cls._sanitize_terminal()

        # Determine target from args
        target = cls._get_target(args)

        if not target:
            cls.print_error("No target specified for wizard mode")
            print("    Usage: crack bloodtrail --wizard <IP>")
            print("       or: crack bloodtrail --wizard --wizard-target <IP>")
            return 1

        # Create and run wizard flow
        try:
            flow = WizardFlow(target=str(target), resume=False)
            flow.run()
            return 0
        except Exception as e:
            cls.print_error(f"Wizard failed: {e}")
            raise

    @classmethod
    def _handle_wizard_resume(cls, args: Namespace) -> int:
        """Handle --wizard-resume command - resume from saved checkpoint."""
        from ...wizard import WizardFlow

        target = args.wizard_resume

        if not target:
            cls.print_error("Target required for --wizard-resume")
            print("    Usage: crack bloodtrail --wizard-resume <IP>")
            return 1

        # Create and run wizard flow with resume=True
        try:
            flow = WizardFlow(target=str(target), resume=True)
            flow.run()
            return 0
        except Exception as e:
            cls.print_error(f"Failed to resume wizard: {e}")
            raise

    @classmethod
    def _get_target(cls, args: Namespace) -> Optional[str]:
        """
        Extract target from args in priority order.

        Priority:
        1. --wizard-target (explicit wizard target)
        2. bh_data_dir (positional arg)

        Returns:
            Target IP/hostname or None if not found
        """
        # Check explicit wizard target first
        if getattr(args, 'wizard_target', None):
            return args.wizard_target

        # Fall back to positional (bh_data_dir)
        if getattr(args, 'bh_data_dir', None):
            return str(args.bh_data_dir)

        return None

    @classmethod
    def _sanitize_terminal(cls) -> None:
        """Ensure terminal is in canonical mode for interactive input.

        Fixes issues where terminal may be left in raw/non-canonical mode
        causing input() to malfunction (e.g., displaying ^M characters).
        """
        import sys
        import os

        # Only attempt if connected to a real terminal
        if not sys.stdin.isatty():
            return

        try:
            import termios
            import tty

            # Get current terminal attributes
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)

            # Ensure we're in canonical (cooked) mode with proper input processing
            # This resets ICANON, ECHO, and importantly ICRNL (CR to NL translation)
            new_settings = old_settings.copy()

            # Input flags: enable CR to NL translation
            new_settings[0] |= termios.ICRNL

            # Local flags: enable canonical mode and echo
            new_settings[3] |= (termios.ICANON | termios.ECHO)

            # Apply if different
            if new_settings != old_settings:
                termios.tcsetattr(fd, termios.TCSANOW, new_settings)

        except (ImportError, termios.error, OSError):
            # If termios not available or fails, try stty as fallback
            try:
                os.system('stty sane 2>/dev/null')
            except Exception:
                pass  # Best effort - continue anyway
