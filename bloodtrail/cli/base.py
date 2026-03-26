"""
BloodTrail CLI Base Classes

Provides base infrastructure for command handlers including:
- Neo4j connection management
- Common argument handling
- Display utilities
"""

from abc import ABC, abstractmethod
from argparse import Namespace
from typing import Optional, Callable, List, Dict, Any

from ..config import Neo4jConfig
from ..core.neo4j_connection import Neo4jConnection
from ..core.formatters import Colors


class BaseCommandGroup(ABC):
    """
    Base class for command group handlers.

    Each command group (query, pwned, config, etc.) should inherit from this
    and implement add_arguments() and handle().

    Example:
        class QueryCommands(BaseCommandGroup):
            @classmethod
            def add_arguments(cls, parser):
                group = parser.add_argument_group("Query Library")
                group.add_argument("--list-queries", action="store_true")
                # ... more arguments

            @classmethod
            def handle(cls, args):
                if args.list_queries:
                    return cls._handle_list_queries(args)
                return -1  # Not handled by this group
    """

    @classmethod
    @abstractmethod
    def add_arguments(cls, parser) -> None:
        """
        Add command arguments to the given parser.

        Args:
            parser: argparse.ArgumentParser instance
        """
        pass

    @classmethod
    @abstractmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle command execution based on parsed arguments.

        Args:
            args: Parsed command line arguments

        Returns:
            Exit code (0 for success, non-zero for error)
            -1 indicates this group doesn't handle the given arguments
        """
        pass

    @staticmethod
    def get_neo4j_config(args: Namespace) -> Neo4jConfig:
        """
        Create Neo4j config from command line arguments.

        Args:
            args: Parsed arguments with uri, user, password

        Returns:
            Neo4jConfig instance
        """
        import os
        return Neo4jConfig(
            uri=getattr(args, 'uri', 'bolt://localhost:7687'),
            user=getattr(args, 'user', 'neo4j'),
            password=getattr(args, 'neo4j_password', None) or os.environ.get('NEO4J_PASSWORD', '')
        )

    @staticmethod
    def require_neo4j(
        args: Namespace,
        silent: bool = False
    ) -> Optional[Neo4jConnection]:
        """
        Get connected Neo4j connection or print error.

        Args:
            args: Parsed arguments with Neo4j connection info
            silent: If True, don't print error messages

        Returns:
            Connected Neo4jConnection or None if connection failed
        """
        config = BaseCommandGroup.get_neo4j_config(args)
        conn = Neo4jConnection(config)

        if not conn.connect():
            if not silent:
                print(f"{Colors.RED}[!] Could not connect to Neo4j{Colors.RESET}")
                print(f"    URI: {config.uri}")
                print(f"    Ensure Neo4j is running: sudo neo4j start")
            return None

        return conn

    @staticmethod
    def print_header(title: str, width: int = 70) -> None:
        """Print a section header."""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*width}")
        print(f"  {title}")
        print(f"{'='*width}{Colors.RESET}\n")

    @staticmethod
    def print_subheader(title: str, width: int = 68) -> None:
        """Print a subsection header."""
        print(f"{Colors.BOLD}{Colors.CYAN}+{'-'*width}+")
        print(f"|  {title:<{width-2}} |")
        print(f"+{'-'*width}+{Colors.RESET}")

    @staticmethod
    def print_success(message: str) -> None:
        """Print a success message."""
        print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")

    @staticmethod
    def print_error(message: str) -> None:
        """Print an error message."""
        print(f"{Colors.RED}[!] {message}{Colors.RESET}")

    @staticmethod
    def print_warning(message: str) -> None:
        """Print a warning message."""
        print(f"{Colors.YELLOW}[*] {message}{Colors.RESET}")

    @staticmethod
    def print_info(message: str) -> None:
        """Print an info message."""
        print(f"{Colors.CYAN}[*] {message}{Colors.RESET}")


class CommandRegistry:
    """
    Registry for command group handlers.

    Allows registration and dispatch of command groups.
    """

    def __init__(self):
        self._groups: List[type] = []

    def register(self, group_class: type) -> None:
        """
        Register a command group class.

        Args:
            group_class: Class inheriting from BaseCommandGroup
        """
        if not issubclass(group_class, BaseCommandGroup):
            raise TypeError(f"{group_class} must inherit from BaseCommandGroup")
        self._groups.append(group_class)

    def add_all_arguments(self, parser) -> None:
        """
        Add arguments from all registered groups to parser.

        Args:
            parser: argparse.ArgumentParser instance
        """
        for group_class in self._groups:
            group_class.add_arguments(parser)

    def dispatch(self, args: Namespace) -> int:
        """
        Dispatch to the first handler that handles the arguments.

        Args:
            args: Parsed command line arguments

        Returns:
            Exit code from the handling group, or -1 if no group handled
        """
        # Handle --no-prism flag: disable persistence before any command runs
        if getattr(args, 'no_prism', False):
            try:
                from crack.tools.persistence.config import PersistenceConfig
                PersistenceConfig.disable()
            except ImportError:
                pass

        for group_class in self._groups:
            result = group_class.handle(args)
            if result != -1:
                return result
        return -1


# Global registry instance
registry = CommandRegistry()
