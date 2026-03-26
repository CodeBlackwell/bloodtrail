"""
BloodTrail Pwned Commands

Handles pwned user tracking commands:
- --pwn: Mark a user as pwned
- --unpwn: Remove pwned status
- --list-pwned: List all pwned users
- --pwned-user: Show details for a specific pwned user
- --cred-targets: Show credential harvest targets
- --post-exploit: Show post-exploitation commands
- --pwn-interactive: Interactive pwn mode
- --recommend: Recommend attack paths
- --list-ip-addresses: List machines with IPs
"""

import os
from argparse import Namespace
from typing import Optional

from ..base import BaseCommandGroup
from ..interactive import interactive_pwn
from ...config import Neo4jConfig, LHOST as CONFIG_LHOST, LPORT as CONFIG_LPORT
from ...pwned_tracker import PwnedTracker
from ...display import (
    print_pwned_users_table,
    print_machines_ip_table,
    print_cred_harvest_targets,
    print_pwned_followup_commands,
    print_post_exploit_commands,
)


class PwnedCommands(BaseCommandGroup):
    """Pwned user tracking command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add pwned tracking arguments."""
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle pwned tracking commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        if getattr(args, 'pwn_interactive', False):
            return cls._handle_pwn_interactive(args)

        if getattr(args, 'pwn', None):
            return cls._handle_pwn(args)

        if getattr(args, 'unpwn', None):
            return cls._handle_unpwn(args)

        if getattr(args, 'list_pwned', False):
            return cls._handle_list_pwned(args)

        if getattr(args, 'pwned_user', None):
            return cls._handle_pwned_user(args)

        if getattr(args, 'cred_targets', False):
            return cls._handle_cred_targets(args)

        if getattr(args, 'post_exploit', False):
            return cls._handle_post_exploit(args)

        if getattr(args, 'recommend', False):
            return cls._handle_recommend(args)

        if getattr(args, 'list_ip_addresses', False):
            return cls._handle_list_ip_addresses(args)

        return -1

    @classmethod
    def _handle_pwn_interactive(cls, args: Namespace) -> int:
        """Handle --pwn-interactive command - interactive credential entry."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        prefill_user = None

        while True:
            creds = interactive_pwn(config, prefill_user=prefill_user)
            if not creds:
                return 0  # User cancelled

            # Populate args and mark user as pwned
            args.pwn = creds["user"]
            args.cred_type = creds["cred_type"]
            args.cred_value = creds["cred_value"]
            args.source_machine = creds["source_machine"]
            args.pwn_notes = creds["notes"]
            cls._handle_pwn(args)

            # Ask to continue
            print("\nAdd another credential?")
            print("  [Enter] Done")
            print("  [1] Same user (different cred)")
            print("  [2] Different user")
            choice = input("Choice [Enter]: ").strip()

            if choice == "1":
                prefill_user = creds["user"]  # Pre-fill same user
            elif choice == "2":
                prefill_user = None  # Fresh selection
            else:
                break  # Done

        return 0

    @classmethod
    def _handle_pwn(cls, args: Namespace) -> int:
        """Handle --pwn command - mark user as pwned."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            result = tracker.mark_pwned(
                user=args.pwn,
                cred_type=getattr(args, 'cred_type', None),
                cred_value=getattr(args, 'cred_value', None),
                source_machine=getattr(args, 'source_machine', None),
                notes=getattr(args, 'pwn_notes', None),
            )

            if not result.success:
                cls.print_error(f"Failed to mark {args.pwn} as pwned: {result.error}")
                return 1

            # Get domain config for DC IP and SID auto-population
            domain_config = tracker.get_domain_config()
            dc_ip = domain_config.get("dc_ip") if domain_config else None
            dc_hostname = domain_config.get("dc_hostname") if domain_config else None
            domain_sid = domain_config.get("domain_sid") if domain_config else None

            # Get user SPNs for manual enumeration suggestions
            user_spns = tracker.get_user_spns(result.user)

            # Show success with follow-up commands
            print_pwned_followup_commands(
                user_name=result.user,
                cred_type=getattr(args, 'cred_type', None),
                cred_value=getattr(args, 'cred_value', None),
                access=result.access,
                domain_level_access=result.domain_level_access,
                dc_ip=dc_ip,
                dc_hostname=dc_hostname,
                domain_sid=domain_sid,
                spns=user_spns,
            )
            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_unpwn(cls, args: Namespace) -> int:
        """Handle --unpwn command - remove pwned status."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            result = tracker.unmark_pwned(args.unpwn)

            if not result.success:
                cls.print_error(f"Failed to unmark {args.unpwn}: {result.error}")
                return 1

            cls.print_success(f"Removed pwned status from: {args.unpwn}")
            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_list_pwned(cls, args: Namespace) -> int:
        """Handle --list-pwned command - list all pwned users."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            pwned_users = tracker.list_pwned_users()

            if not pwned_users:
                cls.print_info("No pwned users found")
                return 0

            print_pwned_users_table(pwned_users)
            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_pwned_user(cls, args: Namespace) -> int:
        """Handle --pwned-user command - show details for a pwned user."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            pwned_user = tracker.get_pwned_user(args.pwned_user)

            if not pwned_user:
                cls.print_error(f"User not found or not pwned: {args.pwned_user}")
                return 1

            machine_access = tracker.get_pwned_user_access(args.pwned_user)

            # Get domain config for DC IP, SID, and LHOST/LPORT auto-population
            domain_config = tracker.get_domain_config()
            dc_ip = domain_config.get("dc_ip") if domain_config else None
            dc_hostname = domain_config.get("dc_hostname") if domain_config else None
            domain_sid = domain_config.get("domain_sid") if domain_config else None
            lhost = domain_config.get("lhost") if domain_config else None
            lport = domain_config.get("lport") if domain_config else None

            # Override from CLI args if provided
            if getattr(args, 'lhost', None):
                lhost = args.lhost
            if getattr(args, 'lport', None):
                lport = args.lport

            # Fall back to config.py defaults if still not set
            if not lhost and CONFIG_LHOST:
                lhost = CONFIG_LHOST
            if not lport and CONFIG_LPORT:
                lport = CONFIG_LPORT

            # Get user SPNs for manual enumeration suggestions
            user_spns = tracker.get_user_spns(pwned_user.name)

            print_pwned_followup_commands(
                user_name=pwned_user.name,
                access=machine_access,
                domain_level_access=pwned_user.domain_level_access,
                cred_types=pwned_user.cred_types,
                cred_values=pwned_user.cred_values,
                dc_ip=dc_ip,
                dc_hostname=dc_hostname,
                domain_sid=domain_sid,
                lhost=lhost,
                lport=lport,
                spns=user_spns,
            )
            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_cred_targets(cls, args: Namespace) -> int:
        """Handle --cred-targets command - show credential harvest targets."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            targets = tracker.get_cred_harvest_targets()

            if not targets:
                cls.print_info("No credential harvest targets found")
                print("    Mark users as pwned first: --pwn USER@DOMAIN.COM")
                return 0

            print_cred_harvest_targets(targets)
            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_post_exploit(cls, args: Namespace) -> int:
        """Handle --post-exploit command - show mimikatz recommendations."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            # Get domain config for DC IP, SID, and LHOST/LPORT auto-population
            domain_config = tracker.get_domain_config()
            dc_ip = domain_config.get("dc_ip") if domain_config else None
            domain_sid = domain_config.get("domain_sid") if domain_config else None
            lhost = domain_config.get("lhost") if domain_config else None
            lport = domain_config.get("lport") if domain_config else None

            # Override from CLI args if provided
            if getattr(args, 'lhost', None):
                lhost = args.lhost
            if getattr(args, 'lport', None):
                lport = args.lport

            # Fall back to config.py defaults if still not set
            if not lhost and CONFIG_LHOST:
                lhost = CONFIG_LHOST
            if not lport and CONFIG_LPORT:
                lport = CONFIG_LPORT

            # Get all pwned users
            pwned_users = tracker.list_pwned_users()
            if not pwned_users:
                cls.print_info("No pwned users found")
                print("    Mark users as pwned first: --pwn USER@DOMAIN.COM")
                return 0

            shown_count = 0
            for user in pwned_users:
                machine_access = tracker.get_pwned_user_access(user.name)

                # Check if user has local-admin or domain-admin access
                has_local_admin = any(a.privilege_level == "local-admin" for a in machine_access)
                has_domain_admin = user.domain_level_access is not None

                if has_local_admin or has_domain_admin:
                    print_post_exploit_commands(
                        user_name=user.name,
                        access=machine_access,
                        domain_level_access=user.domain_level_access,
                        cred_types=user.cred_types,
                        cred_values=user.cred_values,
                        dc_ip=dc_ip,
                        domain_sid=domain_sid,
                        lhost=lhost,
                        lport=lport,
                    )
                    shown_count += 1

            if shown_count == 0:
                cls.print_info("No pwned users with local-admin or domain-admin access found")
                print("    Post-exploitation commands require elevated access")

            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_recommend(cls, args: Namespace) -> int:
        """Handle --recommend command - recommend attack paths for pwned users."""
        from ...query_runner import QueryRunner
        from ...command_suggester import CommandSuggester

        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            # Get domain config
            domain_config = tracker.get_domain_config()
            dc_ip = domain_config.get("dc_ip") if domain_config else None
            domain = domain_config.get("domain") if domain_config else None

            # Get all pwned users
            pwned_users = tracker.list_pwned_users()
            if not pwned_users:
                cls.print_info("No pwned users found")
                print("    Mark users as pwned first: --pwn USER@DOMAIN.COM")
                return 0

            # Initialize QueryRunner and CommandSuggester
            runner = QueryRunner(config)
            if not runner.connect():
                cls.print_error("Could not connect to Neo4j for queries")
                return 1

            try:
                suggester = CommandSuggester()

                total_recommendations = 0

                for user in pwned_users:
                    # Extract domain from user name if not configured
                    user_domain = domain
                    if not user_domain and "@" in user.name:
                        user_domain = user.name.split("@")[1]

                    recommendations = suggester.recommend_attack_paths(
                        pwned_user=user.name,
                        domain=user_domain or "UNKNOWN",
                        query_runner=runner,
                        dc_ip=dc_ip,
                    )

                    if recommendations:
                        print(f"\n{'='*70}")
                        print(f"[+] ATTACK PATHS FOR: {user.name}")
                        print(f"{'='*70}")

                        for seq in recommendations:
                            print(f"\n[CHAIN] {seq.name}")
                            if seq.description:
                                print(f"        {seq.description}")
                            print(f"        Steps: {seq.total_steps}")
                            print("-" * 60)

                            for i, step in enumerate(seq.steps, 1):
                                print(f"  Step {i}: {step.name}")
                                if step.ready_to_run:
                                    print(f"          $ {step.ready_to_run}")
                                if step.context:
                                    print(f"          Context: {step.context}")

                            total_recommendations += 1

                if total_recommendations == 0:
                    cls.print_info("No attack path recommendations found")
                    print("    Prerequisites may not be met (e.g., Account Operators membership)")

                return 0

            finally:
                runner.close()

        finally:
            tracker.close()

    @classmethod
    def _handle_list_ip_addresses(cls, args: Namespace) -> int:
        """Handle --list-ip-addresses command - list all machines with IPs."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            machines = tracker.get_all_machines_with_ips()
            # Get DC IP from stored config for highlighting
            domain_config = tracker.get_domain_config()
            dc_ip = domain_config.get("dc_ip") if domain_config else None
            print_machines_ip_table(machines, dc_ip=dc_ip)
            return 0

        finally:
            tracker.close()
