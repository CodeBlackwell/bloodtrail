"""
BloodTrail Config Commands

Handles domain configuration commands:
- --show-config: Show stored domain configuration
- --clear-config: Clear domain configuration
- --set-dc-ip: Set DC IP address
- --domain-sid: Set domain SID
- --lhost/--lport: Set callback configuration
- --discover-dc: Auto-discover DC IP
- --purge: Purge all data from Neo4j
"""

import os
import getpass
from argparse import Namespace

from neo4j import GraphDatabase

from ..base import BaseCommandGroup
from ...config import Neo4jConfig
from ...pwned_tracker import (
    PwnedTracker,
    DiscoveryError,
    discover_dc_ip,
    discover_dc_hostname,
    update_etc_hosts,
)


class ConfigCommands(BaseCommandGroup):
    """Domain configuration command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add config arguments."""
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle config commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        if getattr(args, 'show_config', False):
            return cls._handle_show_config(args)

        if getattr(args, 'clear_config', False):
            return cls._handle_clear_config(args)

        if getattr(args, 'purge', False):
            return cls._handle_purge(args)

        if getattr(args, 'domain_sid', None):
            return cls._handle_domain_sid(args)

        # Handle standalone --lhost (not during import)
        if getattr(args, 'lhost', None) and not getattr(args, 'bh_data_dir', None):
            return cls._handle_callback_config(args)

        if getattr(args, 'discover_dc', None) is not None:
            return cls._handle_discover_dc(args)

        return -1

    @classmethod
    def _handle_show_config(cls, args: Namespace) -> int:
        """Handle --show-config command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            domain_config = tracker.get_domain_config()

            if not domain_config:
                cls.print_warning("No domain found in BloodHound data")
                print("    Import BloodHound data first: crack bloodtrail /path/to/bh/json/")
                return 0

            print()
            print("Domain Configuration")
            print("=" * 40)
            print(f"  Domain:      {domain_config['domain']}")
            print(f"  DC Hostname: {domain_config['dc_hostname'] or '(not set)'}")
            print(f"  DC IP:       {domain_config['dc_ip'] or '(not set)'}")
            print(f"  Domain SID:  {domain_config['domain_sid'] or '(not set)'}")

            # Callback config
            lhost = domain_config.get('lhost')
            lport = domain_config.get('lport')
            if lhost or lport:
                print()
                print("Callback Configuration")
                print("-" * 40)
                print(f"  LHOST:       {lhost or '(not set)'}")
                print(f"  LPORT:       {lport or '(not set)'}")

            print()

            if not domain_config['dc_ip']:
                print("  Set DC IP:   crack bloodtrail /path/to/bh/json/ --dc-ip 192.168.50.70")
            if not domain_config['domain_sid']:
                print("  Set SID:     crack bloodtrail -ds S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX")
            if not lhost:
                print("  Set LHOST:   crack bloodtrail --lhost 192.168.45.200 --lport 443")
            print()

            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_clear_config(cls, args: Namespace) -> int:
        """Handle --clear-config command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            result = tracker.clear_domain_config()

            if not result.success:
                cls.print_error(f"Failed to clear config: {result.error}")
                return 1

            cls.print_success("Domain configuration cleared")
            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_purge(cls, args: Namespace) -> int:
        """Handle --purge command - completely clear Neo4j database."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))

        # Connect to Neo4j
        try:
            driver = GraphDatabase.driver(config.uri, auth=(config.user, config.password))
            with driver.session() as session:
                session.run("RETURN 1")
        except Exception as e:
            cls.print_error(f"Could not connect to Neo4j: {e}")
            return 1

        # Get current database stats
        try:
            with driver.session() as session:
                result = session.run("""
                    MATCH (n)
                    WITH count(n) AS total_nodes
                    MATCH ()-[r]->()
                    WITH total_nodes, count(r) AS total_rels
                    RETURN total_nodes, total_rels
                """)
                record = result.single()
                total_nodes = record["total_nodes"] if record else 0
                total_rels = record["total_rels"] if record else 0

                result = session.run("""
                    MATCH (u:User) WITH count(u) AS users
                    MATCH (c:Computer) WITH users, count(c) AS computers
                    MATCH (g:Group) WITH users, computers, count(g) AS groups
                    MATCH (d:Domain) WITH users, computers, groups, count(d) AS domains
                    RETURN users, computers, groups, domains
                """)
                record = result.single()
                if record:
                    users = record["users"]
                    computers = record["computers"]
                    groups = record["groups"]
                    domains = record["domains"]
                else:
                    users = computers = groups = domains = 0

        except Exception as e:
            cls.print_error(f"Error checking database: {e}")
            driver.close()
            return 1

        # Display warning
        print()
        print("\033[91m\033[1m" + "=" * 70 + "\033[0m")
        print("\033[91m\033[1m  WARNING: Database Purge\033[0m")
        print("\033[91m\033[1m" + "=" * 70 + "\033[0m")
        print()
        print("  This will permanently delete ALL data from Neo4j:")
        print()
        print(f"    - Users:         \033[1m{users}\033[0m")
        print(f"    - Computers:     \033[1m{computers}\033[0m")
        print(f"    - Groups:        \033[1m{groups}\033[0m")
        print(f"    - Domains:       \033[1m{domains}\033[0m")
        print(f"    - Total Nodes:   \033[1m{total_nodes}\033[0m")
        print(f"    - Relationships: \033[1m{total_rels}\033[0m")
        print()

        if total_nodes == 0:
            cls.print_warning("Database is already empty.")
            driver.close()
            return 0

        # Confirm unless -y/--yes provided
        if not getattr(args, 'yes', False):
            confirm = input("  \033[1mType 'PURGE' to confirm:\033[0m ").strip()
            if confirm != "PURGE":
                print()
                cls.print_warning("Aborted. No changes made.")
                driver.close()
                return 0

        # Execute purge
        print()
        cls.print_info("Purging database...")

        try:
            with driver.session() as session:
                result = session.run("MATCH (n) DETACH DELETE n RETURN count(n) AS deleted")
                record = result.single()
                deleted = record["deleted"] if record else 0

            cls.print_success(f"Purge complete: {deleted} nodes deleted")
            print()
            print("  To reimport BloodHound data:")
            print("    1. Import via BloodHound GUI (File > Upload Data)")
            print("    2. Run: crack bloodtrail /path/to/sharphound.zip")
            print()

        except Exception as e:
            cls.print_error(f"Purge failed: {e}")
            driver.close()
            return 1

        driver.close()
        return 0

    @classmethod
    def _handle_domain_sid(cls, args: Namespace) -> int:
        """Handle --domain-sid command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            result = tracker.set_domain_sid(args.domain_sid)

            if not result.success:
                cls.print_error(f"Failed to set Domain SID: {result.error}")
                return 1

            domain_config = tracker.get_domain_config()
            stored_sid = domain_config.get("domain_sid") if domain_config else args.domain_sid
            cls.print_success(f"Domain SID set: {stored_sid}")

            if domain_config:
                print()
                print(f"  Domain:     {domain_config['domain']}")
                print(f"  Domain SID: {domain_config['domain_sid']}")

            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_callback_config(cls, args: Namespace) -> int:
        """Handle --lhost/--lport flags - store callback configuration."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            lhost = args.lhost
            lport = getattr(args, 'lport', None) or 443

            result = tracker.set_callback_config(lhost, lport)

            if not result.success:
                cls.print_error(f"Failed to set callback config: {result.error}")
                return 1

            cls.print_success(f"Callback config set: LHOST={lhost} LPORT={lport}")
            return 0

        finally:
            tracker.close()

    @classmethod
    def _handle_discover_dc(cls, args: Namespace) -> int:
        """Handle --discover-dc command - auto-discover DC IP."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        tracker = PwnedTracker(config)

        if not tracker.connect():
            cls.print_error("Could not connect to Neo4j")
            return 1

        try:
            domain_config = tracker.get_domain_config()

            if not domain_config or not domain_config.get('domain'):
                cls.print_error("No domain found in BloodHound data")
                print("    Import BloodHound data first: crack bloodtrail /path/to/bh/json/")
                return 1

            domain = domain_config['domain']

            # Get credentials
            if args.discover_dc and len(args.discover_dc) >= 2:
                ad_user, ad_password = args.discover_dc[0], args.discover_dc[1]
            else:
                cls.print_info(f"Discovering DC for {domain}")
                ad_user = input("    Username: ").strip()
                ad_password = getpass.getpass("    Password: ")

            if not ad_user or not ad_password:
                cls.print_error("Username and password required")
                return 1

            cls.print_info(f"Discovering DC for {domain}...")

            # Discover DC IP
            try:
                dc_ip = discover_dc_ip(domain, ad_user, ad_password)
                cls.print_success(f"DC IP: {dc_ip}")
            except DiscoveryError as e:
                cls.print_error(str(e))
                return 1

            # Discover DC hostname
            dc_hostname = None
            try:
                dc_hostname = discover_dc_hostname(dc_ip, ad_user, ad_password)
                cls.print_success(f"DC Hostname: {dc_hostname}")
            except DiscoveryError as e:
                cls.print_warning(str(e))

            # Store DC IP
            result = tracker.set_dc_ip(dc_ip, dc_hostname)
            if result.success:
                cls.print_success("DC IP stored in domain config")
            else:
                cls.print_error(f"Failed to store DC IP: {result.error}")

            # Update /etc/hosts
            if dc_hostname:
                try:
                    update_etc_hosts(dc_ip, [dc_hostname, domain])
                    cls.print_success(f"Updated /etc/hosts: {dc_ip} -> {dc_hostname}")
                except Exception as e:
                    cls.print_warning(f"Could not update /etc/hosts: {e}")

            return 0

        finally:
            tracker.close()
