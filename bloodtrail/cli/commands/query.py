"""
BloodTrail Query Commands

Handles query library commands:
- --list-queries: List available Cypher queries
- --search-query: Search queries by keyword
- --run-query: Run a specific query
- --export-query: Export query as raw Cypher
- --install-queries: Install to BloodHound Legacy
- --export-ce: Export for BloodHound CE
- --run-all: Run all queries and generate report
"""

import os
import json
from argparse import Namespace
from typing import Dict, Optional

from ..base import BaseCommandGroup
from ...config import Neo4jConfig
from ...query_runner import QueryRunner
from ...report_generator import (
    run_all_queries,
    export_to_bloodhound_customqueries,
    export_to_bloodhound_ce,
)


def parse_variables(var_list) -> Dict[str, str]:
    """Parse --var arguments into a dict."""
    if not var_list:
        return {}
    variables = {}
    for var in var_list:
        if "=" in var:
            name, value = var.split("=", 1)
            variables[name] = value
        else:
            print(f"[!] Invalid variable format: {var} (expected NAME=VALUE)")
    return variables


class QueryCommands(BaseCommandGroup):
    """Query library command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add query library arguments."""
        # Arguments are already added in cli/parser.py
        # This method exists for the interface but doesn't need to do anything
        # when using the legacy parser
        pass

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle query commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        if getattr(args, 'list_queries', False):
            return cls._handle_list_queries(args)

        if getattr(args, 'search_query', None):
            return cls._handle_search_queries(args)

        if getattr(args, 'run_query', None):
            return cls._handle_run_query(args)

        if getattr(args, 'export_query', None):
            return cls._handle_export_query(args)

        if getattr(args, 'install_queries', False):
            return cls._handle_install_queries(args)

        if getattr(args, 'export_ce', False) or getattr(args, 'export_ce_json', False):
            return cls._handle_export_ce(args)

        if getattr(args, 'run_all', False):
            return cls._handle_run_all(args)

        return -1  # Not handled by this group

    @classmethod
    def _handle_list_queries(cls, args: Namespace) -> int:
        """Handle --list-queries command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        runner = QueryRunner(config)

        queries = runner.list_queries(category=getattr(args, 'category', None))

        if not queries:
            cls.print_error("No queries found")
            return 1

        # Group by category
        by_category = {}
        for q in queries:
            if q.category not in by_category:
                by_category[q.category] = []
            by_category[q.category].append(q)

        print(f"\nBloodHound Cypher Query Library ({len(queries)} queries)")
        print("=" * 60)

        for cat, cat_queries in sorted(by_category.items()):
            print(f"\n[{cat.upper()}] ({len(cat_queries)} queries)")
            for q in cat_queries:
                oscp_marker = "*" if q.oscp_relevance == "high" else " "
                vars_marker = "(vars)" if q.has_variables() else ""
                print(f"  {oscp_marker} {q.id:40} {vars_marker}")

        print("\n* = OSCP:HIGH relevance")
        print("(vars) = requires --var arguments")
        print("\nRun: --run-query <id> to execute")
        return 0

    @classmethod
    def _handle_search_queries(cls, args: Namespace) -> int:
        """Handle --search-query command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        runner = QueryRunner(config)

        queries = runner.search_queries(args.search_query)

        if not queries:
            cls.print_error(f"No queries found matching: {args.search_query}")
            return 1

        print(f"\nSearch Results for '{args.search_query}' ({len(queries)} matches)")
        print("=" * 60)

        for q in queries:
            print(f"\n{q.id}")
            print(f"  Name: {q.name}")
            print(f"  Category: {q.category} | OSCP: {q.oscp_relevance}")
            if q.has_variables():
                print(f"  Variables: {', '.join(q.variables.keys())}")

        return 0

    @classmethod
    def _handle_run_query(cls, args: Namespace) -> int:
        """Handle --run-query command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        runner = QueryRunner(config)

        query = runner.get_query(args.run_query)
        if not query:
            cls.print_error(f"Query not found: {args.run_query}")
            return 1

        # Parse variables
        variables = parse_variables(getattr(args, 'var', None))

        # Check required variables
        if query.has_variables():
            missing = [v for v in query.get_required_variables() if v not in variables]
            if missing:
                cls.print_error(f"Missing required variables: {', '.join(missing)}")
                print(f"    Use: --var {missing[0]}=VALUE")
                for var_name, var_info in query.variables.items():
                    print(f"    {var_name}: {var_info.get('description', '')} (e.g., {var_info.get('example', '')})")
                return 1

        cls.print_info(f"Running: {query.name}")
        cls.print_info(f"Category: {query.category} | OSCP: {query.oscp_relevance}")

        result = runner.run_query(args.run_query, variables)

        if not result.success:
            cls.print_error(f"Query failed: {result.error}")
            return 1

        # Format output
        output_format = getattr(args, 'output_format', 'table')
        if output_format == "json":
            print(json.dumps(result.records, indent=2, default=str))
        elif output_format == "cypher":
            print("\n# Executed Cypher:")
            print(result.cypher_executed)
        else:
            print(runner.format_results_table(result))

        # Suggest next steps
        if result.records and query.next_steps:
            cls.print_info(f"Suggested next queries: {', '.join(query.next_steps[:3])}")

        runner.close()
        return 0

    @classmethod
    def _handle_export_query(cls, args: Namespace) -> int:
        """Handle --export-query command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        runner = QueryRunner(config)

        query = runner.get_query(args.export_query)
        if not query:
            cls.print_error(f"Query not found: {args.export_query}")
            return 1

        variables = parse_variables(getattr(args, 'var', None))
        cypher = runner.export_query(args.export_query, variables)

        print(f"// Query: {query.name}")
        print(f"// Category: {query.category}")
        print(f"// OSCP Relevance: {query.oscp_relevance}")
        if query.has_variables() and not variables:
            print(f"// Variables needed: {', '.join(query.variables.keys())}")
        print()
        print(cypher)

        return 0

    @classmethod
    def _handle_install_queries(cls, args: Namespace) -> int:
        """Handle --install-queries command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        runner = QueryRunner(config)

        # Count queries before filtering
        all_queries = runner.list_queries(category=getattr(args, 'category', None))
        high_only = getattr(args, 'oscp_high_only', False)

        if high_only:
            filtered = [q for q in all_queries if q.oscp_relevance == "high"]
            cls.print_info(f"Installing {len(filtered)} OSCP:HIGH queries (filtered from {len(all_queries)})")
        else:
            filtered = all_queries
            cls.print_info(f"Installing {len(filtered)} queries")

        if getattr(args, 'category', None):
            cls.print_info(f"Category filter: {args.category}")

        # Export to BloodHound format
        output_path = export_to_bloodhound_customqueries(
            runner,
            output_path=getattr(args, 'install_path', None),
            category_filter=getattr(args, 'category', None),
            oscp_high_only=high_only
        )

        cls.print_success(f"Saved to: {output_path}")
        print()
        print("To use in BloodHound Legacy:")
        print("  1. Restart BloodHound")
        print("  2. Click 'Queries' tab (left sidebar)")
        print("  3. Look for '[CRACK] *' categories (sorted together)")
        print()
        print("Query categories installed:")
        category_display = {
            "lateral_movement": "Lateral Movement",
            "quick_wins": "Quick Wins",
            "privilege_escalation": "Privilege Escalation",
            "attack_chains": "Attack Chains",
            "operational": "Operational",
            "owned_principal": "Owned Principal",
        }
        categories = set(q.category for q in filtered)
        for cat in sorted(categories):
            count = sum(1 for q in filtered if q.category == cat)
            display = category_display.get(cat, cat.replace("_", " ").title())
            print(f"  - [CRACK] {display} ({count} queries)")

        return 0

    @classmethod
    def _handle_export_ce(cls, args: Namespace) -> int:
        """Handle --export-ce and --export-ce-json commands."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        runner = QueryRunner(config)

        # Count queries
        all_queries = runner.list_queries(category=getattr(args, 'category', None))
        high_only = getattr(args, 'oscp_high_only', False)
        create_zip = getattr(args, 'export_ce', False)  # True for --export-ce

        if high_only:
            filtered = [q for q in all_queries if q.oscp_relevance == "high"]
            cls.print_info(f"Exporting {len(filtered)} OSCP:HIGH queries (filtered from {len(all_queries)})")
        else:
            filtered = all_queries
            cls.print_info(f"Exporting {len(filtered)} queries")

        if getattr(args, 'category', None):
            cls.print_info(f"Category filter: {args.category}")

        # Export to BloodHound CE format
        output_path = export_to_bloodhound_ce(
            runner,
            output_path=getattr(args, 'install_path', None),
            category_filter=getattr(args, 'category', None),
            oscp_high_only=high_only,
            create_zip=create_zip
        )

        cls.print_success(f"Saved to: {output_path}")
        print()
        if create_zip:
            print("To use in BloodHound CE:")
            print("  1. Open BloodHound CE")
            print("  2. Go to Explore > Cypher")
            print("  3. Click 'Saved Queries' dropdown")
            print("  4. Drag and drop the ZIP file")
        else:
            print("To use in BloodHound CE:")
            print("  1. Import the JSON file via the API")
            print("  2. Or use the individual query files")

        return 0

    @classmethod
    def _handle_run_all(cls, args: Namespace) -> int:
        """Handle --run-all command."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))
        runner = QueryRunner(config)

        if not runner.connect():
            cls.print_error("Could not connect to Neo4j")
            print("    Ensure Neo4j is running: sudo neo4j start")
            return 1

        high_only = getattr(args, 'oscp_high_only', False)

        # Get stored DC IP from domain config
        dc_ip = cls._get_stored_dc_ip(config)

        try:
            stats = run_all_queries(
                runner,
                output_path=getattr(args, 'report_path', None),
                skip_variable_queries=True,
                oscp_high_only=high_only,
                show_commands=getattr(args, 'commands', False),
                show_data=getattr(args, 'data', False),
                dc_ip=dc_ip,
            )
        finally:
            runner.close()

        return 0 if stats["failed"] == 0 else 1

    @classmethod
    def _get_stored_dc_ip(cls, config: Neo4jConfig) -> Optional[str]:
        """Get stored DC IP from domain config."""
        try:
            from ...pwned_tracker import PwnedTracker
            tracker = PwnedTracker(config)
            if tracker.connect():
                domain_config = tracker.get_domain_config()
                dc_ip = domain_config.get("dc_ip") if domain_config else None
                tracker.close()
                return dc_ip
        except Exception:
            pass
        return None
