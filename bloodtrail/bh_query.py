#!/usr/bin/env python3
"""
BloodHound Trail - Query Runner

Interactive Cypher query execution for BloodHound attack path discovery.

Usage:
    # List all queries
    crack bloodtrail --list-queries

    # Run query by ID
    crack bloodtrail --run-query lateral-adminto-nonpriv

    # With variables
    crack bloodtrail --run-query owned-what-can-access --var USER=PETE@CORP.COM

    # Search queries
    crack bloodtrail --search-query DCSync

    # Export for BloodHound
    crack bloodtrail --export-query lateral-adminto-nonpriv
"""

import sys
import json
import readline  # Enables line editing in interactive mode
from typing import Optional

from .config import Neo4jConfig
from .query_runner import QueryRunner, Query


def print_banner():
    """Print tool banner"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║              BloodHound Trail (bloodtrail)               ║
║                                                           ║
║  63+ pre-built Cypher queries for attack path discovery   ║
║  Set NEO4J_PASSWORD env var for authentication            ║
╚═══════════════════════════════════════════════════════════╝
""")


def print_categories(runner: QueryRunner):
    """Print available query categories"""
    print("\nCategories:")
    for cat in sorted(runner.get_categories()):
        queries = runner.list_queries(category=cat)
        high_count = sum(1 for q in queries if q.oscp_relevance == "high")
        print(f"  {cat:25} ({len(queries)} queries, {high_count} OSCP:HIGH)")


def print_category_queries(runner: QueryRunner, category: str):
    """Print queries in a category"""
    queries = runner.list_queries(category=category)
    if not queries:
        print(f"[!] Category not found: {category}")
        return

    print(f"\n[{category.upper()}] Queries:")
    for q in queries:
        marker = "*" if q.oscp_relevance == "high" else " "
        vars_str = f" (vars: {', '.join(q.variables.keys())})" if q.has_variables() else ""
        print(f"  {marker} {q.id}{vars_str}")


def print_query_details(query: Query):
    """Print detailed query information"""
    print(f"\n{'='*60}")
    print(f"ID:          {query.id}")
    print(f"Name:        {query.name}")
    print(f"Category:    {query.category}")
    print(f"OSCP:        {query.oscp_relevance}")
    print(f"\nDescription:")
    print(f"  {query.description}")
    if query.variables:
        print(f"\nVariables:")
        for name, info in query.variables.items():
            print(f"  <{name}>: {info.get('description', '')}")
            print(f"           Example: {info.get('example', '')}")
    print(f"\nCypher:")
    for line in query.cypher.split('\n'):
        print(f"  {line}")
    if query.expected_results:
        print(f"\nExpected Results:")
        print(f"  {query.expected_results}")
    if query.next_steps:
        print(f"\nNext Steps:")
        print(f"  {', '.join(query.next_steps)}")
    print(f"{'='*60}")


def interactive_mode(runner: QueryRunner):
    """Run interactive query session"""
    print_banner()
    print_categories(runner)

    print("\nCommands:")
    print("  <query-id>          Run query")
    print("  <query-id> VAR=val  Run query with variable")
    print("  list <category>     Show category queries")
    print("  search <keyword>    Search queries")
    print("  info <query-id>     Show query details")
    print("  export <query-id>   Export as raw Cypher")
    print("  help                Show this help")
    print("  quit                Exit")

    while True:
        try:
            line = input("\nbh-query> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        # Handle commands
        if cmd in ("quit", "exit", "q"):
            print("Goodbye!")
            break

        elif cmd == "help":
            print("\nCommands:")
            print("  <query-id>          Run query")
            print("  <query-id> VAR=val  Run query with variable")
            print("  list <category>     Show category queries")
            print("  search <keyword>    Search queries")
            print("  info <query-id>     Show query details")
            print("  export <query-id>   Export as raw Cypher")
            print("  categories          List all categories")
            print("  quit                Exit")

        elif cmd == "categories":
            print_categories(runner)

        elif cmd == "list" and len(parts) > 1:
            print_category_queries(runner, parts[1])

        elif cmd == "search" and len(parts) > 1:
            keyword = " ".join(parts[1:])
            matches = runner.search_queries(keyword)
            if matches:
                print(f"\nFound {len(matches)} matches for '{keyword}':")
                for q in matches:
                    print(f"  {q.id} ({q.category})")
            else:
                print(f"[!] No matches for: {keyword}")

        elif cmd == "info" and len(parts) > 1:
            query = runner.get_query(parts[1])
            if query:
                print_query_details(query)
            else:
                print(f"[!] Query not found: {parts[1]}")

        elif cmd == "export" and len(parts) > 1:
            query_id = parts[1]
            variables = {}
            for p in parts[2:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    variables[k] = v
            cypher = runner.export_query(query_id, variables)
            if cypher:
                print(f"\n// {query_id}")
                print(cypher)
            else:
                print(f"[!] Query not found: {query_id}")

        else:
            # Try to run as query
            query_id = parts[0]
            query = runner.get_query(query_id)

            if not query:
                print(f"[!] Unknown command or query: {query_id}")
                print("    Type 'help' for commands or 'search <keyword>' to find queries")
                continue

            # Parse variables from remaining args
            variables = {}
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    variables[k] = v

            # Check required variables
            if query.has_variables():
                missing = [v for v in query.get_required_variables() if v not in variables]
                if missing:
                    print(f"[!] Missing variables: {', '.join(missing)}")
                    print(f"    Usage: {query_id} {missing[0]}=VALUE")
                    continue

            print(f"[*] Running: {query.name}")
            result = runner.run_query(query_id, variables)

            if result.success:
                print(runner.format_results_table(result))
                if result.records and query.next_steps:
                    print(f"\n[*] Try next: {', '.join(query.next_steps[:3])}")
            else:
                print(f"[!] Error: {result.error}")


def main():
    """Main entry point"""
    config = Neo4jConfig()
    runner = QueryRunner(config)

    # Check for command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1]

        # Handle --search
        if arg == "--search" and len(sys.argv) > 2:
            keyword = " ".join(sys.argv[2:])
            matches = runner.search_queries(keyword)
            if matches:
                print(f"Found {len(matches)} matches for '{keyword}':")
                for q in matches:
                    print(f"  {q.id:40} ({q.category})")
            else:
                print(f"[!] No matches for: {keyword}")
            return 0

        # Handle --export
        if arg == "--export" and len(sys.argv) > 2:
            query_id = sys.argv[2]
            variables = {}
            for a in sys.argv[3:]:
                if "=" in a:
                    k, v = a.split("=", 1)
                    variables[k] = v
            cypher = runner.export_query(query_id, variables)
            if cypher:
                query = runner.get_query(query_id)
                print(f"// {query.name}")
                print(cypher)
            else:
                print(f"[!] Query not found: {query_id}")
                return 1
            return 0

        # Handle --list
        if arg == "--list":
            category = sys.argv[2] if len(sys.argv) > 2 else None
            if category:
                print_category_queries(runner, category)
            else:
                print_categories(runner)
            return 0

        # Handle --help
        if arg in ("--help", "-h"):
            print(__doc__)
            return 0

        # Try as query ID
        query_id = arg
        query = runner.get_query(query_id)

        if query:
            # Parse variables
            variables = {}
            for a in sys.argv[2:]:
                if "=" in a:
                    k, v = a.split("=", 1)
                    variables[k] = v

            # Check required variables
            if query.has_variables():
                missing = [v for v in query.get_required_variables() if v not in variables]
                if missing:
                    print(f"[!] Missing variables: {', '.join(missing)}")
                    print(f"    Usage: bh_query {query_id} {missing[0]}=VALUE")
                    return 1

            print(f"[*] Running: {query.name}")
            result = runner.run_query(query_id, variables)

            if result.success:
                print(runner.format_results_table(result))
                return 0
            else:
                print(f"[!] Error: {result.error}")
                return 1
        else:
            print(f"[!] Query not found: {query_id}")
            print("    Use --search <keyword> to find queries")
            return 1

    # No arguments - interactive mode
    if not runner.connect():
        print("[!] Could not connect to Neo4j")
        print("    Ensure Neo4j is running: sudo neo4j start")
        return 1

    try:
        interactive_mode(runner)
    finally:
        runner.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
