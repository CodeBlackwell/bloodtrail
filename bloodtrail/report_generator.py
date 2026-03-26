"""
BloodTrail Report Generator

Extracted from query_runner.py - handles report generation and query export.
Contains run_all_queries() and BloodHound export functions.
"""

import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, TYPE_CHECKING

from .core.formatters import (
    Colors,
    format_field_value,
    format_neo4j_path,
    has_path_results,
    is_neo4j_path,
    print_attack_paths,
)
from .core.models import Query

if TYPE_CHECKING:
    from .query_runner import QueryRunner


def run_all_queries(
    runner: 'QueryRunner',
    output_path: Optional[Path] = None,
    skip_variable_queries: bool = True,
    oscp_high_only: bool = False,
    verbose: bool = False,
    show_commands: bool = False,
    show_data: bool = False,
    dc_ip: Optional[str] = None,
) -> dict:
    """
    Run all queries and generate colorized console output + markdown report.

    Args:
        runner: QueryRunner instance
        output_path: Path for markdown report (default: ./bloodtrail.md)
        skip_variable_queries: Skip queries requiring variables (default: True)
        oscp_high_only: Only run OSCP:HIGH queries
        verbose: Show full query results in console (no truncation)
        show_commands: Only show command suggestions in console (-c flag)
        show_data: Only show raw query data in console (-d flag)
        dc_ip: Domain Controller IP (for <DC_IP> placeholder - retrieved from Neo4j)

    Returns:
        Dict with summary statistics
    """
    # Determine what to show in console (default: both)
    # If neither flag set, show everything
    # If one flag set, show only that section
    show_all = not show_commands and not show_data

    # Initialize command suggester for attack recommendations
    try:
        from .command_suggester import CommandSuggester
        from .display_commands import (
            print_command_tables_by_phase,
            print_post_success,
            format_tables_markdown,
        )
        suggester = CommandSuggester()
        suggestions_enabled = bool(suggester.commands)
    except ImportError:
        suggester = None
        suggestions_enabled = False

    # Fetch pwned users for credential auto-fill
    pwned_lookup = {}
    try:
        from .pwned_tracker import PwnedTracker
        tracker = PwnedTracker(runner.config)
        if tracker.connect():
            for u in tracker.list_pwned_users():
                pwned_lookup[u.name.upper()] = u
            tracker.close()
    except Exception:
        pass  # Continue without pwned user credentials

    queries = runner.list_queries()
    if oscp_high_only:
        queries = [q for q in queries if q.oscp_relevance == "high"]

    # Category display names
    cat_names = {
        "quick_wins": "Quick Wins",
        "lateral_movement": "Lateral Movement",
        "privilege_escalation": "Privilege Escalation",
        "attack_chains": "Attack Chains",
        "operational": "Operational",
        "owned_principal": "Owned Principal",
    }

    # Group queries by category
    by_category = {}
    for q in queries:
        if q.category not in by_category:
            by_category[q.category] = []
        by_category[q.category].append(q)

    # Results storage
    all_results = {}
    all_tables = []       # DRY command tables
    all_sequences = []    # attack sequences from chain queries
    stats = {
        "total_queries": 0,
        "successful": 0,
        "with_results": 0,
        "skipped": 0,
        "failed": 0,
        "findings": [],
        "tables_generated": 0,
        "total_targets": 0,
        "sequences_generated": 0,
    }

    # Markdown report
    report_lines = [
        "# BloodHound Enhanced Report",
        f"",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        "---",
        "",
    ]

    # Print header (always show if any console output)
    if show_all or show_commands or show_data:
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
        print(f"  BLOODHOUND ENHANCED REPORT")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}{Colors.RESET}\n")

    # Get and display inventory
    inventory = runner.get_inventory()
    if inventory and not inventory.get("error"):
        # Console output (only if showing data or all)
        if show_all or show_data:
            print(f"{Colors.BOLD}{Colors.CYAN}+{'-'*68}+")
            print(f"|  {'DATA INVENTORY':64} |")
            print(f"+{'-'*68}+{Colors.RESET}")

            # Domain info
            if inventory["domains"]:
                print(f"  {Colors.BOLD}Domains:{Colors.RESET} {', '.join(inventory['domains'])}")

            # Counts table
            u = inventory["users"]
            c = inventory["computers"]
            g = inventory["groups"]
            print(f"\n  {Colors.BOLD}{'Type':<12} {'Count':>8}  {'Details':<45}{Colors.RESET}")
            print(f"  {'-'*12} {'-'*8}  {'-'*45}")
            print(f"  {'Users':<12} {u['count']:>8}  {Colors.GREEN}{u['enabled']} enabled{Colors.RESET}")
            print(f"  {'Computers':<12} {c['count']:>8}  {', '.join(c['samples'][:3]) if c['samples'] else '-'}")
            print(f"  {'Groups':<12} {g['count']:>8}  {', '.join(g['samples'][:3]) if g['samples'] else '-'}")

            # Relationships
            rels = inventory.get("relationships", {})
            if rels:
                print(f"\n  {Colors.BOLD}Relationships:{Colors.RESET}")
                rel_items = [f"{k}: {v}" for k, v in sorted(rels.items(), key=lambda x: -x[1])]
                print(f"  {Colors.DIM}{' | '.join(rel_items)}{Colors.RESET}")

            # User samples
            if u["samples"]:
                print(f"\n  {Colors.BOLD}Key Users:{Colors.RESET}")
                for user in u["samples"][:5]:
                    print(f"    {Colors.YELLOW}>{Colors.RESET} {user}")

            # Computer samples
            if c["samples"]:
                print(f"\n  {Colors.BOLD}Computers:{Colors.RESET}")
                for comp in c["samples"][:5]:
                    print(f"    {Colors.CYAN}>{Colors.RESET} {comp}")

            print()
        else:
            # Need these for report even if not printing
            u = inventory["users"]
            c = inventory["computers"]
            g = inventory["groups"]
            rels = inventory.get("relationships", {})
            rel_items = [f"{k}: {v}" for k, v in sorted(rels.items(), key=lambda x: -x[1])] if rels else []

        # Add to report (always)
        report_lines.append("## Data Inventory")
        report_lines.append("")
        report_lines.append(f"**Domains:** {', '.join(inventory['domains'])}")
        report_lines.append("")
        report_lines.append("| Type | Count | Details |")
        report_lines.append("|------|-------|---------|")
        report_lines.append(f"| Users | {u['count']} | {u['enabled']} enabled |")
        report_lines.append(f"| Computers | {c['count']} | {', '.join(c['samples'][:3]) if c['samples'] else '-'} |")
        report_lines.append(f"| Groups | {g['count']} | {', '.join(g['samples'][:3]) if g['samples'] else '-'} |")
        report_lines.append("")
        if rels:
            report_lines.append(f"**Relationships:** {' | '.join(rel_items)}")
            report_lines.append("")

    # =========================================================================
    # PHASE 1: Run all queries and collect results (no printing yet)
    # =========================================================================
    category_order = ["quick_wins", "lateral_movement", "privilege_escalation",
                      "attack_chains", "owned_principal", "operational"]

    # Storage for deferred output
    category_outputs = {}  # category -> list of (query, result, status) tuples

    for category in category_order:
        if category not in by_category:
            continue

        cat_queries = by_category[category]
        cat_display = cat_names.get(category, category.replace("_", " ").title())
        category_outputs[category] = {"display": cat_display, "queries": []}

        for query in cat_queries:
            stats["total_queries"] += 1

            # Skip variable queries if requested
            if skip_variable_queries and query.has_variables():
                stats["skipped"] += 1
                category_outputs[category]["queries"].append({
                    "query": query, "result": None, "status": "skipped"
                })
                continue

            # Run query
            result = runner.run_query(query.id)

            if result.success:
                stats["successful"] += 1
                all_results[query.id] = result

                if result.record_count > 0:
                    stats["with_results"] += 1

                    # Generate attack command tables (DRY approach)
                    if suggestions_enabled and suggester:
                        tables = suggester.build_command_tables(query.id, result.records, pwned_users=pwned_lookup, dc_ip=dc_ip)
                        if tables:
                            all_tables.extend(tables)
                            stats["tables_generated"] += len(tables)
                            stats["total_targets"] += sum(len(t.targets) for t in tables)

                        # Also check for attack sequences (chain queries)
                        from .mappings.query_loader import QUERY_COMMAND_MAPPINGS
                        mapping = QUERY_COMMAND_MAPPINGS.get(query.id)
                        if mapping == "BUILD_SEQUENCE":
                            sequences = suggester.suggest_for_query(query.id, result.records)
                            if sequences:
                                all_sequences.extend(sequences)
                                stats["sequences_generated"] += len(sequences)

                    # Add to findings
                    stats["findings"].append({
                        "query": query.name,
                        "category": cat_display,
                        "count": result.record_count,
                        "relevance": query.oscp_relevance
                    })

                    category_outputs[category]["queries"].append({
                        "query": query, "result": result, "status": "results"
                    })
                else:
                    category_outputs[category]["queries"].append({
                        "query": query, "result": result, "status": "no_results"
                    })
            else:
                stats["failed"] += 1
                category_outputs[category]["queries"].append({
                    "query": query, "result": result, "status": "failed"
                })

    # =========================================================================
    # PHASE 1.5: Detect dynamic attack chains from pwned users
    # =========================================================================
    dynamic_chains = _detect_dynamic_chains(runner, pwned_lookup, dc_ip)
    if dynamic_chains:
        all_sequences.extend(dynamic_chains)
        stats["sequences_generated"] += len(dynamic_chains)

    # =========================================================================
    # PHASE 2: Print ATTACK COMMANDS first (actionable items at top)
    # =========================================================================
    if all_tables or all_sequences:
        # Console output (only if showing commands or all)
        if show_all or show_commands:
            print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
            print(f"  ATTACK COMMANDS")
            print(f"{'='*70}{Colors.RESET}")

            # Print DRY command tables grouped by phase
            if all_tables:
                print_command_tables_by_phase(all_tables, use_colors=True)

                # Print post-success suggestions for tables that have them
                for table in all_tables:
                    if table.post_success and table.targets:
                        domain = table.targets[0].domain if table.targets else ""
                        print_post_success(table.post_success, domain=domain, use_colors=True)

            # Attack Sequences (chain queries)
            if all_sequences:
                print(f"\n{Colors.BOLD}{Colors.HEADER}Multi-Step Attack Chains{Colors.RESET}")
                for seq in all_sequences:
                    print(f"  {Colors.BOLD}{Colors.HEADER}{seq.name}{Colors.RESET}")
                    print(f"  {Colors.DIM}{seq.description}{Colors.RESET}")
                    for i, step in enumerate(seq.steps, 1):
                        print(f"    {i}. {Colors.DIM}{step.template}{Colors.RESET}")
                        print(f"       {Colors.GREEN}{step.ready_to_run}{Colors.RESET}")
                    print()

            # Stats
            print(f"\n{Colors.DIM}Command tables: {stats['tables_generated']} | Targets: {stats['total_targets']}")
            print(f"Attack chains: {stats['sequences_generated']}{Colors.RESET}")
            print()

        # Add to report (always)
        if all_tables:
            report_lines.append("## Attack Commands")
            report_lines.append("")
            report_lines.append(format_tables_markdown(all_tables))

        if all_sequences:
            report_lines.append("### Multi-Step Attack Chains")
            report_lines.append("")
            for seq in all_sequences:
                report_lines.append(f"#### {seq.name}")
                report_lines.append(f"*{seq.description}*")
                report_lines.append("")
                for i, step in enumerate(seq.steps, 1):
                    report_lines.append(f"{i}. **{step.context}**")
                    report_lines.append(f"   - Template: `{step.template}`")
                    report_lines.append(f"   - Ready: `{step.ready_to_run}`")
                report_lines.append("")

        report_lines.append("---")
        report_lines.append("")

    # =========================================================================
    # PHASE 3: Print query results (raw data at bottom)
    # =========================================================================
    if show_all or show_data:
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
        print(f"  QUERY RESULTS (RAW DATA)")
        print(f"{'='*70}{Colors.RESET}\n")

    for category in category_order:
        if category not in category_outputs:
            continue

        cat_data = category_outputs[category]
        cat_display = cat_data["display"]

        # Category header (console only if showing data)
        if show_all or show_data:
            print(f"{Colors.BOLD}{Colors.CYAN}+{'-'*68}+")
            print(f"|  {cat_display.upper():64} |")
            print(f"+{'-'*68}+{Colors.RESET}")

        report_lines.append(f"## {cat_display}")
        report_lines.append("")

        for item in cat_data["queries"]:
            query = item["query"]
            result = item["result"]
            status = item["status"]

            rel_color = Colors.RED if query.oscp_relevance == "high" else (
                Colors.YELLOW if query.oscp_relevance == "medium" else Colors.DIM
            )
            rel_badge = f"[{query.oscp_relevance.upper()}]"

            if status == "skipped":
                if show_all or show_data:
                    print(f"  {Colors.DIM}o {query.name} (skipped - requires variables){Colors.RESET}")
                report_lines.append(f"### {query.name}")
                report_lines.append(f"*Skipped - requires variables: {', '.join(query.variables.keys())}*")
                report_lines.append("")

            elif status == "results":
                if show_all or show_data:
                    print(f"  {Colors.GREEN}*{Colors.RESET} {rel_color}{rel_badge}{Colors.RESET} {Colors.BOLD}{query.name}{Colors.RESET}")
                    print(f"    {Colors.GREEN}+-- {result.record_count} results{Colors.RESET}")

                    # Check if results contain path objects
                    if result.records and has_path_results(result.records):
                        # Use visual path display for attack paths
                        print_attack_paths(result.records, query.name, use_colors=True)
                    # Verbose: show full table in console (non-path results)
                    elif verbose and result.records:
                        headers = list(result.records[0].keys())
                        widths = {h: len(h) for h in headers}
                        for record in result.records:
                            for h in headers:
                                val = format_field_value(h, record.get(h, ""))
                                widths[h] = max(widths[h], len(val))
                        header_line = " | ".join(h.ljust(widths[h]) for h in headers)
                        print(f"    {Colors.DIM}{header_line}{Colors.RESET}")
                        print(f"    {Colors.DIM}{'-' * len(header_line)}{Colors.RESET}")
                        for record in result.records:
                            row = " | ".join(format_field_value(h, record.get(h, "")).ljust(widths[h]) for h in headers)
                            print(f"    {row}")
                        print()

                # Markdown (always)
                report_lines.append(f"### [OK] {query.name}")
                report_lines.append(f"**OSCP Relevance:** {query.oscp_relevance.upper()} | **Results:** {result.record_count}")
                report_lines.append("")
                report_lines.append(f"> {query.description}")
                report_lines.append("")

                if result.records:
                    # Format paths nicely in markdown too
                    if has_path_results(result.records):
                        report_lines.append("**Attack Paths:**")
                        report_lines.append("")
                        for i, record in enumerate(result.records[:15], 1):
                            for key, val in record.items():
                                if is_neo4j_path(val):
                                    parsed = format_neo4j_path(val)
                                    if not parsed.get('error'):
                                        edges_str = ' -> '.join(parsed['edges'])
                                        report_lines.append(f"{i}. **{parsed['start']}** -> **{parsed['end']}** ({parsed['hops']} hops)")
                                        report_lines.append(f"   - Path: {' -> '.join(parsed['nodes'])}")
                                        report_lines.append(f"   - Edges: {edges_str}")
                                        report_lines.append("")
                        if len(result.records) > 15:
                            report_lines.append(f"*... and {len(result.records) - 15} more paths*")
                    else:
                        headers = list(result.records[0].keys())
                        report_lines.append("| " + " | ".join(headers) + " |")
                        report_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
                        for record in result.records:
                            row = [format_field_value(h, record.get(h, "")).replace("|", "\\|") for h in headers]
                            report_lines.append("| " + " | ".join(row) + " |")
                report_lines.append("")

            elif status == "no_results":
                if show_all or show_data:
                    print(f"  {Colors.DIM}o {rel_badge} {query.name} (no results){Colors.RESET}")
                report_lines.append(f"### [-] {query.name}")
                report_lines.append(f"**OSCP Relevance:** {query.oscp_relevance.upper()} | **Results:** None")
                report_lines.append("")

            elif status == "failed":
                if show_all or show_data:
                    print(f"  {Colors.RED}X {rel_badge} {query.name} (failed: {result.error[:40]}){Colors.RESET}")
                report_lines.append(f"### [X] {query.name}")
                report_lines.append(f"**Error:** {result.error}")
                report_lines.append("")

        if show_all or show_data:
            print()  # Space between categories
        report_lines.append("---")
        report_lines.append("")

    # Summary
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}{Colors.RESET}")
    print(f"  {Colors.CYAN}Total Queries:{Colors.RESET}  {stats['total_queries']}")
    print(f"  {Colors.GREEN}With Results:{Colors.RESET}   {stats['with_results']}")
    print(f"  {Colors.DIM}No Results:{Colors.RESET}     {stats['successful'] - stats['with_results']}")
    print(f"  {Colors.YELLOW}Skipped:{Colors.RESET}        {stats['skipped']}")
    print(f"  {Colors.RED}Failed:{Colors.RESET}         {stats['failed']}")
    print()

    # Key findings
    if stats["findings"]:
        high_findings = [f for f in stats["findings"] if f["relevance"] == "high"]
        if high_findings:
            print(f"{Colors.BOLD}{Colors.RED}  KEY FINDINGS (OSCP:HIGH):{Colors.RESET}")
            for f in high_findings[:10]:
                print(f"    {Colors.RED}>{Colors.RESET} {f['query']}: {Colors.BOLD}{f['count']}{Colors.RESET} results")
            print()

    # Summary in report
    report_lines.append("## Summary")
    report_lines.append("")
    report_lines.append(f"| Metric | Count |")
    report_lines.append(f"| ------ | ----- |")
    report_lines.append(f"| Total Queries | {stats['total_queries']} |")
    report_lines.append(f"| With Results | {stats['with_results']} |")
    report_lines.append(f"| No Results | {stats['successful'] - stats['with_results']} |")
    report_lines.append(f"| Skipped | {stats['skipped']} |")
    report_lines.append(f"| Failed | {stats['failed']} |")
    report_lines.append("")

    if stats["findings"]:
        report_lines.append("### Key Findings")
        report_lines.append("")
        high_findings = [f for f in stats["findings"] if f["relevance"] == "high"]
        for f in sorted(high_findings, key=lambda x: -x["count"]):
            report_lines.append(f"- **{f['query']}**: {f['count']} results ({f['category']})")
        report_lines.append("")

    # Generate additional sections
    _add_pwned_attack_paths(runner, report_lines, show_all, show_commands)
    _add_post_exploit_section(runner, report_lines, show_all, show_commands)
    _add_spray_sections(runner, report_lines, show_all, show_commands)

    # Write report
    if output_path is None:
        output_path = Path.cwd() / "bloodtrail.md"
    else:
        output_path = Path(output_path)

    with open(output_path, "w") as f:
        f.write("\n".join(report_lines))

    print(f"{Colors.GREEN}Report saved:{Colors.RESET} {output_path}")
    print()

    return stats


def _add_pwned_attack_paths(runner, report_lines, show_all, show_commands):
    """Add pwned user attack paths section."""
    try:
        from .display_commands import generate_pwned_attack_paths
        if runner.driver:
            pwned_console, pwned_markdown = generate_pwned_attack_paths(runner.driver)
            if pwned_console:
                if show_all or show_commands:
                    print(pwned_console)
                report_lines.append("")
                report_lines.append(pwned_markdown)
    except Exception:
        pass


def _add_post_exploit_section(runner, report_lines, show_all, show_commands):
    """Add post-exploitation commands section."""
    try:
        from .display_commands import generate_post_exploit_section
        if runner.driver:
            pe_console, pe_markdown = generate_post_exploit_section(runner.driver)
            if pe_console:
                if show_all or show_commands:
                    print(pe_console)
                report_lines.append("")
                report_lines.append(pe_markdown)
    except Exception:
        pass


def _add_spray_sections(runner, report_lines, show_all, show_commands):
    """Add spray recommendations sections."""
    try:
        from .display_commands import print_spray_tailored, generate_spray_section
        from .pwned_tracker import PwnedTracker

        tracker = PwnedTracker(runner.config)
        if not tracker.connect():
            return

        # Tailored spray
        access_data = tracker.get_all_users_with_access()
        if access_data:
            domain_config = tracker.get_domain_config()
            domain = domain_config.get("domain", "") if domain_config else ""
            ts_console, ts_markdown = print_spray_tailored(access_data, domain)
            if ts_console:
                if show_all or show_commands:
                    print(ts_console)
                report_lines.append("")
                report_lines.append(ts_markdown)

        # Password spray recommendations
        pwned_users_list = tracker.list_pwned_users()
        policy = tracker.get_password_policy()
        domain_config = tracker.get_domain_config()
        tracker.close()

        if pwned_users_list:
            domain = ""
            if domain_config and domain_config.get("domain"):
                domain = domain_config["domain"]
            else:
                for user in pwned_users_list:
                    if "@" in user.name:
                        domain = user.name.split("@")[1]
                        break

            dc_ip = (domain_config.get("dc_ip") if domain_config else None) or "<DC_IP>"

            spray_console, spray_markdown = generate_spray_section(
                pwned_users=pwned_users_list,
                policy=policy,
                domain=domain,
                dc_ip=dc_ip,
                use_colors=True,
            )
            if spray_console:
                if show_all or show_commands:
                    print(spray_console)
                report_lines.append("")
                report_lines.append(spray_markdown)
    except Exception:
        pass


def print_query_info(query: Query):
    """Print detailed information about a query."""
    print(f"\n{'='*60}")
    print(f"ID:          {query.id}")
    print(f"Name:        {query.name}")
    print(f"Category:    {query.category}")
    print(f"OSCP:        {query.oscp_relevance}")
    print(f"Description: {query.description[:100]}...")
    if query.variables:
        print(f"Variables:   {', '.join(query.variables.keys())}")
    if query.edge_types_used:
        print(f"Edges Used:  {', '.join(query.edge_types_used)}")
    print(f"Tags:        {', '.join(query.tags[:5])}")
    print(f"{'='*60}\n")


def export_to_bloodhound_customqueries(
    runner: 'QueryRunner',
    output_path: Optional[Path] = None,
    category_filter: Optional[str] = None,
    oscp_high_only: bool = False
) -> str:
    """
    Export queries to BloodHound Legacy customqueries.json format.

    Args:
        runner: QueryRunner instance with loaded queries
        output_path: Path to save customqueries.json (default: ~/.config/bloodhound/)
        category_filter: Only export queries from this category
        oscp_high_only: Only export OSCP:HIGH queries

    Returns:
        Path where file was saved
    """
    queries = runner.list_queries(category=category_filter)

    if oscp_high_only:
        queries = [q for q in queries if q.oscp_relevance == "high"]

    # Group by category for BloodHound UI organization
    bh_queries = []

    # Map internal categories to BloodHound display names
    category_display = {
        "lateral_movement": "Lateral Movement",
        "quick_wins": "Quick Wins",
        "privilege_escalation": "Privilege Escalation",
        "attack_chains": "Attack Chains",
        "operational": "Operational",
        "owned_principal": "Owned Principal",
    }

    for query in queries:
        # Convert to BloodHound format
        # Use "[CRACK]" prefix to group all our queries together in BH sidebar
        display_cat = category_display.get(query.category, query.category.replace("_", " ").title())
        bh_query = {
            "name": f"[{query.oscp_relevance.upper()}] {query.name}",
            "category": f"[CRACK] {display_cat}",
            "queryList": []
        }

        # Handle queries with variables - create selection step
        if query.has_variables():
            for var_name, var_info in query.variables.items():
                # Add variable selection step
                var_type = "User" if "user" in var_name.lower() else "Computer"
                selection_query = f"MATCH (n:{var_type}) WHERE n.enabled = true RETURN n.name ORDER BY n.name"

                bh_query["queryList"].append({
                    "final": False,
                    "title": f"Select {var_info.get('description', var_name)}",
                    "query": selection_query
                })

            # Final query with $result substitution (for single variable)
            # BloodHound uses $result for the selected value
            final_cypher = query.cypher
            for var_name in query.variables.keys():
                final_cypher = final_cypher.replace(f"<{var_name}>", "$result")

            bh_query["queryList"].append({
                "final": True,
                "query": final_cypher,
                "allowCollapse": True
            })
        else:
            # Simple query without variables
            bh_query["queryList"].append({
                "final": True,
                "query": query.cypher,
                "allowCollapse": True
            })

        bh_queries.append(bh_query)

    # Build final structure
    output = {"queries": bh_queries}

    # Determine output path
    if output_path is None:
        output_path = Path.home() / ".config" / "bloodhound" / "customqueries.json"

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Check for existing file and merge
    if output_path.exists():
        try:
            with open(output_path) as f:
                existing = json.load(f)
            # Remove old CRACK queries, keep user's custom queries
            existing_queries = [
                q for q in existing.get("queries", [])
                if not q.get("category", "").startswith("[CRACK]")
                and not q.get("category", "").startswith("blood_trail/")  # Legacy cleanup
            ]
            output["queries"] = existing_queries + bh_queries
            print(f"[*] Merged with existing {len(existing_queries)} custom queries")
        except Exception:
            pass  # Overwrite if can't parse

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    return str(output_path)


# ============================================================================
# DYNAMIC ATTACK CHAIN DETECTION
# ============================================================================

def _chain_to_sequence(chain, state) -> 'AttackSequence':
    """Convert AttackChain to AttackSequence for consistent display."""
    from .command_suggester import AttackSequence, CommandSuggestion

    context = {
        "target": state.target,
        "domain": state.domain,
        "new_user": "bloodtrail",
        "new_pass": "B1oodTr@il123!",
    }

    steps = []
    for i, step in enumerate(chain.steps, 1):
        # Fill template with available context
        try:
            cmd = step.command_template.format(**context)
        except KeyError:
            cmd = step.command_template

        steps.append(CommandSuggestion(
            command_id=f"chain_{chain.id}_{step.id}",
            name=step.name,
            context=step.why[:100] if step.why else "",  # Truncate for display
            template=step.command_template,
            ready_to_run=cmd,
            variables_needed=step.required_vars,
            oscp_relevance="high"
        ))

    return AttackSequence(
        name=f"[DETECTED] {chain.name}",
        description=chain.description,
        path_nodes=[],
        edge_types=chain.required_finding_tags,
        steps=steps
    )


def _detect_dynamic_chains(
    runner: 'QueryRunner',
    pwned_lookup: Dict[str, any],
    dc_ip: Optional[str] = None,
) -> List:
    """
    Detect viable attack chains from BloodHound findings.

    Analyzes pwned users against BloodHound data to detect multi-step
    privilege escalation paths (e.g., Exchange WriteDACL → DCSync).

    Args:
        runner: QueryRunner with Neo4j connection
        pwned_lookup: Dict of pwned users (username -> PwnedUser)
        dc_ip: Domain Controller IP for command generation

    Returns:
        List of AttackSequence objects for display
    """
    try:
        from .recommendation import (
            BloodHoundAnalyzer,
            ChainDetector,
            AttackState,
        )

        if not runner.driver:
            return []

        # Get domain from BloodHound
        domain = None
        try:
            with runner.driver.session() as session:
                result = session.run("MATCH (d:Domain) RETURN d.name LIMIT 1")
                record = result.single()
                if record:
                    domain = record["d.name"]
        except Exception:
            return []

        if not domain:
            return []

        # Analyze for each pwned user
        analyzer = BloodHoundAnalyzer()
        all_findings = []

        for username in pwned_lookup.keys():
            # Extract sAMAccountName from UPN (e.g., "SVC-ALFRESCO@HTB.LOCAL" -> "svc-alfresco")
            sam = username.split("@")[0] if "@" in username else username
            findings = analyzer.analyze_attack_paths(sam, domain)
            all_findings.extend(findings)

        if not all_findings:
            return []

        # Build state and detect chains
        state = AttackState(target=dc_ip or "<DC_IP>", domain=domain)
        for finding in all_findings:
            state.add_finding(finding)

        # Add credentials from pwned users
        for username, pwned in pwned_lookup.items():
            if hasattr(pwned, 'password') and pwned.password:
                state.add_credential(
                    username=username,
                    password=pwned.password,
                    validated=True
                )

        detector = ChainDetector(state)
        viable_chains = detector.detect_viable_chains()

        # Convert to AttackSequence format for display
        return [_chain_to_sequence(chain, state) for chain in viable_chains]

    except Exception:
        return []  # Silent fail - don't break report generation


def export_to_bloodhound_ce(
    runner: 'QueryRunner',
    output_path: Optional[Path] = None,
    category_filter: Optional[str] = None,
    oscp_high_only: bool = False,
    create_zip: bool = True
) -> str:
    """
    Export queries to BloodHound CE format (JSON array or ZIP).

    BloodHound CE requires this schema (from SpecterOps Query Library):
    {
        "name": "Query Name",
        "description": "Description",
        "query": "MATCH..."
    }

    Can be uploaded via: Explore > Cypher > Saved Queries > drag-and-drop

    Args:
        runner: QueryRunner instance with loaded queries
        output_path: Path to save file (default: ./crack_queries.zip or .json)
        category_filter: Only export queries from this category
        oscp_high_only: Only export OSCP:HIGH queries
        create_zip: Create ZIP file for easier upload (default: True)

    Returns:
        Path where file was saved
    """
    queries = runner.list_queries(category=category_filter)

    if oscp_high_only:
        queries = [q for q in queries if q.oscp_relevance == "high"]

    # Short category codes for concise naming
    category_short = {
        "lateral_movement": "LM",
        "quick_wins": "QW",
        "privilege_escalation": "PE",
        "attack_chains": "AC",
        "operational": "OP",
        "owned_principal": "OWN",
    }

    # Short relevance codes
    relevance_short = {"high": "H", "medium": "M", "low": "L"}

    # Build BloodHound CE format (simple: query, name, description)
    ce_queries = []

    for query in queries:
        cat_code = category_short.get(query.category, query.category[:3].upper())
        rel_code = relevance_short.get(query.oscp_relevance, "M")

        # Concise name: [CAT:REL] Query Name
        if query.has_variables():
            var_hint = ",".join(query.variables.keys())
            name = f"[{cat_code}:{rel_code}] {query.name} <{var_hint}>"
        else:
            name = f"[{cat_code}:{rel_code}] {query.name}"

        ce_queries.append({
            "query": query.cypher,
            "name": name,
            "description": query.description
        })

    # Determine output path
    if output_path is None:
        ext = ".zip" if create_zip else ".json"
        output_path = Path.cwd() / f"crack_queries{ext}"
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if create_zip:
        # Create ZIP with individual JSON files (one query per file)
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for i, q in enumerate(ce_queries):
                # Create safe filename from query name
                safe_name = q["name"][:60].replace("/", "-").replace("\\", "-")
                safe_name = re.sub(r'[<>:"|?*\[\]]', '', safe_name).strip()
                filename = f"{i+1:02d}_{safe_name}.json"

                # Write single query object (not array)
                json_content = json.dumps(q, indent=2)
                zf.writestr(filename, json_content)
    else:
        # Write as array for non-zip (backwards compat)
        with open(output_path, "w") as f:
            json.dump(ce_queries, f, indent=2)

    return str(output_path)
