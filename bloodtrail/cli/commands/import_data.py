"""
BloodTrail Import Data Commands

Handles BloodHound data import and related commands:
- bh_data_dir: Import BloodHound data from directory or ZIP
- --resume: Work with existing Neo4j data
- --validate: Validate BloodHound data
- --list-edges: List supported edge types
"""

import os
from argparse import Namespace
from pathlib import Path

from ..base import BaseCommandGroup
from ..parser import InputMode, detect_input_mode
from ...config import Neo4jConfig, ATTACK_PATH_EDGES
from ...data_source import is_valid_bloodhound_source, create_data_source
from ...main import BHEnhancer
from ...query_runner import QueryRunner
from ...pwned_tracker import PwnedTracker
from ...report_generator import run_all_queries


class ImportDataCommands(BaseCommandGroup):
    """BloodHound data import command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add import data arguments."""
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle import data commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        if getattr(args, 'list_edges', False):
            return cls._handle_list_edges(args)

        if getattr(args, 'resume', False):
            return cls._handle_resume(args)

        # Check if bh_data_dir is a BloodHound data source (directory or ZIP)
        bh_data_dir = getattr(args, 'bh_data_dir', None)
        if bh_data_dir is not None:
            mode, target = detect_input_mode(str(bh_data_dir))
            if mode == InputMode.BLOODHOUND:
                return cls.run_import_mode(args)

        return -1

    @classmethod
    def _handle_list_edges(cls, args: Namespace) -> int:
        """Handle --list-edges command."""
        print("Supported Edge Types:")
        print()
        print("Computer Access:")
        for e in ["AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM", "HasSession", "AllowedToAct"]:
            marker = "*" if e in ATTACK_PATH_EDGES else " "
            print(f"  {marker} {e}")
        print()
        print("ACL-Based:")
        for e in ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
                  "ForceChangePassword", "AddKeyCredentialLink", "AllExtendedRights"]:
            marker = "*" if e in ATTACK_PATH_EDGES else " "
            print(f"  {marker} {e}")
        print()
        print("DCSync Rights:")
        for e in ["GetChanges", "GetChangesAll", "GetChangesInFilteredSet"]:
            marker = "*" if e in ATTACK_PATH_EDGES else " "
            print(f"  {marker} {e}")
        print()
        print("Membership:")
        for e in ["MemberOf"]:
            marker = "*" if e in ATTACK_PATH_EDGES else " "
            print(f"  {marker} {e}")
        print()
        print("Delegation:")
        for e in ["AllowedToDelegate"]:
            marker = "*" if e in ATTACK_PATH_EDGES else " "
            print(f"  {marker} {e}")
        print()
        print("* = Included in 'attack-paths' preset")
        return 0

    @classmethod
    def _handle_resume(cls, args: Namespace) -> int:
        """Handle --resume command - work with existing Neo4j data."""
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))

        # Connect and verify data exists
        runner = QueryRunner(config)
        if not runner.connect():
            cls.print_error("Could not connect to Neo4j")
            print("    Ensure Neo4j is running: sudo neo4j start")
            return 1

        # Check if Neo4j has data
        try:
            with runner.driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) as total")
                total_nodes = result.single()["total"]

                if total_nodes == 0:
                    cls.print_error("No data found in Neo4j database")
                    print()
                    print("    To import BloodHound data, run:")
                    print("      crack bt /path/to/bloodhound/json/")
                    print()
                    runner.close()
                    return 1
        except Exception as e:
            cls.print_error(f"Error checking Neo4j data: {e}")
            runner.close()
            return 1

        # Display nice banner
        C = "\033[96m"  # Cyan
        Y = "\033[93m"  # Yellow
        B = "\033[1m"   # Bold
        D = "\033[2m"   # Dim
        R = "\033[0m"   # Reset

        print()
        print(f"{C}{B}{'=' * 74}{R}")
        print(f"{C}{B}  BloodHound Trail - Resume Mode (Existing Data){R}")
        print(f"{C}{B}{'=' * 74}{R}")
        print()
        print(f"  {D}Neo4j endpoint:{R}  {B}{args.uri}{R}")
        print(f"  {D}Nodes in DB:{R}     {B}{total_nodes}{R}")
        print()

        # Get stored DC IP from domain config
        dc_ip = None
        try:
            tracker = PwnedTracker(config)
            if tracker.connect():
                domain_config = tracker.get_domain_config()
                dc_ip = domain_config.get("dc_ip") if domain_config else None
                tracker.close()
        except Exception:
            pass

        # Run all queries (auto-generate report)
        high_only = getattr(args, 'oscp_high_only', False)

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

            # Auto-run attack vector detection (integrated flow)
            cls._run_attack_detection(runner.driver.session(), dc_ip)
        finally:
            runner.close()

        return 0 if stats["failed"] == 0 else 1

    @classmethod
    def run_import_mode(cls, args: Namespace) -> int:
        """
        Run BloodHound data import mode.

        This is the main entry point for importing BloodHound data
        from directories or ZIP files.
        """
        # Validate data source (directory or ZIP file)
        is_valid, message = is_valid_bloodhound_source(args.bh_data_dir)
        if not is_valid:
            cls.print_error(message)
            return 1

        # Create data source to get file count for display
        try:
            data_source = create_data_source(args.bh_data_dir)
            json_files = data_source.list_json_files()
            source_type = data_source.source_type
        except Exception as e:
            cls.print_error(f"Failed to read data source: {e}")
            return 1

        # Create config
        config = Neo4jConfig(
            uri=args.uri,
            user=args.user,
            password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""),
            batch_size=getattr(args, 'batch_size', 1000),
        )

        # Create enhancer
        enhancer = BHEnhancer(args.bh_data_dir, config)

        # Handle --validate
        if getattr(args, 'validate', False):
            return cls._run_validate(enhancer, args)

        # Determine edge filter
        edge_filter = None
        preset = None

        if getattr(args, 'edges', None):
            edge_filter = set(args.edges.split(","))
            cls.print_info(f"Filtering to edge types: {', '.join(edge_filter)}")
        elif getattr(args, 'preset', None) == "attack-paths":
            preset = "attack-paths"
        # else: preset=None means all edges

        # Run enhancement with colorized banner
        C = "\033[96m"  # Cyan
        G = "\033[92m"  # Green
        Y = "\033[93m"  # Yellow
        B = "\033[1m"   # Bold
        D = "\033[2m"   # Dim
        R = "\033[0m"   # Reset

        print()
        print(f"{C}{B}{'=' * 74}{R}")
        print(f"{C}{B}  BloodHound Trail - Edge Enhancement & Attack Path Discovery{R}")
        print(f"{C}{B}{'=' * 74}{R}")
        print()
        source_label = "ZIP file:" if source_type == "zip" else "Data directory:"
        print(f"  {D}{source_label:16}{R} {B}{args.bh_data_dir}{R}")
        print(f"  {D}Neo4j endpoint:{R}  {B}{args.uri}{R}")
        print(f"  {D}JSON files:{R}      {B}{len(json_files)}{R} files found")
        print()

        stats = enhancer.run(
            preset=preset,
            edge_filter=edge_filter,
            dry_run=getattr(args, 'dry_run', False),
            verbose=getattr(args, 'verbose', 0),
            dc_ip=getattr(args, 'dc_ip', None),
            clean_ips=not getattr(args, 'update', False),
            import_properties=not getattr(args, 'no_properties', False),
            properties_only=getattr(args, 'properties_only', False),
        )

        # Check if we should run the report
        total_processed = stats.edges_imported + stats.edges_already_existed
        should_run_report = (
            total_processed > 0
            and not getattr(args, 'dry_run', False)
            and not getattr(args, 'no_report', False)
            and not stats.errors
        )

        if should_run_report:
            return cls._run_report(args, config, stats, source_type, total_processed)

        elif getattr(args, 'dry_run', False):
            print(f"{D}[*] Dry run - skipping report generation{R}")
        elif getattr(args, 'no_report', False):
            print(f"{D}[*] Report generation skipped (--no-report){R}")
        elif total_processed == 0 and not stats.errors:
            print(f"{Y}[!]{R} No edges were processed. Run with --verbose for details.")

        # Return code based on errors
        if stats.errors:
            return 1
        return 0

    @classmethod
    def _run_validate(cls, enhancer: BHEnhancer, args: Namespace) -> int:
        """Run validation mode."""
        cls.print_info(f"Validating BloodHound data in {args.bh_data_dir}...")
        summary = enhancer.validate(verbose=getattr(args, 'verbose', 0))

        if "error" in summary:
            cls.print_error(summary['error'])
            return 1

        print(f"\n=== Validation Summary ===")
        print(f"Total edges:     {summary['total_edges']}")
        print(f"Edge types:      {len(summary['edges_by_type'])}")
        print(f"SIDs resolved:   {summary['resolver_stats']['cache_size']}")
        print(f"SIDs unresolved: {summary['resolver_stats']['unresolved']}")

        if getattr(args, 'verbose', 0):
            print(f"\nEdges by type:")
            for etype, count in sorted(summary['edges_by_type'].items()):
                print(f"  {etype}: {count}")

            if summary['resolver_stats']['unresolved_sids']:
                print(f"\nUnresolved SIDs (first 10):")
                for sid in summary['resolver_stats']['unresolved_sids']:
                    print(f"  {sid}")

        return 0

    @classmethod
    def _run_report(
        cls,
        args: Namespace,
        config: Neo4jConfig,
        stats,
        source_type: str,
        total_processed: int
    ) -> int:
        """Generate report after import."""
        C = "\033[96m"  # Cyan
        G = "\033[92m"  # Green
        Y = "\033[93m"  # Yellow
        B = "\033[1m"   # Bold
        D = "\033[2m"   # Dim
        R = "\033[0m"   # Reset

        print()
        print(f"{C}{B}{'=' * 74}{R}")
        print(f"{C}{B}  Running Attack Path Queries - Generating Report{R}")
        print(f"{C}{B}{'=' * 74}{R}")
        print()

        runner = QueryRunner(config)
        if runner.connect():
            try:
                # For ZIP files, put report next to ZIP; for directories, inside
                bh_data_path = Path(args.bh_data_dir)
                if getattr(args, 'report_path', None):
                    report_path = args.report_path
                elif source_type == "zip":
                    report_path = bh_data_path.parent / "bloodtrail.md"
                else:
                    report_path = bh_data_path / "bloodtrail.md"

                # Get DC IP from args (if provided) or from stored domain config
                dc_ip_for_report = getattr(args, 'dc_ip', None)
                if not dc_ip_for_report:
                    try:
                        tracker = PwnedTracker(config)
                        if tracker.connect():
                            domain_config = tracker.get_domain_config()
                            dc_ip_for_report = domain_config.get("dc_ip") if domain_config else None
                            tracker.close()
                    except Exception:
                        pass

                report_stats = run_all_queries(
                    runner,
                    output_path=report_path,
                    skip_variable_queries=True,
                    oscp_high_only=False,
                    verbose=getattr(args, 'verbose', 0),
                    show_commands=getattr(args, 'commands', False),
                    show_data=getattr(args, 'data', False),
                    dc_ip=dc_ip_for_report,
                )

                # Final summary
                print(f"{C}{B}{'=' * 74}{R}")
                print(f"{C}{B}  BloodHound Trail Complete{R}")
                print(f"{C}{B}{'=' * 74}{R}")
                print()
                print(f"  {D}Edges processed:{R}    {B}{total_processed}{R} ({stats.edges_imported} new, {stats.edges_already_existed} existed)")
                print(f"  {D}Queries with hits:{R}  {B}{report_stats['with_results']}{R} / {report_stats['total_queries']}")
                print(f"  {D}Report saved:{R}       {B}{report_path}{R}")
                print()

                if report_stats['findings']:
                    high_findings = [f for f in report_stats['findings'] if f['relevance'] == 'high']
                    if high_findings:
                        print(f"  {G}{B}Top Attack Paths Discovered:{R}")
                        for f in sorted(high_findings, key=lambda x: -x['count'])[:5]:
                            print(f"     {Y}>{R} {f['query']}: {B}{f['count']}{R} results")
                        print()

                # Auto-run attack vector detection (integrated flow)
                cls._run_attack_detection(runner.driver.session(), dc_ip_for_report)

            finally:
                runner.close()
        else:
            print(f"{Y}[!]{R} Could not connect to Neo4j for report generation")
            print(f"    Run manually: crack bloodtrail --run-all")

        # Return code based on errors
        if stats.errors:
            return 1
        return 0

    @classmethod
    def _run_attack_detection(cls, session, dc_ip: str = None) -> None:
        """
        Automatically run attack vector detection on BloodHound data.

        This provides automated detection without requiring --detect flag.
        Detects: Azure AD Connect, GPP passwords, LAPS, and prioritizes service accounts.
        """
        from ...core.detection import get_default_registry as get_detector_registry
        from ...core.service_accounts import ServiceAccountAnalyzer, AttackVector

        # Colors
        C = "\033[96m"   # Cyan
        G = "\033[92m"   # Green
        Y = "\033[93m"   # Yellow
        R = "\033[91m"   # Red
        B = "\033[1m"    # Bold
        D = "\033[2m"    # Dim
        X = "\033[0m"    # Reset

        # Get users and groups from BloodHound
        try:
            result = session.run("""
                MATCH (u:User)
                RETURN u.name AS name, u.description AS description,
                       u.hasspn AS spn, u.dontreqpreauth AS dontreqpreauth
                LIMIT 1000
            """)
            users = [dict(r) for r in result]

            result = session.run("""
                MATCH (g:Group)
                OPTIONAL MATCH (u:User)-[:MemberOf*1..]->(g)
                RETURN g.name AS name, collect(DISTINCT u.name)[..20] AS members
                LIMIT 500
            """)
            groups = [dict(r) for r in result]

            # Get domain from data
            result = session.run("MATCH (d:Domain) RETURN d.name AS name LIMIT 1")
            domain_record = result.single()
            domain = domain_record["name"] if domain_record else "DOMAIN"

        except Exception as e:
            # Silently skip if query fails
            return

        if not users:
            return

        context = {
            "target_ip": dc_ip or "<DC_IP>",
            "domain": domain,
        }

        # Run attack vector detection
        registry = get_detector_registry()
        detections = registry.detect_all_ldap(users, groups, [], context)

        # Run service account analysis
        analyzer = ServiceAccountAnalyzer()
        svc_result = analyzer.analyze_from_bloodhound(session, context)

        # Check for password-in-description
        pwd_in_desc = [a for a in svc_result.all_accounts if AttackVector.PASSWORD_IN_DESC in a.attack_vectors]

        # Only show section if we have findings
        has_detections = bool(detections)
        has_critical_svc = bool(pwd_in_desc or svc_result.critical or svc_result.high)

        if not has_detections and not has_critical_svc:
            if svc_result.all_accounts:
                print(f"  {D}Service accounts detected:{X} {B}{len(svc_result.all_accounts)}{X} {D}(use --analyze-svc for details){X}")
            return

        print()
        print(f"{C}{B}{'=' * 74}{X}")
        print(f"{C}{B}  ATTACK VECTOR DETECTION (Auto-Scan){X}")
        print(f"{C}{B}{'=' * 74}{X}")
        print()

        # Show detections
        if detections:
            for detection in detections:
                confidence_colors = {
                    "confirmed": G,
                    "likely": Y,
                    "possible": C,
                }
                color = confidence_colors.get(detection.confidence.value, X)

                print(f"  {color}{B}[{detection.confidence.value.upper()}] {detection.name}{X}")
                print(f"  {D}{'─' * 60}{X}")

                for evidence in detection.evidence[:3]:
                    print(f"    • {evidence}")

                if detection.attack_commands:
                    cmd = detection.attack_commands[0]
                    print(f"\n    {G}$ {cmd.command}{X}")
                    if cmd.explanation:
                        print(f"    {D}Why: {cmd.explanation[:80]}...{X}")

                print()

        # Show service account findings
        if pwd_in_desc:
            print(f"  {R}{B}PASSWORD IN DESCRIPTION ({len(pwd_in_desc)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for account in pwd_in_desc[:5]:
                print(f"    {R}{account.name}{X}")
                print(f"      {D}Attack: {account.attack_suggestion}{X}")
            print()

        if svc_result.critical:
            print(f"  {R}{B}CRITICAL SERVICE ACCOUNTS ({len(svc_result.critical)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for account in svc_result.critical[:5]:
                vectors = ", ".join(v.value for v in account.attack_vectors)
                print(f"    {R}{account.name}{X} - {vectors}")
            print()

        if svc_result.high:
            print(f"  {Y}{B}HIGH PRIORITY SERVICE ACCOUNTS ({len(svc_result.high)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for account in svc_result.high[:5]:
                vectors = ", ".join(v.value for v in account.attack_vectors)
                print(f"    {Y}{account.name}{X} - {vectors}")
            if len(svc_result.high) > 5:
                print(f"    {D}... and {len(svc_result.high) - 5} more{X}")
            print()

        # Show next steps
        all_next_steps = []
        for detection in detections:
            if detection.attack_commands:
                for cmd in detection.attack_commands[:1]:
                    all_next_steps.append({
                        "command": cmd.command,
                        "explanation": cmd.explanation or cmd.description,
                    })
        all_next_steps.extend(svc_result.next_steps[:2])

        if all_next_steps:
            print(f"  {B}RECOMMENDED ACTIONS{X}")
            print(f"  {D}{'─' * 60}{X}")
            for step in all_next_steps[:5]:
                print(f"    {G}$ {step['command']}{X}")
                if step.get('explanation'):
                    print(f"      {D}{step['explanation'][:80]}{X}")
            print()
