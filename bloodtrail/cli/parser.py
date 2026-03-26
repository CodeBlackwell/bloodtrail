"""
BloodTrail CLI Parser

Argument parser creation with input mode detection.
Extracted from cli.py for modularity.
"""

import argparse
import ipaddress
from enum import Enum
from pathlib import Path
from typing import Tuple


class InputMode(Enum):
    """Mode determined by input type."""
    ENUMERATE = "enumerate"   # IP address -> run live enumeration
    BLOODHOUND = "bloodhound" # Directory/ZIP -> parse BloodHound data


def detect_input_mode(input_arg: str) -> Tuple[InputMode, str]:
    """
    Detect mode based on input argument.

    Returns:
        (mode, normalized_input)

    - IP address -> ENUMERATE mode
    - Existing directory/ZIP -> BLOODHOUND mode
    - Hostname with dots -> ENUMERATE mode

    Raises:
        ValueError: If input cannot be classified
    """
    # Try IP address first (most specific)
    try:
        ipaddress.ip_address(input_arg)
        return (InputMode.ENUMERATE, input_arg)
    except ValueError:
        pass

    # Try as path
    path = Path(input_arg)
    if path.exists():
        if path.is_dir() or path.suffix.lower() == '.zip':
            return (InputMode.BLOODHOUND, str(path))

    # Could be hostname for enumerate mode (e.g., dc.corp.local)
    if '.' in input_arg and not path.exists():
        return (InputMode.ENUMERATE, input_arg)

    raise ValueError(f"Cannot determine mode for input: {input_arg}")


def create_parser() -> argparse.ArgumentParser:
    """
    Create the main argument parser with all argument groups.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog="bloodtrail",
        description="BloodHound Trail - Edge enhancement and Neo4j query analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import edges + auto-generate report with all queries (default)
  crack bloodtrail /path/to/bh/json/

  # Show commands in console (report still saved to file)
  crack bloodtrail /path/to/bh/json/ -c

  # Attack-path focused edges only (recommended)
  crack bloodtrail /path/to/bh/json/ --preset attack-paths

  # Dry run (validate without importing)
  crack bloodtrail /path/to/bh/json/ --dry-run --verbose

  # Skip report generation (edges only)
  crack bloodtrail /path/to/bh/json/ --no-report

  # Run queries against existing Neo4j data (no import)
  crack bloodtrail --run-all

  # Resume with existing Neo4j data (quick shortcut)
  crack bloodtrail -r
  crack bloodtrail --resume

Supported Edge Types:
  Computer Access: AdminTo, CanPSRemote, CanRDP, ExecuteDCOM, HasSession
  ACL Abuse:       GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns
  DCSync:          GetChanges, GetChangesAll
  Membership:      MemberOf
  Delegation:      AllowedToDelegate, AllowedToAct
        """,
    )

    # Positional (optional for query commands)
    parser.add_argument(
        "bh_data_dir",
        type=Path,
        nargs="?",
        default=None,
        help="Directory or ZIP file containing BloodHound JSON exports",
    )

    # Add argument groups
    _add_wizard_options(parser)  # Add wizard mode early for discoverability
    _add_filter_options(parser)
    _add_neo4j_options(parser)
    _add_behavior_options(parser)
    _add_enumerate_options(parser)
    _add_property_options(parser)
    _add_info_options(parser)
    _add_query_options(parser)
    _add_pwned_options(parser)
    _add_config_options(parser)
    _add_policy_options(parser)
    _add_spray_options(parser)
    _add_creds_pipeline_options(parser)
    _add_analyze_options(parser)

    return parser


def _add_wizard_options(parser: argparse.ArgumentParser) -> None:
    """Add wizard mode options."""
    wizard_group = parser.add_argument_group("Wizard Mode (Guided Interface)")
    wizard_group.add_argument(
        "--wizard",
        action="store_true",
        help="Launch guided wizard mode for first-time users (step-by-step enumeration)",
    )
    wizard_group.add_argument(
        "--wizard-resume",
        type=str,
        metavar="TARGET",
        help="Resume wizard session from saved checkpoint (use target IP/hostname)",
    )
    wizard_group.add_argument(
        "--wizard-target",
        type=str,
        metavar="TARGET",
        help="Target IP/hostname for wizard mode (alternative to positional arg)",
    )


def _add_filter_options(parser: argparse.ArgumentParser) -> None:
    """Add preset/filter options."""
    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument(
        "--preset",
        choices=["attack-paths", "all"],
        default="attack-paths",
        help="Edge preset: 'attack-paths' (default) or 'all'",
    )
    filter_group.add_argument(
        "--edges",
        type=str,
        help="Comma-separated list of specific edge types to import",
    )


def _add_neo4j_options(parser: argparse.ArgumentParser) -> None:
    """Add Neo4j connection options."""
    parser.add_argument(
        "-r", "--resume",
        action="store_true",
        help="Resume from existing Neo4j data (skip edge import)",
    )
    parser.add_argument(
        "--uri",
        default="bolt://localhost:7687",
        help="Neo4j URI (default: bolt://localhost:7687)",
    )
    parser.add_argument(
        "--user",
        default="neo4j",
        help="Neo4j username (default: neo4j)",
    )
    parser.add_argument(
        "--neo4j-password",
        dest="neo4j_password",
        default=None,
        help="Neo4j password (default: from NEO4J_PASSWORD env var)",
    )


def _add_behavior_options(parser: argparse.ArgumentParser) -> None:
    """Add behavior options."""
    parser.add_argument(
        "--debug",
        type=str,
        nargs="?",
        const="all",
        default=None,
        metavar="FILTER",
        help="Enable debug logging. Optional filter: 'all', component (bloodtrail, bt_neo4j), "
             "or step type (querying, connection). Comma-separate multiple filters.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Extract and validate without importing to Neo4j",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v: streaming output + commands, -vv: debug info)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet mode (minimal output)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Edges per batch (default: 500)",
    )
    parser.add_argument(
        "--dc-ip",
        type=str,
        metavar="IP",
        help="Set DC IP for DNS resolution and command auto-population",
    )


def _add_enumerate_options(parser: argparse.ArgumentParser) -> None:
    """Add enumerate mode credential options."""
    cred_group = parser.add_argument_group("Enumerate Mode Credentials")
    cred_group.add_argument(
        "-u", "--ad-username",
        type=str,
        metavar="USER",
        help="AD username for authenticated enumeration",
    )
    cred_group.add_argument(
        "-p", "--ad-password",
        type=str,
        metavar="PASS",
        help="AD password for authenticated enumeration",
    )
    cred_group.add_argument(
        "--domain",
        type=str,
        metavar="DOMAIN",
        help="Domain name (auto-detected if not provided)",
    )
    cred_group.add_argument(
        "--list-enumerators",
        action="store_true",
        help="List available enumeration tools and exit",
    )
    cred_group.add_argument(
        "--asrep-file",
        type=Path,
        metavar="FILE",
        help="Username file for AS-REP roasting spray (one username per line)",
    )
    cred_group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode: guided recommendations one at a time",
    )

    # Auto-execute mode options
    auto_group = parser.add_argument_group("Auto-Execute Mode")
    auto_group.add_argument(
        "--auto",
        action="store_true",
        help="Auto-execute recommendations (recon/enum/cred tests, pauses before shells)",
    )
    auto_group.add_argument(
        "--auto-level",
        type=str,
        choices=["critical", "high", "medium"],
        default="high",
        help="Minimum priority to auto-execute (default: high)",
    )
    auto_group.add_argument(
        "--cred",
        type=str,
        action="append",
        metavar="USER:PASS",
        help="Inject credential for resume (can be repeated)",
    )
    auto_group.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum credential chain depth (default: 5)",
    )
    auto_group.add_argument(
        "--cmd-timeout",
        type=int,
        default=180,
        help="Command timeout in seconds (default: 180)",
    )

    # Persistence options
    persist_group = parser.add_argument_group("Data Persistence")
    persist_group.add_argument(
        "--no-prism",
        action="store_true",
        help="Disable data persistence (standalone mode). Results display only, no SQLite/Neo4j writes.",
    )


def _add_property_options(parser: argparse.ArgumentParser) -> None:
    """Add property import options."""
    prop_group = parser.add_mutually_exclusive_group()
    prop_group.add_argument(
        "--no-properties",
        action="store_true",
        help="Skip property import (edges only)",
    )
    prop_group.add_argument(
        "--properties-only",
        action="store_true",
        help="Import properties without edges",
    )

    # IP refresh mode
    ip_group = parser.add_mutually_exclusive_group()
    ip_group.add_argument(
        "--clean",
        action="store_true",
        help="Clear all IPs before regenerating (default)",
    )
    ip_group.add_argument(
        "--update",
        action="store_true",
        help="Incremental update - keep existing IPs",
    )


def _add_info_options(parser: argparse.ArgumentParser) -> None:
    """Add info options."""
    parser.add_argument(
        "--list-edges",
        action="store_true",
        help="List all supported edge types and exit",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate data and show summary without importing",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip automatic report generation",
    )


def _add_query_options(parser: argparse.ArgumentParser) -> None:
    """Add query library options."""
    query_group = parser.add_argument_group("Query Library")
    query_group.add_argument(
        "--list-queries",
        action="store_true",
        help="List all available Cypher queries",
    )
    query_group.add_argument(
        "--category",
        type=str,
        choices=["lateral_movement", "quick_wins", "privilege_escalation",
                 "attack_chains", "operational", "owned_principal"],
        help="Filter queries by category",
    )
    query_group.add_argument(
        "--run-query",
        type=str,
        metavar="QUERY_ID",
        help="Run a specific query by ID",
    )
    query_group.add_argument(
        "--var",
        type=str,
        action="append",
        metavar="NAME=VALUE",
        help="Set query variable (e.g., --var USER=PETE@CORP.COM)",
    )
    query_group.add_argument(
        "--search-query",
        type=str,
        metavar="KEYWORD",
        help="Search queries by keyword",
    )
    query_group.add_argument(
        "--export-query",
        type=str,
        metavar="QUERY_ID",
        help="Export query as raw Cypher for BloodHound paste",
    )
    query_group.add_argument(
        "--output-format",
        type=str,
        choices=["table", "json", "cypher"],
        default="table",
        help="Output format for query results (default: table)",
    )
    query_group.add_argument(
        "--install-queries",
        action="store_true",
        help="Install queries to BloodHound Legacy customqueries.json",
    )
    query_group.add_argument(
        "--export-ce",
        action="store_true",
        help="Export queries as ZIP for BloodHound CE",
    )
    query_group.add_argument(
        "--export-ce-json",
        action="store_true",
        help="Export queries as JSON for BloodHound CE",
    )
    query_group.add_argument(
        "--install-path",
        type=Path,
        help="Custom output path for exported queries",
    )
    query_group.add_argument(
        "--oscp-high-only",
        action="store_true",
        help="Only export OSCP:HIGH relevance queries",
    )
    query_group.add_argument(
        "--run-all",
        action="store_true",
        help="Run all queries against existing Neo4j data",
    )
    query_group.add_argument(
        "--report-path",
        type=Path,
        help="Custom path for report output (default: ./bloodtrail.md)",
    )
    query_group.add_argument(
        "--commands", "-c",
        action="store_true",
        help="Only print command suggestions to console",
    )
    query_group.add_argument(
        "--data", "-d",
        action="store_true",
        help="Only print raw query data to console",
    )


def _add_pwned_options(parser: argparse.ArgumentParser) -> None:
    """Add pwned user tracking options."""
    pwned_group = parser.add_argument_group("Pwned User Tracking")
    pwned_group.add_argument(
        "--pwn-interactive", "-pi",
        action="store_true",
        help="Interactively input credential information",
    )
    pwned_group.add_argument(
        "--pwn",
        type=str,
        metavar="USER",
        help="Mark user as pwned (e.g., PETE@CORP.COM)",
    )
    pwned_group.add_argument(
        "--unpwn",
        type=str,
        metavar="USER",
        help="Unmark user as pwned",
    )
    pwned_group.add_argument(
        "--list-pwned", "-lp",
        action="store_true",
        help="List all pwned users with access paths",
    )
    pwned_group.add_argument(
        "--cred-type",
        type=str,
        choices=["password", "ntlm-hash", "kerberos-ticket", "certificate"],
        help="Credential type for --pwn",
    )
    pwned_group.add_argument(
        "--cred-value",
        type=str,
        metavar="VALUE",
        help="Credential value for --pwn",
    )
    pwned_group.add_argument(
        "--source-machine",
        type=str,
        metavar="MACHINE",
        help="Machine where credential was obtained",
    )
    pwned_group.add_argument(
        "--pwn-notes",
        type=str,
        metavar="NOTES",
        help="Notes about compromise method",
    )
    pwned_group.add_argument(
        "--cred-targets",
        action="store_true",
        help="Show high-value credential harvest targets",
    )
    pwned_group.add_argument(
        "--pwned-user",
        type=str,
        metavar="USER",
        help="Show details for specific pwned user",
    )
    pwned_group.add_argument(
        "--post-exploit", "-pe",
        action="store_true",
        help="Show post-exploitation commands for pwned users",
    )
    pwned_group.add_argument(
        "--recommend", "-rec",
        action="store_true",
        help="Recommend attack paths based on pwned users",
    )
    pwned_group.add_argument(
        "--list-ip-addresses", "-lip",
        action="store_true",
        help="List all machines with resolved IP addresses",
    )


def _add_config_options(parser: argparse.ArgumentParser) -> None:
    """Add domain configuration options."""
    config_group = parser.add_argument_group("Domain Configuration")
    config_group.add_argument(
        "--set-dc-ip",
        type=str,
        metavar="IP",
        help="[DEPRECATED] Use --dc-ip instead",
    )
    config_group.add_argument(
        "--set-dc-hostname",
        type=str,
        metavar="HOSTNAME",
        help="Store DC hostname",
    )
    config_group.add_argument(
        "--domain-sid", "-ds",
        type=str,
        metavar="SID",
        help="Store Domain SID for ticket auto-population",
    )
    config_group.add_argument(
        "--show-config",
        action="store_true",
        help="Show stored domain configuration",
    )
    config_group.add_argument(
        "--clear-config",
        action="store_true",
        help="Clear stored domain configuration",
    )
    config_group.add_argument(
        "--purge",
        action="store_true",
        help="Purge ALL data from Neo4j database",
    )
    config_group.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompts",
    )
    config_group.add_argument(
        "--discover-dc",
        nargs='*',
        metavar=('USER', 'PASSWORD'),
        help="Discover DC IP using BloodHound + crackmapexec",
    )
    config_group.add_argument(
        "--lhost",
        type=str,
        metavar="IP",
        help="Attacker IP for reverse shell callbacks",
    )
    config_group.add_argument(
        "--lport",
        type=int,
        metavar="PORT",
        help="Attacker port for reverse shell callbacks",
    )


def _add_policy_options(parser: argparse.ArgumentParser) -> None:
    """Add password policy options."""
    policy_group = parser.add_argument_group("Password Policy")
    policy_group.add_argument(
        "--set-policy",
        nargs="?",
        const="-",
        metavar="FILE",
        help="Import password policy from 'net accounts' output",
    )
    policy_group.add_argument(
        "--show-policy",
        action="store_true",
        help="Show stored password policy",
    )
    policy_group.add_argument(
        "--clear-policy",
        action="store_true",
        help="Clear stored password policy",
    )


def _add_spray_options(parser: argparse.ArgumentParser) -> None:
    """Add password spray options."""
    spray_group = parser.add_argument_group("Password Spraying")
    spray_group.add_argument(
        "--spray",
        action="store_true",
        help="Show password spray recommendations",
    )
    spray_group.add_argument(
        "--spray-method",
        type=str,
        choices=["smb", "kerberos", "ldap", "all"],
        default="all",
        help="Filter spray methods (default: all)",
    )
    spray_group.add_argument(
        "--spray-tailored",
        action="store_true",
        help="Generate tailored spray commands",
    )
    spray_group.add_argument(
        "--spray-tailored-output",
        type=str,
        metavar="FILE",
        help="Output file for tailored spray report",
    )
    spray_group.add_argument(
        "--auto-spray",
        action="store_true",
        help="Generate auto-spray scripts",
    )
    spray_group.add_argument(
        "--execute",
        action="store_true",
        help="Execute spray commands automatically",
    )
    spray_group.add_argument(
        "--spray-tool",
        type=str,
        choices=["kerbrute", "crackmapexec", "netexec", "hydra", "auto"],
        default="auto",
        help="Spray tool to use (default: auto)",
    )
    spray_group.add_argument(
        "--cred-source",
        type=str,
        action="append",
        choices=["neo4j", "potfile", "wordlist"],
        metavar="SOURCE",
        help="Credential sources",
    )
    spray_group.add_argument(
        "--wordlist",
        type=Path,
        metavar="FILE",
        help="Custom password wordlist file",
    )
    spray_group.add_argument(
        "--potfile",
        type=Path,
        metavar="FILE",
        help="Custom potfile path",
    )
    spray_group.add_argument(
        "--spray-users",
        type=str,
        choices=["all", "enabled", "non-pwned", "custom"],
        default="enabled",
        help="Users to target (default: enabled)",
    )
    spray_group.add_argument(
        "--user-file",
        type=Path,
        metavar="FILE",
        help="Custom user list file",
    )
    spray_group.add_argument(
        "--targets-file",
        type=Path,
        metavar="FILE",
        help="Custom machine targets file",
    )
    spray_group.add_argument(
        "--no-lockout-protection",
        action="store_true",
        help="Disable lockout protection (DANGEROUS)",
    )
    spray_group.add_argument(
        "--spray-output",
        type=Path,
        metavar="DIR",
        help="Output directory for spray scripts",
    )


def _add_creds_pipeline_options(parser: argparse.ArgumentParser) -> None:
    """Add credential integration pipeline options."""
    creds_group = parser.add_argument_group("Credential Integration Pipeline")
    creds_group.add_argument(
        "--creds",
        type=str,
        metavar="CREDS",
        help="Credential string or path to credentials file",
    )
    creds_group.add_argument(
        "--creds-file",
        type=Path,
        metavar="FILE",
        help="Path to credentials file",
    )
    creds_group.add_argument(
        "--use-potfile",
        action="store_true",
        help="Auto-detect and use hashcat/john potfile",
    )
    creds_group.add_argument(
        "--potfile-path",
        type=Path,
        metavar="FILE",
        help="Custom potfile path",
    )
    creds_group.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip credential validation",
    )
    creds_group.add_argument(
        "--no-collect",
        action="store_true",
        help="Skip BloodHound collection",
    )
    creds_group.add_argument(
        "--no-pwn",
        action="store_true",
        help="Skip marking users as pwned",
    )
    creds_group.add_argument(
        "--no-import",
        action="store_true",
        help="Skip Neo4j import of BloodHound data",
    )
    creds_group.add_argument(
        "--bh-output",
        type=Path,
        metavar="DIR",
        help="BloodHound output directory",
    )


def _add_analyze_options(parser: argparse.ArgumentParser) -> None:
    """Add attack analysis options."""
    analyze_group = parser.add_argument_group("Analysis Commands")

    analyze_group.add_argument(
        "--detect",
        action="store_true",
        help="Detect attack vectors (Azure AD Connect, GPP, LAPS)",
    )

    analyze_group.add_argument(
        "--analyze-svc",
        action="store_true",
        help="Analyze service accounts for attack prioritization",
    )

    analyze_group.add_argument(
        "--analyze-reuse",
        metavar="CREDS_FILE",
        help="Analyze password reuse from credentials file",
    )

    analyze_group.add_argument(
        "--crawl-smb",
        metavar="HOST",
        help="Crawl SMB shares for sensitive files (requires -u/-p)",
    )

    analyze_group.add_argument(
        "--share",
        metavar="NAME",
        help="Specific share to crawl (with --crawl-smb)",
    )

    analyze_group.add_argument(
        "--hunt-sqlite",
        metavar="DB_FILE",
        help="Hunt SQLite database for credentials",
    )

    analyze_group.add_argument(
        "--target",
        metavar="IP",
        help="Target IP for credential testing (with --hunt-sqlite)",
    )

    analyze_group.add_argument(
        "--hunt-dotnet",
        metavar="FILE",
        help="Hunt .NET assembly for secrets (exe/dll)",
    )

    analyze_group.add_argument(
        "--parse-deleted",
        metavar="LDIF_FILE",
        help="Parse AD Recycle Bin ldapsearch output for legacy passwords",
    )
