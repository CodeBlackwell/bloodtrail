"""
Subcommand-based CLI router for BloodTrail.

Usage:
    bloodtrail enum 10.10.10.161
    bloodtrail import ./sharphound.zip
    bloodtrail query list
    bloodtrail query run find-asrep
    bloodtrail pwn svc-alfresco@htb.local
    bloodtrail config show
    bloodtrail doctor
    bloodtrail quickwin 10.10.10.161

Old flat-flag syntax (bloodtrail --list-queries) still works via legacy fallback.
"""

import argparse
import sys
from argparse import Namespace
from pathlib import Path

SUBCOMMANDS = {
    "enum", "import", "query", "pwn", "config", "policy",
    "spray", "creds", "analyze", "wizard", "ui", "doctor",
    "quickwin", "ingest", "escalate",
}


def _add_global_opts(parser: argparse.ArgumentParser, skip: set = None) -> None:
    """Flags shared by all subcommands. Use skip= to avoid conflicts with subcommand-specific flags."""
    skip = skip or set()
    opts = {
        "uri": lambda p: p.add_argument("--uri", default=None, help="Neo4j URI"),
        "user": lambda p: p.add_argument("--user", default=None, help="Neo4j username"),
        "neo4j_password": lambda p: p.add_argument("--neo4j-password", dest="neo4j_password", default=None, help="Neo4j password"),
        "debug": lambda p: p.add_argument("--debug", nargs="?", const="all", default=None, help="Debug logging"),
        "verbose": lambda p: p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity"),
        "quiet": lambda p: p.add_argument("-q", "--quiet", action="store_true", help="Minimal output"),
        "limit": lambda p: p.add_argument("--limit", type=int, default=None, help="Max results to display"),
        "dc_ip": lambda p: p.add_argument("--dc-ip", type=str, default=None, help="DC IP address"),
        "domain": lambda p: p.add_argument("--domain", type=str, default=None, help="Domain name"),
        "yes": lambda p: p.add_argument("-y", "--yes", action="store_true", help="Skip confirmations"),
    }
    for key, add_fn in opts.items():
        if key not in skip:
            add_fn(parser)


def _build_enum_parser(sub) -> None:
    p = sub.add_parser("enum", help="Enumerate a target (IP or hostname)")
    p.add_argument("target", help="Target IP or hostname")
    p.add_argument("-u", "--ad-username", type=str, help="AD username")
    p.add_argument("-p", "--ad-password", type=str, help="AD password")
    p.add_argument("--domain", type=str, help="Domain name")
    p.add_argument("--list-enumerators", action="store_true", help="List tools and exit")
    p.add_argument("-i", "--interactive", action="store_true", help="Guided mode")
    p.add_argument("--auto", action="store_true", help="Auto-execute recommendations")
    p.add_argument("--auto-level", choices=["critical", "high", "medium"], default="high")
    p.add_argument("--cred", type=str, action="append", help="Inject credential (USER:PASS)")
    p.add_argument("--max-depth", type=int, default=5, help="Max credential chain depth")
    p.add_argument("--cmd-timeout", type=int, default=180, help="Command timeout (seconds)")
    p.add_argument("--no-prism", action="store_true", help="Disable persistence")
    p.add_argument("--asrep-file", type=Path, help="Username file for AS-REP spray")
    p.add_argument("--creds", type=str, help="Credential string for pipeline")
    p.add_argument("--creds-file", type=Path, help="Credentials file")
    p.add_argument("--use-potfile", action="store_true", help="Use hashcat/john potfile")
    p.add_argument("--skip-validate", action="store_true")
    p.add_argument("--no-collect", action="store_true")
    p.add_argument("--no-pwn", action="store_true")
    p.add_argument("--no-import", action="store_true")
    _add_global_opts(p, skip={"domain"})
    p.set_defaults(_handler=_handle_enum)


def _build_import_parser(sub) -> None:
    p = sub.add_parser("import", help="Import BloodHound data (directory or ZIP)")
    p.add_argument("path", type=Path, help="BloodHound JSON directory or ZIP")
    p.add_argument("--preset", choices=["attack-paths", "all"], default="attack-paths")
    p.add_argument("--edges", type=str, help="Comma-separated edge types")
    p.add_argument("--dry-run", action="store_true", help="Validate without importing")
    p.add_argument("--no-report", action="store_true", help="Skip report generation")
    p.add_argument("--no-properties", action="store_true")
    p.add_argument("--properties-only", action="store_true")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--report-path", type=Path)
    p.add_argument("-c", "--commands", action="store_true", help="Print commands only")
    p.add_argument("-d", "--data", action="store_true", help="Print data only")
    _add_global_opts(p)
    p.set_defaults(_handler=_handle_import)


def _build_query_parser(sub) -> None:
    p = sub.add_parser("query", help="Query library (list, run, search, export)")
    qsub = p.add_subparsers(dest="query_action")

    ls = qsub.add_parser("list", help="List all queries")
    ls.add_argument("--category", type=str, choices=[
        "lateral_movement", "quick_wins", "privilege_escalation",
        "attack_chains", "operational", "owned_principal"])
    _add_global_opts(ls)

    run = qsub.add_parser("run", help="Run a query by ID")
    run.add_argument("query_id", help="Query ID")
    run.add_argument("--var", type=str, action="append", help="NAME=VALUE")
    run.add_argument("--output-format", choices=["table", "json", "cypher"], default="table")
    _add_global_opts(run)

    search = qsub.add_parser("search", help="Search queries by keyword")
    search.add_argument("keyword", help="Search term")
    _add_global_opts(search)

    export = qsub.add_parser("export", help="Export query as raw Cypher")
    export.add_argument("query_id", help="Query ID")
    export.add_argument("--var", type=str, action="append", help="NAME=VALUE")
    _add_global_opts(export)

    run_all = qsub.add_parser("run-all", help="Run all queries and generate report")
    run_all.add_argument("--report-path", type=Path)
    run_all.add_argument("--oscp-high-only", action="store_true")
    run_all.add_argument("-c", "--commands", action="store_true")
    run_all.add_argument("-d", "--data", action="store_true")
    _add_global_opts(run_all)

    install = qsub.add_parser("install", help="Install to BloodHound Legacy")
    install.add_argument("--install-path", type=Path)
    install.add_argument("--category", type=str)
    install.add_argument("--oscp-high-only", action="store_true")
    _add_global_opts(install)

    export_ce = qsub.add_parser("export-ce", help="Export for BloodHound CE")
    export_ce.add_argument("--install-path", type=Path)
    export_ce.add_argument("--category", type=str)
    export_ce.add_argument("--oscp-high-only", action="store_true")
    export_ce.add_argument("--json", dest="ce_json", action="store_true", help="JSON instead of ZIP")
    _add_global_opts(export_ce)

    p.set_defaults(_handler=_handle_query)


def _build_pwn_parser(sub) -> None:
    p = sub.add_parser("pwn", help="Track pwned users and credentials")
    psub = p.add_subparsers(dest="pwn_action")

    mark = psub.add_parser("mark", help="Mark user as pwned")
    mark.add_argument("user", help="Username (e.g., PETE@CORP.COM)")
    mark.add_argument("--cred-type", choices=["password", "ntlm-hash", "kerberos-ticket", "certificate"])
    mark.add_argument("--cred-value", type=str)
    mark.add_argument("--source-machine", type=str)
    mark.add_argument("--notes", type=str)
    _add_global_opts(mark)

    unmark = psub.add_parser("unmark", help="Remove pwned status")
    unmark.add_argument("user", help="Username")
    _add_global_opts(unmark)

    ls = psub.add_parser("list", help="List all pwned users")
    _add_global_opts(ls)

    details = psub.add_parser("details", help="Show pwned user details")
    details.add_argument("user", help="Username")
    _add_global_opts(details)

    targets = psub.add_parser("targets", help="High-value credential harvest targets")
    _add_global_opts(targets)

    post = psub.add_parser("post-exploit", help="Post-exploitation commands")
    _add_global_opts(post)

    rec = psub.add_parser("recommend", help="Attack path recommendations")
    _add_global_opts(rec)

    ips = psub.add_parser("ips", help="List machines with IP addresses")
    _add_global_opts(ips)

    interactive = psub.add_parser("interactive", help="Interactive credential entry")
    _add_global_opts(interactive)

    p.set_defaults(_handler=_handle_pwn)


def _build_config_parser(sub) -> None:
    p = sub.add_parser("config", help="Engagement config and domain settings")
    csub = p.add_subparsers(dest="config_action")

    show = csub.add_parser("show", help="Show current configuration")
    _add_global_opts(show)

    s = csub.add_parser("set", help="Set a config value")
    s.add_argument("key", choices=["dc-ip", "dc-hostname", "domain-sid", "lhost", "lport", "neo4j-uri", "neo4j-user"])
    s.add_argument("value", help="Value to set")
    _add_global_opts(s)

    clear = csub.add_parser("clear", help="Clear domain configuration")
    _add_global_opts(clear)

    purge = csub.add_parser("purge", help="Purge ALL Neo4j data")
    _add_global_opts(purge, skip={"yes"})
    purge.add_argument("-y", "--yes", action="store_true")

    discover = csub.add_parser("discover-dc", help="Auto-discover DC IP")
    discover.add_argument("credentials", nargs="*", help="USER PASSWORD")
    _add_global_opts(discover)

    # Engagement management
    eng_use = csub.add_parser("use", help="Switch active engagement")
    eng_use.add_argument("name", help="Engagement name")
    _add_global_opts(eng_use)

    eng_new = csub.add_parser("new", help="Create new engagement")
    eng_new.add_argument("name", help="Engagement name")
    _add_global_opts(eng_new, skip={"dc_ip", "domain"})
    eng_new.add_argument("--dc-ip", type=str)
    eng_new.add_argument("--domain", type=str)

    eng_list = csub.add_parser("engagements", help="List all engagements")
    _add_global_opts(eng_list)

    p.set_defaults(_handler=_handle_config)


def _build_policy_parser(sub) -> None:
    p = sub.add_parser("policy", help="Password policy management")
    psub = p.add_subparsers(dest="policy_action")

    show = psub.add_parser("show", help="Show stored policy")
    _add_global_opts(show)

    s = psub.add_parser("set", help="Import policy from 'net accounts' output")
    s.add_argument("file", nargs="?", default="-", help="Policy file (default: stdin)")
    _add_global_opts(s)

    clear = psub.add_parser("clear", help="Clear stored policy")
    _add_global_opts(clear)

    p.set_defaults(_handler=_handle_policy)


def _build_spray_parser(sub) -> None:
    p = sub.add_parser("spray", help="Password spray operations")
    ssub = p.add_subparsers(dest="spray_action")

    show = ssub.add_parser("show", help="Show spray recommendations")
    show.add_argument("--spray-method", choices=["smb", "kerberos", "ldap", "all"], default="all")
    _add_global_opts(show)

    tailored = ssub.add_parser("tailored", help="BloodHound-based targeted spray")
    tailored.add_argument("--output", type=str, help="Output file")
    _add_global_opts(tailored)

    auto = ssub.add_parser("auto", help="Generate/execute spray scripts")
    auto.add_argument("--execute", action="store_true", help="Execute immediately")
    auto.add_argument("--tool", choices=["kerbrute", "crackmapexec", "netexec", "hydra", "auto"], default="auto")
    auto.add_argument("--cred-source", type=str, action="append", choices=["neo4j", "potfile", "wordlist"])
    auto.add_argument("--wordlist", type=Path)
    auto.add_argument("--potfile", type=Path)
    auto.add_argument("--spray-users", choices=["all", "enabled", "non-pwned", "custom"], default="enabled")
    auto.add_argument("--user-file", type=Path)
    auto.add_argument("--targets-file", type=Path)
    auto.add_argument("--no-lockout-protection", action="store_true")
    auto.add_argument("--spray-output", type=Path)
    _add_global_opts(auto)

    p.set_defaults(_handler=_handle_spray)


def _build_creds_parser(sub) -> None:
    p = sub.add_parser("creds", help="Credential pipeline (validate -> collect -> import -> pwn)")
    p.add_argument("credential", nargs="?", help="Credential string (user:pass or DOMAIN/user:pass)")
    p.add_argument("--file", type=Path, dest="creds_file", help="Credentials file")
    p.add_argument("--potfile", action="store_true", dest="use_potfile", help="Use hashcat/john potfile")
    p.add_argument("--potfile-path", type=Path)
    p.add_argument("--stages", type=str, help="Comma-separated stages: validate,collect,import,pwn")
    p.add_argument("--from", type=str, dest="from_stage", help="Resume from stage")
    p.add_argument("--as", type=str, dest="as_user", help="Use stored credential by username")
    p.add_argument("--skip-validate", action="store_true")
    p.add_argument("--no-collect", action="store_true")
    p.add_argument("--no-pwn", action="store_true")
    p.add_argument("--no-import", action="store_true")
    p.add_argument("--bh-output", type=Path)
    p.add_argument("target", nargs="?", help="Target for collection (IP or hostname)")
    _add_global_opts(p)
    p.set_defaults(_handler=_handle_creds)


def _build_analyze_parser(sub) -> None:
    p = sub.add_parser("analyze", help="Attack detection and analysis")
    asub = p.add_subparsers(dest="analyze_action")

    detect = asub.add_parser("detect", help="Detect attack vectors (Azure AD Connect, GPP, LAPS)")
    _add_global_opts(detect)

    svc = asub.add_parser("services", help="Service account prioritization")
    _add_global_opts(svc)

    reuse = asub.add_parser("reuse", help="Password reuse analysis")
    reuse.add_argument("creds_file", help="Credentials file")
    _add_global_opts(reuse)

    smb = asub.add_parser("smb", help="Crawl SMB shares for sensitive files")
    smb.add_argument("host", help="Target host")
    smb.add_argument("-u", "--ad-username", type=str, required=True)
    smb.add_argument("-p", "--ad-password", type=str, required=True)
    smb.add_argument("--share", type=str)
    _add_global_opts(smb)

    sqlite = asub.add_parser("sqlite", help="Hunt SQLite DB for credentials")
    sqlite.add_argument("db_file", help="SQLite file")
    sqlite.add_argument("--target", help="Target IP for cred testing")
    _add_global_opts(sqlite)

    dotnet = asub.add_parser("dotnet", help="Hunt .NET assembly for secrets")
    dotnet.add_argument("file", help="EXE or DLL path")
    _add_global_opts(dotnet)

    deleted = asub.add_parser("deleted", help="Parse AD Recycle Bin output")
    deleted.add_argument("ldif_file", help="ldapsearch LDIF output")
    _add_global_opts(deleted)

    chains = asub.add_parser("chains", help="Detect attack chains for user")
    chains.add_argument("user", help="Username")
    _add_global_opts(chains, skip={"domain", "dc_ip"})
    chains.add_argument("-d", "--domain", type=str)
    chains.add_argument("--dc-ip", type=str)

    p.set_defaults(_handler=_handle_analyze)


def _build_wizard_parser(sub) -> None:
    p = sub.add_parser("wizard", help="Guided first-time setup")
    p.add_argument("target", nargs="?", help="Target IP/hostname")
    p.add_argument("--resume", type=str, metavar="TARGET", help="Resume from checkpoint")
    _add_global_opts(p)
    p.set_defaults(_handler=_handle_wizard)


def _build_ui_parser(sub) -> None:
    p = sub.add_parser("ui", help="Launch interactive web UI")
    p.add_argument("path", nargs="?", type=Path, help="BloodHound data to load")
    p.add_argument("--port", type=int, default=8765)
    _add_global_opts(p)
    p.set_defaults(_handler=_handle_ui)


def _build_doctor_parser(sub) -> None:
    p = sub.add_parser("doctor", help="Check dependencies and connectivity")
    _add_global_opts(p)
    p.set_defaults(_handler=_handle_doctor)


def _build_quickwin_parser(sub) -> None:
    p = sub.add_parser("quickwin", help="Fast path: enum -> asrep -> kerberoast -> report")
    p.add_argument("target", help="Target IP or hostname")
    p.add_argument("-u", "--ad-username", type=str)
    p.add_argument("-p", "--ad-password", type=str)
    _add_global_opts(p, skip={"domain"})
    p.add_argument("--domain", type=str)
    p.set_defaults(_handler=_handle_quickwin)


def _build_ingest_parser(sub) -> None:
    p = sub.add_parser("ingest", help="Import + run-all + chains + report in one shot")
    p.add_argument("path", type=Path, help="BloodHound data directory or ZIP")
    p.add_argument("--preset", choices=["attack-paths", "all"], default="attack-paths")
    p.add_argument("--report-path", type=Path)
    _add_global_opts(p)
    p.set_defaults(_handler=_handle_ingest)


def _build_escalate_parser(sub) -> None:
    p = sub.add_parser("escalate", help="Pwn + recommend + post-exploit for a user")
    p.add_argument("user", help="Username to mark as pwned")
    p.add_argument("--cred-type", choices=["password", "ntlm-hash", "kerberos-ticket", "certificate"])
    p.add_argument("--cred-value", type=str)
    _add_global_opts(p)
    p.set_defaults(_handler=_handle_escalate)


def create_subcommand_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bloodtrail",
        description="BloodHound attack path discovery and exploitation toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick start:
  bloodtrail enum 10.10.10.161           Enumerate a target
  bloodtrail import ./sharphound.zip     Import BloodHound data
  bloodtrail query run-all               Run all queries + report
  bloodtrail pwn mark USER@DOMAIN        Mark user as pwned
  bloodtrail config show                 View configuration
  bloodtrail doctor                      Check dependencies

Workflows:
  bloodtrail quickwin 10.10.10.161       Enum -> roast -> report
  bloodtrail ingest ./data.zip           Import + analyze + report
  bloodtrail escalate USER@DOMAIN        Pwn + recommend + post-exploit

Engagement management:
  bloodtrail config new htb-forest       Create engagement profile
  bloodtrail config set dc-ip 10.10.10.1 Store DC IP (persists)
  bloodtrail config use htb-forest       Switch active engagement

Legacy flags (--list-queries, --pwn, etc.) still work.
""",
    )

    sub = parser.add_subparsers(dest="subcommand")
    _build_enum_parser(sub)
    _build_import_parser(sub)
    _build_query_parser(sub)
    _build_pwn_parser(sub)
    _build_config_parser(sub)
    _build_policy_parser(sub)
    _build_spray_parser(sub)
    _build_creds_parser(sub)
    _build_analyze_parser(sub)
    _build_wizard_parser(sub)
    _build_ui_parser(sub)
    _build_doctor_parser(sub)
    _build_quickwin_parser(sub)
    _build_ingest_parser(sub)
    _build_escalate_parser(sub)

    return parser


# ---------------------------------------------------------------------------
# Handlers — translate subcommand args to legacy Namespace and dispatch
# ---------------------------------------------------------------------------

def _apply_settings_defaults(args: Namespace) -> Namespace:
    """Fill in missing args from persistent config."""
    from ..settings import get_effective_config
    cfg = get_effective_config(args)
    if not getattr(args, "uri", None):
        args.uri = cfg["neo4j_uri"]
    if not getattr(args, "user", None):
        args.user = cfg["neo4j_user"]
    if not getattr(args, "neo4j_password", None):
        args.neo4j_password = cfg["neo4j_password"]
    if not getattr(args, "dc_ip", None) and cfg.get("dc_ip"):
        args.dc_ip = cfg["dc_ip"]
    if not getattr(args, "domain", None) and cfg.get("domain"):
        args.domain = cfg["domain"]
    return args


def _handle_enum(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    args.bh_data_dir = Path(args.target)
    # Check if creds pipeline should run
    if getattr(args, "creds", None) or getattr(args, "creds_file", None) or getattr(args, "use_potfile", False):
        from .commands.creds import CredsCommands
        return CredsCommands.handle(args)
    from .commands.enumerate import EnumerateCommands
    return EnumerateCommands.handle(args)


def _handle_import(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    args.bh_data_dir = args.path
    args.resume = False
    args.validate = getattr(args, "validate", False)
    args.list_edges = False
    from .commands.import_data import ImportDataCommands
    return ImportDataCommands.handle(args)


def _handle_query(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    action = getattr(args, "query_action", None)
    if not action:
        print("Usage: bloodtrail query {list|run|search|export|run-all|install|export-ce}")
        return 1

    mapping = {
        "list": {"list_queries": True},
        "run": {"run_query": args.query_id if hasattr(args, "query_id") else None},
        "search": {"search_query": args.keyword if hasattr(args, "keyword") else None},
        "export": {"export_query": args.query_id if hasattr(args, "query_id") else None},
        "run-all": {"run_all": True},
        "install": {"install_queries": True},
        "export-ce": {"export_ce": not getattr(args, "ce_json", False), "export_ce_json": getattr(args, "ce_json", False)},
    }

    for key, val in mapping.get(action, {}).items():
        setattr(args, key, val)

    from .commands.query import QueryCommands
    return QueryCommands.handle(args)


def _handle_pwn(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    action = getattr(args, "pwn_action", None)
    if not action:
        print("Usage: bloodtrail pwn {mark|unmark|list|details|targets|post-exploit|recommend|ips|interactive}")
        return 1

    mapping = {
        "mark": {"pwn": args.user if hasattr(args, "user") else None, "pwn_notes": getattr(args, "notes", None)},
        "unmark": {"unpwn": args.user if hasattr(args, "user") else None},
        "list": {"list_pwned": True},
        "details": {"pwned_user": args.user if hasattr(args, "user") else None},
        "targets": {"cred_targets": True},
        "post-exploit": {"post_exploit": True},
        "recommend": {"recommend": True},
        "ips": {"list_ip_addresses": True},
        "interactive": {"pwn_interactive": True},
    }

    for key, val in mapping.get(action, {}).items():
        setattr(args, key, val)

    from .commands.pwned import PwnedCommands
    return PwnedCommands.handle(args)


def _handle_config(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    action = getattr(args, "config_action", None)
    if not action:
        print("Usage: bloodtrail config {show|set|clear|purge|discover-dc|use|new|engagements}")
        return 1

    # Engagement management (handled by settings, not Neo4j)
    if action in ("use", "new", "engagements"):
        return _handle_engagement_config(args, action)

    if action == "set":
        return _handle_config_set(args)

    mapping = {
        "show": {"show_config": True},
        "clear": {"clear_config": True},
        "purge": {"purge": True},
        "discover-dc": {"discover_dc": getattr(args, "credentials", [])},
    }

    for key, val in mapping.get(action, {}).items():
        setattr(args, key, val)

    from .commands.config import ConfigCommands
    return ConfigCommands.handle(args)


def _handle_engagement_config(args: Namespace, action: str) -> int:
    from ..settings import load_settings, save_settings
    from .base import BaseCommandGroup

    settings = load_settings()

    if action == "engagements":
        names = settings.list_engagements()
        if not names:
            print("No engagements configured. Create one with: bloodtrail config new <name>")
            return 0
        print("\nEngagements:")
        for name in names:
            marker = " *" if name == settings.active_engagement else ""
            eng = settings.get_engagement(name)
            domain = f" ({eng.domain})" if eng and eng.domain else ""
            print(f"  {name}{domain}{marker}")
        print(f"\n* = active")
        return 0

    if action == "new":
        eng = settings.create_engagement(args.name)
        if getattr(args, "dc_ip", None):
            eng.dc_ip = args.dc_ip
        if getattr(args, "domain", None):
            eng.domain = args.domain
        settings.set_engagement(eng)
        save_settings(settings)
        BaseCommandGroup.print_success(f"Created engagement '{args.name}' (now active)")
        return 0

    if action == "use":
        if settings.use(args.name):
            save_settings(settings)
            BaseCommandGroup.print_success(f"Switched to engagement '{args.name}'")
            return 0
        BaseCommandGroup.print_error(f"Engagement '{args.name}' not found")
        print(f"  Available: {', '.join(settings.list_engagements()) or '(none)'}")
        return 1

    return -1


def _handle_config_set(args: Namespace) -> int:
    from ..settings import load_settings, save_settings, Engagement
    from .base import BaseCommandGroup

    settings = load_settings()
    key, value = args.key, args.value

    # Global Neo4j settings
    if key == "neo4j-uri":
        settings.neo4j_uri = value
        save_settings(settings)
        BaseCommandGroup.print_success(f"Neo4j URI: {value}")
        return 0
    if key == "neo4j-user":
        settings.neo4j_user = value
        save_settings(settings)
        BaseCommandGroup.print_success(f"Neo4j user: {value}")
        return 0

    # Engagement-scoped settings
    eng = settings.active()
    if not eng:
        eng = settings.create_engagement("default")

    field_map = {
        "dc-ip": "dc_ip",
        "dc-hostname": "dc_hostname",
        "domain-sid": "domain_sid",
        "lhost": "lhost",
        "lport": "lport",
    }

    field_name = field_map.get(key)
    if field_name:
        val = int(value) if key == "lport" else value
        setattr(eng, field_name, val)
        settings.set_engagement(eng)
        save_settings(settings)
        BaseCommandGroup.print_success(f"{key}: {value} (engagement: {eng.name})")

        # Also push to Neo4j for backward compat
        if key == "dc-ip":
            _push_dc_ip_to_neo4j(args, value)
        return 0

    BaseCommandGroup.print_error(f"Unknown key: {key}")
    return 1


def _push_dc_ip_to_neo4j(args, dc_ip):
    """Best-effort sync of dc-ip to Neo4j domain config."""
    try:
        from ..config import Neo4jConfig
        from ..pwned_tracker import PwnedTracker
        config = Neo4jConfig(
            uri=getattr(args, "uri", None) or "bolt://localhost:7687",
            user=getattr(args, "user", None) or "neo4j",
            password=getattr(args, "neo4j_password", None) or __import__("os").environ.get("NEO4J_PASSWORD", ""),
        )
        tracker = PwnedTracker(config)
        if tracker.connect():
            tracker.set_dc_ip(dc_ip)
            tracker.close()
    except Exception:
        pass


def _handle_policy(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    action = getattr(args, "policy_action", None)
    if not action:
        print("Usage: bloodtrail policy {show|set|clear}")
        return 1

    mapping = {
        "show": {"show_policy": True},
        "set": {"set_policy": getattr(args, "file", "-")},
        "clear": {"clear_policy": True},
    }

    for key, val in mapping.get(action, {}).items():
        setattr(args, key, val)

    from .commands.policy import PolicyCommands
    return PolicyCommands.handle(args)


def _handle_spray(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    action = getattr(args, "spray_action", None)
    if not action:
        print("Usage: bloodtrail spray {show|tailored|auto}")
        return 1

    if action == "show":
        args.spray = True
    elif action == "tailored":
        args.spray_tailored = True
        args.spray_tailored_output = getattr(args, "output", None)
    elif action == "auto":
        args.auto_spray = True
        args.spray_tool = getattr(args, "tool", "auto")

    from .commands.spray import SprayCommands
    return SprayCommands.handle(args)


def _handle_creds(args: Namespace) -> int:
    args = _apply_settings_defaults(args)

    # Handle --as flag: pull from credential store
    as_user = getattr(args, "as_user", None)
    if as_user:
        from ..settings import load_settings
        settings = load_settings()
        eng = settings.active()
        if eng:
            cred = eng.get_credential(as_user)
            if cred:
                sep = "/" if cred.domain else ""
                args.creds = f"{cred.domain}{sep}{cred.username}:{cred.value}"
            else:
                from .base import BaseCommandGroup
                BaseCommandGroup.print_error(f"No stored credential for '{as_user}'")
                return 1

    if not getattr(args, "creds", None) and getattr(args, "credential", None):
        args.creds = args.credential

    from .commands.creds import CredsCommands
    return CredsCommands.handle(args)


def _handle_analyze(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    action = getattr(args, "analyze_action", None)
    if not action:
        print("Usage: bloodtrail analyze {detect|services|reuse|smb|sqlite|dotnet|deleted|chains}")
        return 1

    mapping = {
        "detect": {"detect": True},
        "services": {"analyze_svc": True},
        "reuse": {"analyze_reuse": getattr(args, "creds_file", None)},
        "smb": {"crawl_smb": getattr(args, "host", None)},
        "sqlite": {"hunt_sqlite": getattr(args, "db_file", None)},
        "dotnet": {"hunt_dotnet": getattr(args, "file", None)},
        "deleted": {"parse_deleted": getattr(args, "ldif_file", None)},
        "chains": {"chains": getattr(args, "user", None)},
    }

    for key, val in mapping.get(action, {}).items():
        setattr(args, key, val)

    if action == "smb":
        args.share = getattr(args, "share", None)
    if action == "chains" and hasattr(args, "domain"):
        pass  # domain already set
    if action == "sqlite":
        args.target = getattr(args, "target", None)

    from .commands.analyze import AnalyzeCommands
    return AnalyzeCommands.handle(args)


def _handle_wizard(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    if getattr(args, "resume", None):
        args.wizard_resume = args.resume
    else:
        args.wizard = True
        args.wizard_target = getattr(args, "target", None)

    from .commands.wizard import WizardCommands
    return WizardCommands.handle(args)


def _handle_ui(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    args.ui = True
    args.bh_data_dir = getattr(args, "path", None)
    from .commands.ui import UICommands
    return UICommands.handle(args)


def _handle_doctor(args: Namespace) -> int:
    args = _apply_settings_defaults(args)
    from .commands.doctor import DoctorCommands
    return DoctorCommands.handle(args)


def _handle_quickwin(args: Namespace) -> int:
    """enum -> asrep/kerberoast queries -> report"""
    args = _apply_settings_defaults(args)
    from .base import BaseCommandGroup

    BaseCommandGroup.print_header("QuickWin: Enumerate + Roast + Report")

    # Step 1: Enumerate
    BaseCommandGroup.print_info("Step 1/3: Enumerating target...")
    args.bh_data_dir = Path(args.target)
    args.interactive = False
    args.auto = False
    args.cred = None
    args.list_enumerators = False
    args.no_prism = False
    args.max_depth = 5
    args.cmd_timeout = 180

    from .commands.enumerate import EnumerateCommands
    result = EnumerateCommands.handle(args)
    if result != 0 and result != -1:
        return result

    # Step 2: Run roasting queries
    BaseCommandGroup.print_info("Step 2/3: Running AS-REP + Kerberoast queries...")
    for qid in ("find-asrep", "find-kerberoastable"):
        args.run_query = qid
        args.var = None
        args.output_format = "table"
        from .commands.query import QueryCommands
        QueryCommands.handle(args)
        args.run_query = None

    # Step 3: Full report
    BaseCommandGroup.print_info("Step 3/3: Generating full report...")
    args.run_all = True
    args.commands = True
    args.data = False
    args.oscp_high_only = False
    args.report_path = None
    from .commands.query import QueryCommands
    return QueryCommands.handle(args)


def _handle_ingest(args: Namespace) -> int:
    """import + run-all + chains + report"""
    args = _apply_settings_defaults(args)
    from .base import BaseCommandGroup

    BaseCommandGroup.print_header("Ingest: Import + Analyze + Report")

    # Step 1: Import
    BaseCommandGroup.print_info("Step 1/2: Importing BloodHound data...")
    args.bh_data_dir = args.path
    args.resume = False
    args.validate = False
    args.list_edges = False
    args.no_report = True  # We'll generate our own
    args.batch_size = getattr(args, "batch_size", 500)
    args.no_properties = False
    args.properties_only = False
    args.edges = None
    args.commands = False
    args.data = False

    from .commands.import_data import ImportDataCommands
    result = ImportDataCommands.handle(args)
    if result != 0 and result != -1:
        return result

    # Step 2: Run all queries + report
    BaseCommandGroup.print_info("Step 2/2: Running all queries + generating report...")
    args.run_all = True
    args.commands = True
    args.oscp_high_only = False
    from .commands.query import QueryCommands
    return QueryCommands.handle(args)


def _handle_escalate(args: Namespace) -> int:
    """pwn + recommend + post-exploit"""
    args = _apply_settings_defaults(args)
    from .base import BaseCommandGroup

    BaseCommandGroup.print_header(f"Escalate: {args.user}")

    # Step 1: Mark as pwned
    BaseCommandGroup.print_info("Marking user as pwned...")
    args.pwn = args.user
    args.pwn_notes = None
    from .commands.pwned import PwnedCommands
    PwnedCommands.handle(args)
    args.pwn = None

    # Store in credential store
    if getattr(args, "cred_value", None):
        from ..settings import load_settings, save_settings, StoredCredential
        settings = load_settings()
        eng = settings.active()
        if eng:
            domain = ""
            username = args.user
            if "@" in username:
                username, domain = username.split("@", 1)
            cred = StoredCredential(
                username=username, domain=domain,
                cred_type=getattr(args, "cred_type", "password") or "password",
                value=args.cred_value, validated=True,
            )
            eng.add_credential(cred)
            settings.set_engagement(eng)
            save_settings(settings)

    # Step 2: Recommend
    BaseCommandGroup.print_info("Attack path recommendations...")
    args.recommend = True
    PwnedCommands.handle(args)
    args.recommend = False

    # Step 3: Post-exploit
    BaseCommandGroup.print_info("Post-exploitation commands...")
    args.post_exploit = True
    return PwnedCommands.handle(args)
