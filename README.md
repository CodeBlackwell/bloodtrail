# BloodTrail

Active Directory attack path discovery and exploitation toolkit. Extends BloodHound with pre-auth enumeration, credential pipelines, and automated command generation.

## Features

| Feature | Description |
|---------|-------------|
| Pre-Auth Enumeration | AS-REP roasting, Kerberoasting, password policy discovery |
| Credential Pipeline | Validate → Collect → Import → Mark Pwned → Query |
| Edge Enhancement | Import missing edges from SharpHound exports |
| Query Library | 63+ Cypher queries for attack path discovery |
| Pwned Tracking | Track compromised users and access paths in Neo4j |
| Command Generation | Auto-suggest exploitation commands for discovered paths |
| **Attack Chain Detection** | Auto-detect multi-step escalation paths (Exchange DCSync, GenericAll, etc.) |
| Password Spraying | Policy-aware spraying with lockout protection |
| **Engagement Profiles** | Persistent config per engagement — set DC IP once, use everywhere |
| **Shell Completion** | Tab-complete all subcommands and flags via argcomplete |

## Installation

```bash
pip install bloodtrail
# With auto-collection support (bloodhound-python)
pip install bloodtrail[collect]
# From source
pip install -e .
# Enable shell completion (bash/zsh)
activate-global-python-argcomplete
```

### Docker (includes Neo4j + bloodhound-python)

```bash
docker compose up -d
# Import SharpHound data (mount to ./data/)
docker compose exec bloodtrail bloodtrail import /data/sharphound.zip --uri bolt://neo4j:7687
# Run queries
docker compose exec bloodtrail bloodtrail query run-all --uri bolt://neo4j:7687
```

Neo4j UI available at `http://localhost:7474` (neo4j/bloodtrail).

## Quick Start

```bash
# Check dependencies
bloodtrail doctor

# Create an engagement profile (persists DC IP, domain, creds)
bloodtrail config new htb-forest --dc-ip 10.10.10.161 --domain htb.local

# Enumerate a target
bloodtrail enum 10.10.10.161

# Quick win: enum → roast → report in one shot
bloodtrail quickwin 10.10.10.161

# Import + analyze + report in one shot
bloodtrail ingest ./sharphound.zip

# Feed credentials back (validates, collects, marks pwned)
bloodtrail creds svc-alfresco:s3rvice

# Mark pwned and get attack paths + post-exploit commands
bloodtrail escalate SVC-ALFRESCO@HTB.LOCAL --cred-type password --cred-value s3rvice
```

## Command Reference

### Subcommands

BloodTrail uses subcommands for a clean, discoverable interface. Legacy flat flags (`--list-queries`, `--pwn`, etc.) still work.

```
bloodtrail enum          Enumerate a target (IP or hostname)
bloodtrail import        Import BloodHound data (directory or ZIP)
bloodtrail query         Query library (list, run, search, export)
bloodtrail pwn           Track pwned users and credentials
bloodtrail creds         Credential pipeline (validate → collect → import → pwn)
bloodtrail config        Engagement config and domain settings
bloodtrail policy        Password policy management
bloodtrail spray         Password spray operations
bloodtrail analyze       Attack detection and analysis
bloodtrail wizard        Guided first-time setup
bloodtrail ui            Launch interactive web UI
bloodtrail doctor        Check dependencies and connectivity
bloodtrail quickwin      Fast path: enum → roast → report
bloodtrail ingest        Import + run-all + chains + report
bloodtrail escalate      Pwn + recommend + post-exploit for a user
```

### Enumeration

```bash
bloodtrail enum 10.10.10.161                  # Anonymous
bloodtrail enum 10.10.10.161 -u user -p pass  # Authenticated
bloodtrail enum 10.10.10.161 --domain corp.local
bloodtrail enum 10.10.10.161 -i               # Interactive guided mode
bloodtrail enum 10.10.10.161 --auto           # Auto-execute recommendations
```

### Credential Pipeline

```bash
bloodtrail creds admin:password               # Inline credential
bloodtrail creds 'DOMAIN/user:pass'           # With domain
bloodtrail creds --file ./creds.txt           # From file
bloodtrail creds --potfile                    # From hashcat/john potfile
bloodtrail creds --as svc-alfresco            # Reuse stored credential
bloodtrail creds user:pass --stages validate,collect  # Run specific stages
```

Pipeline: `Parse → Validate → Collect → Import → Mark Pwned → Query`

### BloodHound Import

```bash
bloodtrail import ./sharphound.zip            # Import ZIP
bloodtrail import ./bh_data/                  # Import directory
bloodtrail import ./data --preset attack-paths  # High-value edges only
bloodtrail import ./data --dry-run            # Validate without importing
```

### Query Library

```bash
bloodtrail query list                         # List all 63+ queries
bloodtrail query list --category quick_wins   # Filter by category
bloodtrail query search kerberos              # Search by keyword
bloodtrail query run find-asrep               # Execute single query
bloodtrail query run find-user --var USER=PETE@CORP.COM
bloodtrail query run-all                      # Run all + generate report
bloodtrail query export find-asrep            # Raw Cypher for BloodHound
bloodtrail query install                      # Install to BloodHound GUI
bloodtrail query export-ce                    # Export for BloodHound CE
```

### Attack Chain Detection

```bash
bloodtrail analyze chains svc-alfresco -d htb.local --dc-ip 10.10.10.161
bloodtrail query run-all                      # Chains included in report
```

**Detected Chain Types:**

| Chain | Description |
|-------|-------------|
| Exchange WriteDACL → DCSync | Account Operators → Exchange Windows Permissions → DCSync |
| GenericAll → Password Reset | Reset user password via GenericAll privilege |
| ForceChangePassword | Change password without knowing current |
| Backup Operators → NTDS.dit | Extract hashes via backup privilege |

### Pwned User Tracking

```bash
bloodtrail pwn mark 'USER@DOMAIN.COM' --cred-type password --cred-value secret
bloodtrail pwn interactive                    # Interactive credential entry
bloodtrail pwn list                           # List all pwned users
bloodtrail pwn details USER                   # User details + commands
bloodtrail pwn targets                        # Credential harvest targets
bloodtrail pwn post-exploit                   # Post-exploitation commands
bloodtrail pwn recommend                      # Attack path recommendations
bloodtrail pwn ips                            # Machines with IPs
```

### Analysis Commands

```bash
bloodtrail analyze detect                     # Detect attack vectors (Azure AD Connect, GPP, LAPS)
bloodtrail analyze services                   # Service account prioritization
bloodtrail analyze reuse ./creds.txt          # Password reuse analysis
bloodtrail analyze smb 10.10.10.1 -u user -p pass  # Crawl SMB shares
bloodtrail analyze sqlite ./audit.db          # Hunt SQLite for credentials
bloodtrail analyze dotnet ./app.exe           # Hunt .NET assembly for secrets
bloodtrail analyze deleted ./output.ldif      # Parse AD Recycle Bin
```

### Engagement Profiles

Persistent configuration per engagement. Set values once, they apply to all commands.

```bash
bloodtrail config new htb-forest --dc-ip 10.10.10.161 --domain htb.local
bloodtrail config set lhost 10.10.14.5
bloodtrail config set lport 443
bloodtrail config set domain-sid S-1-5-21-...
bloodtrail config set neo4j-uri bolt://custom:7687

bloodtrail config engagements                 # List all engagements
bloodtrail config use pg-practice             # Switch engagement
bloodtrail config show                        # View current config
bloodtrail config clear                       # Clear domain config
bloodtrail config purge                       # Purge all Neo4j data
```

Config stored at `~/.config/bloodtrail/config.json` (respects `$XDG_CONFIG_HOME`).

**Priority order:** CLI flags → engagement config → environment variables → defaults.

### Password Policy & Spraying

```bash
# Policy
bloodtrail policy set                         # Import from 'net accounts' (stdin)
bloodtrail policy set policy.txt              # From file
bloodtrail policy show
bloodtrail policy clear

# Spraying
bloodtrail spray show                         # Spray recommendations
bloodtrail spray tailored                     # BloodHound-based targeting
bloodtrail spray auto                         # Generate spray scripts
bloodtrail spray auto --execute               # Execute with confirmation
bloodtrail spray auto --tool kerbrute         # Specific tool
```

### Pre-Flight Checks

```bash
bloodtrail doctor
```

Checks Neo4j connectivity, config status, external tools (kerbrute, crackmapexec, impacket, etc.), and Python dependencies.

### Compound Workflows

```bash
# Enum → AS-REP/Kerberoast → full report
bloodtrail quickwin 10.10.10.161

# Import + run all queries + report
bloodtrail ingest ./sharphound.zip

# Mark pwned → attack recommendations → post-exploit commands
bloodtrail escalate USER@DOMAIN --cred-type password --cred-value secret
```

## Neo4j Connection

Default: `bolt://localhost:7687`

```bash
# Environment variable (recommended)
export NEO4J_PASSWORD='your_password'
bloodtrail query run-all

# Persistent config (per engagement)
bloodtrail config set neo4j-uri bolt://host:7687

# CLI override (one-off)
bloodtrail query run-all --uri bolt://host:7687 --neo4j-password secret
```

## Example Workflow

```bash
# 1. Set up engagement
bloodtrail config new htb-forest --dc-ip 10.10.10.161 --domain htb.local
bloodtrail config set lhost 10.10.14.5

# 2. Enumerate — find AS-REP roastable users
bloodtrail enum 10.10.10.161

# 3. AS-REP roast + crack (external tools)
impacket-GetNPUsers -dc-ip 10.10.10.161 -request -no-pass htb/svc-alfresco
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# 4. Feed credentials back (validates, collects BloodHound, marks pwned)
bloodtrail creds svc-alfresco:s3rvice

# 5. Full analysis — or use the one-shot workflow
bloodtrail escalate SVC-ALFRESCO@HTB.LOCAL --cred-type password --cred-value s3rvice

# 6. Run full report with attack chain detection
bloodtrail query run-all
```

## Output Files

Generated in working directory or next to imported data:

| File | Contents |
|------|----------|
| `bloodtrail.md` | Full attack path report |
| `users_all.txt` | All discovered users |
| `users_real.txt` | Non-service accounts (spray targets) |
| `asrep_targets.txt` | AS-REP roastable users |
| `kerberoast_targets.txt` | Users with SPNs |
| `computers.txt` | Computer names |
| `domain_info.txt` | Domain summary |

## Architecture

```
bloodtrail/
├── cli/                      # Command-line interface
│   ├── app.py               # Subcommand router (new)
│   ├── base.py              # BaseCommandGroup ABC
│   ├── parser.py            # Legacy flat-flag parser
│   ├── pager.py             # Output pagination
│   ├── interactive.py       # Interactive helpers
│   └── commands/            # Command handlers
│       ├── query.py         # query list/run/search/export
│       ├── pwned.py         # pwn mark/list/details/recommend
│       ├── config.py        # config show/set/clear/purge
│       ├── policy.py        # policy show/set/clear
│       ├── spray.py         # spray show/tailored/auto
│       ├── creds.py         # creds pipeline
│       ├── enumerate.py     # enum mode
│       ├── import_data.py   # import mode
│       ├── analyze.py       # analyze detect/services/reuse/smb
│       ├── wizard.py        # guided wizard
│       ├── doctor.py        # pre-flight checks (new)
│       └── ui.py            # web UI
│
├── settings.py               # Persistent config + engagement profiles (new)
├── core/                     # Shared utilities
├── enumerators/              # Pre-auth enumeration plugins
├── autospray/                # Password spray automation
├── display/                  # Output formatting
├── cypher_queries/           # Query library (JSON)
├── recommendation/           # Attack path analysis
├── main.py                   # BHEnhancer core
├── query_runner.py           # Cypher execution
├── report_generator.py       # Report generation + chain detection
├── pwned_tracker.py          # Pwned user tracking
├── command_suggester.py      # Command generation
└── creds_pipeline.py         # Credential pipeline
```

## Legacy Syntax

All original flat-flag commands still work for backward compatibility:

```bash
bloodtrail 10.10.10.161              # → bloodtrail enum 10.10.10.161
bloodtrail /path/to/data.zip         # → bloodtrail import /path/to/data.zip
bloodtrail --list-queries            # → bloodtrail query list
bloodtrail --run-query find-asrep    # → bloodtrail query run find-asrep
bloodtrail --run-all                 # → bloodtrail query run-all
bloodtrail --pwn USER                # → bloodtrail pwn mark USER
bloodtrail --list-pwned              # → bloodtrail pwn list
bloodtrail --show-config             # → bloodtrail config show
bloodtrail -r                        # → bloodtrail query run-all (resume)
```

## Testing

```bash
pip install -e ".[dev]"
pytest bloodtrail/tests/ -v
```

283 tests covering settings, CLI routing, subcommand parsing, engagement profiles, credential store, handler dispatch, pagination, legacy compatibility, and core functionality.
