# BloodTrail - Claude Code Reference

## Core Philosophy

**BloodTrail is a GUIDED attack path discovery tool, not a data dumper.**

The tool should act as an intelligent assistant that:
1. Discovers findings through enumeration
2. Recognizes patterns in those findings
3. Recommends specific next actions
4. Waits for user decision before proceeding
5. Tracks state to avoid repetition

## CLI Architecture (v1.4.0)

### Subcommand Router

The CLI uses a two-tier routing system in `cli/__init__.py:main()`:
- If the first arg is a known subcommand → `cli/app.py` (new router)
- Otherwise → `cli/parser.py` (legacy flat-flag parser)

Both paths are fully supported. Zero breaking changes.

### Subcommands

```
bloodtrail enum <target>           # Enumerate IP/hostname
bloodtrail import <path>           # Import BloodHound data
bloodtrail query list|run|search   # Query library
bloodtrail pwn mark|list|details   # Pwned user tracking
bloodtrail creds <user:pass>       # Credential pipeline
bloodtrail config show|set|new|use # Engagement config
bloodtrail policy show|set|clear   # Password policy
bloodtrail spray show|tailored|auto # Password spraying
bloodtrail analyze detect|services  # Attack analysis
bloodtrail wizard                  # Guided setup
bloodtrail ui                      # Web UI
bloodtrail doctor                  # Pre-flight checks
bloodtrail quickwin <target>       # enum → roast → report
bloodtrail ingest <path>           # import → run-all → report
bloodtrail escalate <user>         # pwn → recommend → post-exploit
```

### Persistent Configuration

Config at `~/.config/bloodtrail/config.json` (respects `$XDG_CONFIG_HOME`).

**Priority:** CLI flags → engagement config → env vars → defaults.

Managed via `bloodtrail/settings.py`:
- `Settings` — global Neo4j defaults, active engagement, output limits
- `Engagement` — per-engagement DC IP, domain, credentials, lhost/lport
- `StoredCredential` — validated creds cached for reuse via `--as` flag
- `get_effective_config(args)` — merges all sources into a single dict

### Handler Pattern

Each `_handle_*` function in `cli/app.py`:
1. Calls `_apply_settings_defaults(args)` to fill from config
2. Translates subcommand args into legacy `Namespace` attributes
3. Delegates to the existing `CommandGroup.handle(args)` class

This means existing command handlers in `cli/commands/` don't change.

### Adding a New Subcommand

1. Add name to `SUBCOMMANDS` set in `cli/app.py`
2. Write `_build_<name>_parser(sub)` — define args, call `_add_global_opts(p)`
3. Write `_handle_<name>(args)` — translate args, delegate to handler
4. Register in `create_subcommand_parser()` — call `_build_<name>_parser(sub)`
5. Add tests in `tests/test_cli_ux.py`

### Key Files

| File | Purpose |
|------|---------|
| `cli/__init__.py` | Entry point: `main()` routes to subcommand or legacy |
| `cli/app.py` | Subcommand parser + handler functions |
| `cli/parser.py` | Legacy flat-flag parser (backward compat) |
| `cli/pager.py` | Output pagination (`truncate_results`, `paged_output`) |
| `cli/base.py` | `BaseCommandGroup` ABC, Neo4j config from settings |
| `cli/commands/doctor.py` | Pre-flight checks (Neo4j, tools, deps) |
| `settings.py` | Persistent config, engagements, credential store |
| `cli/commands/` | One handler class per feature area |

## Design Principles

| Principle | Implementation |
|-----------|----------------|
| **One thing at a time** | Show ONE recommendation, wait for user decision |
| **Context-aware** | Only suggest relevant actions based on current findings |
| **Auto-decode** | Automatically try base64, hex, known encryption (VNC, etc.) |
| **Explain WHY** | "This file was in s.smith's folder - likely their password" |
| **Track state** | Remember what's been tried, don't repeat suggestions |
| **Prioritize** | Critical findings interrupt, low-priority queue up |
| **Allow skip** | User can skip any recommendation |

## Anti-Patterns (DO NOT)

- Dump 50 commands at once expecting user to figure it out
- Show irrelevant information (no AS-REP commands if no AS-REP users found)
- Require user to remember previous findings
- Suggest actions that have already been tried
- Hide the reasoning behind recommendations
- Add global state to `cli/app.py` handlers — they're stateless translators

## Recommendation Engine

### Finding → Trigger → Recommendation Flow

```
Finding (input)     →    Trigger (pattern match)    →    Recommendation (output)
─────────────────────────────────────────────────────────────────────────────────
"cascadeLegacyPwd"  →    custom_attr_with_pwd       →    decode + test as cred
"VNC Install.reg"   →    vnc_registry_file          →    decrypt VNC password
"*.sqlite file"     →    database_file              →    hunt for cred tables
"AD Recycle Bin"    →    privileged_group           →    query deleted objects
```

### Priority Levels

| Priority | Meaning | Example |
|----------|---------|---------|
| 1 (CRITICAL) | Act immediately | Valid credential discovered |
| 2 (HIGH) | Strong attack vector | AS-REP roastable user found |
| 3 (MEDIUM) | Worth investigating | Interesting file in share |
| 4 (LOW) | Background task | General enumeration |
| 5 (INFO) | For reference only | Domain info collected |

### Interactive Flow Example

```
[*] Finding: Custom LDAP attribute 'cascadeLegacyPwd' on r.thompson
    Raw: clk0bjVldmE=
    Decoded: rY4n5eva (base64)

┌─ RECOMMENDATION ─────────────────────────────────────────────────────┐
│  Test decoded value as password for r.thompson                       │
│  $ crackmapexec smb 10.10.10.182 -u r.thompson -p 'rY4n5eva'         │
│                                                                      │
│  [R]un  [S]kip  [?]Why                                               │
└──────────────────────────────────────────────────────────────────────┘
```

## Adding New Features

When adding features to BloodTrail:

1. **Does it discover something?** → Add to enumerators, emit Finding
2. **Does it recognize a pattern?** → Add trigger rule
3. **Does it suggest an action?** → Add recommendation template
4. **Does it need user input?** → Use interactive prompt, don't assume
5. **Does it need a CLI command?** → Add subcommand in `cli/app.py`

### Trigger Rule Template

```python
{
    "id": "unique_trigger_id",
    "match": {
        "finding_type": "ldap_attribute|file|group_membership|credential",
        "pattern": "regex or exact match",
    },
    "actions": [
        {"type": "auto_decode", "decoders": ["base64", "hex"]},
        {"type": "recommend", "priority": 1, "template": "test_credential"},
    ]
}
```

### Recommendation Template

```python
{
    "id": "test_credential",
    "description": "Test {decoded_value} as password for {username}",
    "command": "crackmapexec smb {target} -u {username} -p '{decoded_value}'",
    "on_success": ["enumerate_smb_shares", "check_winrm", "collect_bloodhound"],
    "on_failure": ["mark_invalid", "try_other_users"],
}
```

## State Tracking

The engine maintains state across the session:

```python
AttackState:
    findings: Dict[str, Finding]        # All discovered facts
    credentials: List[Credential]       # Validated credentials
    recommendations: Queue              # Pending recommendations
    completed: Set[str]                 # Actions already taken
    access_level: str                   # "anonymous" | "user" | "admin"
```

## Common Attack Patterns

These patterns should be auto-detected and guided:

1. **LDAP Legacy Attribute** → Decode → Test cred → SMB enum
2. **VNC Registry Backup** → Decrypt (known DES key) → Test cred
3. **SQLite Database** → Hunt cred tables → Extract → Test
4. **.NET Assembly** → Decompile → Extract keys → Decrypt
5. **AD Recycle Bin Member** → Query deleted objects → Extract legacy passwords
6. **Valid Credential** → SMB shares → BloodHound → Attack paths

## Testing

```bash
pytest bloodtrail/tests/ -v              # All 283 tests
pytest bloodtrail/tests/test_cli_ux.py   # 149 CLI UX tests (94% coverage on new code)
```

When testing BloodTrail features:

1. Verify ONE recommendation is shown at a time
2. Verify skip works and moves to next
3. Verify state tracks completed actions
4. Verify WHY is explained for each recommendation
5. Verify no duplicate suggestions
6. Verify subcommand args translate correctly to legacy handler flags
7. Verify persistent config is respected (engagement → effective config)
