# BloodTrail - Claude Code Reference

## Core Philosophy

**BloodTrail is a GUIDED attack path discovery tool, not a data dumper.**

The tool should act as an intelligent assistant that:
1. Discovers findings through enumeration
2. Recognizes patterns in those findings
3. Recommends specific next actions
4. Waits for user decision before proceeding
5. Tracks state to avoid repetition

## Design Principles

These principles apply to ALL features and the tool as a whole:

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

## Key Modules

| Module | Purpose |
|--------|---------|
| `enumerators/` | Data collection (LDAP, RPC, Kerbrute, etc.) |
| `recommendation/` | Finding analysis and recommendation engine |
| `cli/commands/` | Command handlers for each feature |
| `display/` | Output formatting |
| `cypher_queries/` | Neo4j query library |

## Adding New Features

When adding features to BloodTrail:

1. **Does it discover something?** → Add to enumerators, emit Finding
2. **Does it recognize a pattern?** → Add trigger rule
3. **Does it suggest an action?** → Add recommendation template
4. **Does it need user input?** → Use interactive prompt, don't assume

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

## Testing Recommendations

When testing BloodTrail features:

1. Verify ONE recommendation is shown at a time
2. Verify skip works and moves to next
3. Verify state tracks completed actions
4. Verify WHY is explained for each recommendation
5. Verify no duplicate suggestions
