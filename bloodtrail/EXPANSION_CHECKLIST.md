# BloodTrail Expansion Checklist

Target: Cover Monteverde-style attack gaps (SMB file crawling, config parsing, Azure AD Connect detection)

## Phase 1: Credential Model (Foundation) - COMPLETE
- [x] Extend `core/models.py` with `DiscoveredCredential` dataclass
  - [x] Fields: username, secret, secret_type, domain, source, source_type, confidence, discovered_at, validated
  - [x] Method: `to_creds_string()` - format for --creds pipeline
  - [x] Method: `to_neo4j_props()` - format for pwned tracker storage
  - [x] Enums: SecretType (password, ntlm-hash, aes256-key, kerberos-ticket, certificate)
  - [x] Enums: SourceType (config_file, smb_share, gpp, spray, dump, potfile, manual, kerberoast, asrep, ldap)
  - [x] Enums: Confidence (confirmed, likely, possible)
  - [x] Method: `to_parsed_credential()` - convert to ParsedCredential for pipeline
  - [x] Method: `from_parsed_credential()` - create from ParsedCredential
  - [x] Method: `mark_validated()` - mark as confirmed after validation
  - [x] Properties: `upn`, `sam_account`
  - [x] Hash/equality for deduplication
  - [x] Updated `core/__init__.py` exports

## Phase 2: Config Parser Framework - COMPLETE
- [x] Create `parsers/config_parser.py` (renamed from extractors to avoid conflict)
  - [x] `ConfigParserBase` ABC with:
    - [x] `supported_extensions` property
    - [x] `file_signatures` property (magic bytes/patterns)
    - [x] `parse(content, source_path)` method
    - [x] `can_parse(filename, content)` method
    - [x] `get_next_steps(credentials, context)` method - **EDUCATIONAL**
  - [x] `ConfigParserRegistry` class:
    - [x] `register(parser)` method
    - [x] `parse_file(path, content)` method
    - [x] `parse_all(files)` method
  - [x] `ExtractionResult` with credentials + next_steps
  - [x] `NextStep` dataclass (action, command, explanation, priority)
  - [x] Concrete parsers:
    - [x] `AzurePSCredentialParser` - PSADPasswordCredential XML
    - [x] `WebConfigParser` - .NET connection strings
    - [x] `UnattendXmlParser` - Windows unattend.xml
    - [x] `GroupsPolicyParser` - GPP Groups.xml (cpassword with AES decrypt)
    - [x] `EnvFileParser` - .env files
    - [x] `GenericJsonParser` - JSON with password/secret fields
    - [x] `GenericXmlParser` - Fallback XML parser
  - [x] Convenience functions: `get_default_registry()`, `extract_from_file()`, `extract_from_content()`

## Phase 3: File Discovery Base - COMPLETE
- [x] Create `core/file_discovery.py`
  - [x] `DiscoveredFile` dataclass:
    - [x] Fields: path, source, size, content, interesting_score, score_reasons
  - [x] `FileDiscoveryBase` ABC with:
    - [x] `INTERESTING_EXTENSIONS` class var (25+ extensions)
    - [x] `INTERESTING_NAMES` class var (30+ filenames)
    - [x] `INTERESTING_DIRS` class var
    - [x] `SKIP_PATTERNS` class var
    - [x] `list_sources()` abstract method
    - [x] `crawl(source, max_depth)` abstract method
    - [x] `read_file(file)` abstract method
    - [x] `score_file(file)` concrete method with scoring heuristics
    - [x] `get_discovery_summary(files)` method
    - [x] `get_next_steps(files, context)` method - **EDUCATIONAL**
  - [x] `LocalFileDiscovery` concrete implementation

## Phase 4: SMB Crawler - COMPLETE
- [x] Create `enumerators/smb_crawler.py`
  - [x] `SMBCrawler(FileDiscoveryBase)` class:
    - [x] `__init__(host, username, password, domain, port, ntlm_hash)` - supports PTH
    - [x] `connect()` / `disconnect()` - connection management
    - [x] Context manager support (`with SMBCrawler(...) as crawler:`)
    - [x] `list_sources()` - list accessible SMB shares
    - [x] `list_shares_detailed()` - detailed share info
    - [x] `crawl(share, max_depth, max_files)` - recursive file discovery
    - [x] `read_file(file, max_size)` - download via SMB
    - [x] `crawl_and_extract()` - full pipeline returning CrawlResult
  - [x] `ShareInfo` dataclass (name, remark, share_type, readable, writable)
  - [x] `CrawlResult` dataclass (files, credentials, next_steps, errors)
  - [x] SYSVOL/GPP detection with next steps
  - [x] Updated `enumerators/__init__.py` exports

## Phase 5: Detection Framework + Azure AD Connect - COMPLETE
- [x] Create `core/detection.py`
  - [x] `DetectionConfidence` enum (confirmed, likely, possible)
  - [x] `AttackCommand` dataclass:
    - [x] Fields: command, description, explanation, prerequisites, alternatives, references
  - [x] `DetectionResult` dataclass:
    - [x] Fields: indicator, name, confidence, evidence, attack_commands, next_steps, references
  - [x] `DetectorBase` ABC with:
    - [x] `indicator_name`, `display_name`, `description` properties
    - [x] `detect_from_ldap(users, groups, computers, context)` method
    - [x] `detect_from_bloodhound(neo4j_session, context)` method
    - [x] `get_exploit_commands(context)` method
  - [x] `DetectorRegistry` class:
    - [x] `register(detector)` method (chainable)
    - [x] `detect_all_ldap(...)` method
    - [x] `detect_all_bloodhound(...)` method
    - [x] `list_detectors()` method
  - [x] `get_default_registry()` factory function
- [x] Concrete detectors in `core/detection.py`:
  - [x] `AzureADConnectDetector`:
    - [x] Detection patterns: AAD_*, MSOL_*
    - [x] Azure groups detection (ADSyncAdmins, Azure Admins)
    - [x] 5 exploit commands with educational context
    - [x] Cypher queries for BloodHound detection
  - [x] `GPPPasswordDetector`:
    - [x] SYSVOL check suggestion
    - [x] CME, findstr, gpp-decrypt commands
  - [x] `LAPSDetector`:
    - [x] BloodHound haslaps detection
    - [x] CME and ldapsearch commands
- [x] Create `cypher_queries/azure_attacks.json`
  - [x] Query: azure-sync-accounts (AAD_, MSOL_ accounts)
  - [x] Query: azure-adsync-admins (group members)
  - [x] Query: azure-connect-server
  - [x] Query: azure-path-to-sync (attack paths)
  - [x] Query: azure-dcsync-equivalent
- [x] Updated `core/__init__.py` exports

## Phase 6: Password Reuse + Service Account Analyzer - COMPLETE
- [x] Create `core/password_reuse.py`
  - [x] `ReuseAnalysis` dataclass:
    - [x] Fields: by_password, by_user, reused_passwords, stats
    - [x] Property: `reuse_rate` percentage
    - [x] Method: `shares_password_with(username)` - find reuse partners
  - [x] `SpraySuggestion` dataclass with educational context
  - [x] `PasswordReuseTracker` class:
    - [x] `add_credential(cred)` / `add_credentials(creds)` methods
    - [x] `analyze_reuse()` - detect password patterns
    - [x] `get_spray_candidates()` - prioritize spray passwords
    - [x] `get_spray_suggestions(users, context)` - **EDUCATIONAL**
    - [x] `get_lateral_movement_paths(user, context)` - pivot suggestions
    - [x] `get_reuse_report()` - formatted report
- [x] Create `core/service_accounts.py`
  - [x] `AccountPriority` enum (critical, high, medium, low)
  - [x] `AttackVector` enum (kerberoast, asrep_roast, password_spray, password_in_desc, delegation, gmsa)
  - [x] `ServiceAccountInfo` dataclass:
    - [x] Name, domain, priority, patterns_matched, attack_vectors
    - [x] attack_suggestion, educational_note
    - [x] Properties: has_spn, preauth_disabled, admin_count
  - [x] `AnalysisResult` with priority buckets and next_steps
  - [x] `ServiceAccountAnalyzer` class:
    - [x] Compiled regex patterns for svc_, sa_, sql, backup, batch, etc.
    - [x] Technology patterns (MSSQL, Oracle, Exchange, etc.)
    - [x] `analyze_from_users(users, context)` method
    - [x] `analyze_from_bloodhound(neo4j_session)` method
    - [x] Password-in-description detection
    - [x] `get_spray_wordlist(domain)` - common service passwords
    - [x] `get_report(result)` - formatted report
- [x] Updated `core/__init__.py` exports

## CLI Integration (Final)
- [ ] Update `cli/parser.py` with new flags:
  - [ ] `--crawl-shares`
  - [ ] `--share <name>`
  - [ ] `--extract-creds <path>`
  - [ ] `--detect-azure`
  - [ ] `--spray-reuse`
  - [ ] `--analyze-svc`
- [ ] Update `cli/commands/` with new command handlers
- [ ] Update help text and README.md

## Testing
- [ ] Unit tests for config parsers
- [ ] Unit tests for file discovery
- [ ] Integration tests for SMB crawler (mock)
- [ ] Unit tests for detectors
- [ ] Unit tests for password reuse tracker

---

## Dependency Graph

```
Phase 1 (models)
    ↓
Phase 2 (parsers) ←──┐
    ↓                │
Phase 3 (discovery)──┤
    ↓                │
Phase 4 (SMB) ───────┘
    ↓
Phase 5 (detection)
    ↓
Phase 6 (analysis)
```

## Files Created

```
bloodtrail/
├── core/
│   ├── models.py            # Extended (Phase 1) - DiscoveredCredential, SecretType, SourceType, Confidence
│   ├── file_discovery.py    # New (Phase 3) - DiscoveredFile, FileDiscoveryBase, LocalFileDiscovery
│   ├── detection.py         # New (Phase 5) - DetectorRegistry, Azure/GPP/LAPS detectors
│   ├── password_reuse.py    # New (Phase 6) - PasswordReuseTracker, ReuseAnalysis
│   ├── service_accounts.py  # New (Phase 6) - ServiceAccountAnalyzer, priority scoring
│   └── __init__.py          # Updated - all new exports
├── parsers/                  # New directory (renamed from extractors)
│   ├── __init__.py          # New (Phase 2)
│   └── config_parser.py     # New (Phase 2) - 7 parsers + registry
├── enumerators/
│   ├── smb_crawler.py       # New (Phase 4) - SMBCrawler, ShareInfo, CrawlResult
│   └── __init__.py          # Updated - SMB crawler exports
└── cypher_queries/
    └── azure_attacks.json   # New (Phase 5) - 5 Azure-specific queries
```

## Completion - ALL PHASES COMPLETE
- [x] Phase 1: Credential Model (DiscoveredCredential with provenance)
- [x] Phase 2: Config Parser Framework (7 parsers with NextStep suggestions)
- [x] Phase 3: File Discovery Base (scoring heuristics, 25+ extensions)
- [x] Phase 4: SMB Crawler (impacket-based, crawl_and_extract pipeline)
- [x] Phase 5: Detection Framework (Azure AD Connect, GPP, LAPS)
- [x] Phase 6: Analysis Tools (Password Reuse + Service Account Analyzer)
- [x] CLI Integration (AnalyzeCommands: --detect, --analyze-svc, --analyze-reuse, --crawl-smb)
- [x] Unit Tests (85 tests passing in tests/ directory)
- [x] **Automatic Integration** (detection and service account analysis run in default flow)
- [ ] README.md update (optional)

## Next Step Suggestions (Educational)

Each module now provides `get_next_steps()` or similar methods that explain:
- WHAT to do next
- The COMMAND to run
- WHY it works (educational context)

Example flow for Monteverde-style attack:
```python
# 1. Crawl SMB shares
crawler = SMBCrawler("10.10.10.172", "SABatchJobs", "SABatchJobs", "MEGABANK")
result = crawler.crawl_and_extract()  # Finds azure.xml

# 2. Parse azure.xml
creds = result.credentials  # Extracts mhope password

# 3. Detect Azure AD Connect
detector = AzureADConnectDetector()
detection = detector.detect_from_ldap(users, groups, [], context)
for cmd in detection.attack_commands:
    print(cmd.command)      # Shows ADSync extraction commands
    print(cmd.explanation)  # Explains WHY it works

# 4. Track password reuse
tracker = PasswordReuseTracker()
tracker.add_credentials(creds)
for suggestion in tracker.get_spray_suggestions(all_users, context):
    print(suggestion.action)
    print(suggestion.explanation)

# 5. Analyze service accounts
analyzer = ServiceAccountAnalyzer()
result = analyzer.analyze_from_users(users, context)
print(analyzer.get_report(result))  # Prioritized targets with attack suggestions
```

**DELETE THIS FILE when CLI integration is complete.**
