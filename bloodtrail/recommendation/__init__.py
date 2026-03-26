"""
BloodTrail Recommendation Engine

Context-aware attack path recommendation system that:
1. Analyzes findings from enumeration
2. Pattern matches against known attack vectors
3. Suggests specific next actions
4. Tracks state to avoid repetition

Core Philosophy: Guide the user through ONE action at a time,
explaining WHY each step matters.
"""

from .models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
    AttackState,
    Credential,
    CredentialType,
)
from .decoders import (
    decode_value,
    DecodeResult,
    DecodeMethod,
    try_base64,
    try_hex,
    decrypt_vnc_password,
    try_aes_cbc,
    extract_vnc_password_from_reg,
    looks_like_password,
)
from .triggers import (
    TriggerRule,
    TriggerAction,
    TRIGGER_RULES,
    match_finding,
    get_recommendations_for_finding,
)
from .engine import (
    RecommendationEngine,
)
from .findings_converter import (
    findings_from_enumeration,
    findings_from_smb_crawl,
    findings_from_group_memberships,
)
from .smb_integration import (
    process_smb_crawl,
    SMBCrawlSummary,
    generate_smb_crawl_command,
    generate_file_retrieval_commands,
    display_smb_summary,
)
from .sqlite_integration import (
    process_sqlite_hunt,
    SqliteHuntSummary,
    display_sqlite_summary,
    hunt_and_display as sqlite_hunt_and_display,
)
from .bloodhound_analyzer import (
    BloodHoundAnalyzer,
    analyze_for_user as bloodhound_analyze_for_user,
)
from .attack_chains import (
    AttackChain,
    ChainStep,
    ChainStatus,
    ChainDetector,
    ATTACK_CHAINS,
    EXCHANGE_DCSYNC_CHAIN,
    detect_and_recommend as detect_attack_chains,
    get_chain_summary,
)

__all__ = [
    # Models
    "Finding",
    "FindingType",
    "Recommendation",
    "RecommendationPriority",
    "AttackState",
    "Credential",
    "CredentialType",
    # Decoders
    "decode_value",
    "DecodeResult",
    "DecodeMethod",
    "try_base64",
    "try_hex",
    "decrypt_vnc_password",
    "try_aes_cbc",
    "extract_vnc_password_from_reg",
    "looks_like_password",
    # Triggers
    "TriggerRule",
    "TriggerAction",
    "TRIGGER_RULES",
    "match_finding",
    "get_recommendations_for_finding",
    # Engine
    "RecommendationEngine",
    # Converters
    "findings_from_enumeration",
    "findings_from_smb_crawl",
    "findings_from_group_memberships",
    # SMB Integration
    "process_smb_crawl",
    "SMBCrawlSummary",
    "generate_smb_crawl_command",
    "generate_file_retrieval_commands",
    "display_smb_summary",
    # SQLite Integration
    "process_sqlite_hunt",
    "SqliteHuntSummary",
    "display_sqlite_summary",
    "sqlite_hunt_and_display",
    # BloodHound Analyzer
    "BloodHoundAnalyzer",
    "bloodhound_analyze_for_user",
    # Attack Chains
    "AttackChain",
    "ChainStep",
    "ChainStatus",
    "ChainDetector",
    "ATTACK_CHAINS",
    "EXCHANGE_DCSYNC_CHAIN",
    "detect_attack_chains",
    "get_chain_summary",
]
