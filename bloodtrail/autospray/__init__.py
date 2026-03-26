"""
Auto Password Spray Module for BloodTrail

Provides automated password spraying with:
- Target sources (users and machines from Neo4j or custom files)
- Credential sources (Neo4j pwned users, wordlists, potfiles)
- Policy-aware lockout protection
- Multiple tool support (kerbrute, crackmapexec, netexec, hydra)
- Script generation (default) or auto-execution modes

Usage:
    crack bt --auto-spray                    # Generate scripts for review
    crack bt --auto-spray --execute          # Execute with confirmation
    crack bt --auto-spray --spray-tool kerbrute --cred-source neo4j
"""

from .credential_sources import (
    CredentialSource,
    CredentialManager,
    Neo4jCredentialSource,
    WordlistSource,
    PotfileSource,
)
from .target_sources import (
    TargetSource,
    TargetManager,
    Neo4jUserSource,
    Neo4jMachineSource,
    FileTargetSource,
    Target,
)
from .lockout_manager import LockoutManager, SprayWindow
from .executor import SprayExecutor, SprayTool, ToolConfig, SprayResult
from .result_parser import ResultParser, ParsedResult
from .script_generator import ScriptGenerator

__all__ = [
    # Credential sources
    "CredentialSource",
    "CredentialManager",
    "Neo4jCredentialSource",
    "WordlistSource",
    "PotfileSource",
    # Target sources
    "TargetSource",
    "TargetManager",
    "Neo4jUserSource",
    "Neo4jMachineSource",
    "FileTargetSource",
    "Target",
    # Lockout management
    "LockoutManager",
    "SprayWindow",
    # Execution
    "SprayExecutor",
    "SprayTool",
    "ToolConfig",
    "SprayResult",
    # Result parsing
    "ResultParser",
    "ParsedResult",
    # Script generation
    "ScriptGenerator",
]
