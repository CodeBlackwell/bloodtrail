"""
BloodTrail Auto-Execute Module

Provides automatic attack chain execution:
- AutoOrchestrator: Main loop that chains credential discovery
- Output parsers: Detect success/failure from tool output
- State persistence: Resume interrupted sessions
"""

from .orchestrator import AutoOrchestrator, ExecutionStatus, ChainState
from .output_parsers import (
    ParsedOutput,
    parse_crackmapexec,
    parse_smbmap,
    parse_ldapsearch,
)

__all__ = [
    "AutoOrchestrator",
    "ExecutionStatus",
    "ChainState",
    "ParsedOutput",
    "parse_crackmapexec",
    "parse_smbmap",
    "parse_ldapsearch",
]
