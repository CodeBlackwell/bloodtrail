"""
Base dataclasses for bloodtrail command mappings.

Shared data structures used across mapping modules.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class TechniqueInfo:
    """
    Lateral movement technique metadata for educational command suggestions.

    Each technique provides multiple command templates (one per credential type)
    along with OSCP-relevant context about when, why, and how to use it.
    """
    name: str                           # Human-readable technique name
    command_templates: Dict[str, str]   # cred_type -> command template
    ports: List[int]                    # Required network ports
    requirements: List[str]             # Prerequisites for this technique
    noise_level: str                    # Detection risk: low, medium, high
    advantages: str                     # Why use this technique
    disadvantages: str                  # Limitations / risks
    oscp_relevance: str                 # OSCP exam relevance: high, medium, low


@dataclass
class AccessTypeInfo:
    """Consolidated metadata for a BloodHound access type (edge)."""
    reward: str
    phase: str
    priority: int
    reason_template: str


@dataclass
class SprayTechniqueInfo:
    """
    Password spray technique metadata for educational command suggestions.

    Each technique provides command templates and operational context
    for safe password spraying operations.
    """
    name: str
    description: str
    command_templates: Dict[str, str]   # template_name -> command template
    ports: List[int]                    # Required network ports
    requirements: List[str]             # Prerequisites
    noise_level: str                    # Detection risk: low, medium, high
    advantages: str                     # Why use this technique
    disadvantages: str                  # Limitations / risks
    oscp_relevance: str                 # OSCP exam relevance
    best_for: List[str]                 # Ideal scenarios
