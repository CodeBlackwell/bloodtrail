"""
BloodTrail Interactive Mode.

User interaction handlers for the recommendation engine.
"""

from .session import InteractiveSession
from .display import (
    display_finding,
    display_recommendation,
    display_stats,
)

__all__ = [
    "InteractiveSession",
    "display_finding",
    "display_recommendation",
    "display_stats",
]
