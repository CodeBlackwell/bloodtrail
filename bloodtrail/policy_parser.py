"""
Password Policy Parser

Parse Windows 'net accounts' output into structured policy data for safe
password spraying operations.

Usage:
    from bloodtrail.policy_parser import parse_net_accounts, PasswordPolicy

    # Parse net accounts output
    policy = parse_net_accounts('''
        Lockout threshold:                        5
        Lockout duration (minutes):               30
        Lockout observation window (minutes):     30
    ''')

    # Use safe spray parameters
    print(f"Safe attempts: {policy.safe_spray_attempts}")
    print(f"Delay between rounds: {policy.spray_delay_minutes} minutes")
"""

from dataclasses import dataclass
from typing import Optional
import re


@dataclass
class PasswordPolicy:
    """
    Domain password policy settings.

    Stores lockout and password complexity requirements for safe spray planning.
    """
    lockout_threshold: int = 0       # Failed attempts before lockout (0 = no lockout)
    lockout_duration: int = 30       # Minutes account stays locked
    observation_window: int = 30     # Minutes before failed attempt counter resets
    min_length: int = 0              # Minimum password length
    max_age: int = 0                 # Days until password expires (0 = never)
    min_age: int = 0                 # Days before password can be changed
    history: int = 0                 # Number of previous passwords remembered

    @property
    def safe_spray_attempts(self) -> int:
        """
        Calculate safe number of spray attempts per observation window.

        Uses threshold - 1 to avoid lockout (e.g., if threshold is 5, spray 4).
        Returns 999 if no lockout policy is configured.

        Returns:
            Maximum safe attempts before risk of lockout
        """
        if self.lockout_threshold == 0:
            return 999  # No lockout policy - but still recommend caution
        return max(1, self.lockout_threshold - 1)

    @property
    def spray_delay_minutes(self) -> int:
        """
        Recommended delay between spray rounds in minutes.

        Uses observation window if set (counter resets after this time),
        otherwise falls back to lockout duration.

        Returns:
            Minutes to wait between spray rounds
        """
        if self.observation_window > 0:
            return self.observation_window
        if self.lockout_duration > 0:
            return self.lockout_duration
        return 30  # Conservative default

    @property
    def has_lockout(self) -> bool:
        """Check if lockout policy is configured."""
        return self.lockout_threshold > 0

    def to_dict(self) -> dict:
        """Convert to dictionary for Neo4j storage."""
        return {
            "lockout_threshold": self.lockout_threshold,
            "lockout_duration": self.lockout_duration,
            "observation_window": self.observation_window,
            "min_length": self.min_length,
            "max_age": self.max_age,
            "min_age": self.min_age,
            "history": self.history,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordPolicy":
        """Create from dictionary (Neo4j retrieval)."""
        return cls(
            lockout_threshold=data.get("lockout_threshold", 0),
            lockout_duration=data.get("lockout_duration", 30),
            observation_window=data.get("observation_window", 30),
            min_length=data.get("min_length", 0),
            max_age=data.get("max_age", 0),
            min_age=data.get("min_age", 0),
            history=data.get("history", 0),
        )


def _extract_int(pattern: str, text: str, default: int = 0) -> int:
    """
    Extract integer value from text using regex pattern.

    Handles special values like 'Never', 'None', 'Unlimited'.

    Args:
        pattern: Regex pattern with one capture group for the value
        text: Text to search
        default: Value to return if not found or invalid

    Returns:
        Extracted integer or default
    """
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    if match:
        value = match.group(1).strip()
        # Handle special string values
        if value.lower() in ('never', 'none', 'unlimited', 'n/a'):
            return 0
        try:
            return int(value)
        except ValueError:
            return default
    return default


def parse_net_accounts(output: str) -> PasswordPolicy:
    """
    Parse Windows 'net accounts' command output.

    Example input:
        Force user logoff how long after time expires?:       Never
        Minimum password age (days):                          1
        Maximum password age (days):                          42
        Minimum password length:                              7
        Length of password history maintained:                24
        Lockout threshold:                                    5
        Lockout duration (minutes):                           30
        Lockout observation window (minutes):                 30
        Computer role:                                        PRIMARY

    Also handles 'net accounts /domain' output format.

    Args:
        output: Raw output from 'net accounts' or 'net accounts /domain'

    Returns:
        PasswordPolicy dataclass with parsed values
    """
    return PasswordPolicy(
        lockout_threshold=_extract_int(
            r'Lockout threshold[:\s]+(\d+|Never)',
            output,
            default=0
        ),
        lockout_duration=_extract_int(
            r'Lockout duration[^\d]*(\d+|Never)',
            output,
            default=30
        ),
        observation_window=_extract_int(
            r'Lockout observation window[^\d]*(\d+|Never)',
            output,
            default=30
        ),
        min_length=_extract_int(
            r'Minimum password length[:\s]+(\d+)',
            output,
            default=0
        ),
        max_age=_extract_int(
            r'Maximum password age[^\d]*(\d+|Unlimited)',
            output,
            default=0
        ),
        min_age=_extract_int(
            r'Minimum password age[^\d]*(\d+)',
            output,
            default=0
        ),
        history=_extract_int(
            r'(?:Length of )?password history[^\d]*(\d+|None)',
            output,
            default=0
        ),
    )


def format_policy_display(policy: PasswordPolicy) -> str:
    """
    Format policy for terminal display.

    Args:
        policy: PasswordPolicy to format

    Returns:
        Formatted string for display
    """
    lines = [
        "Password Policy",
        "=" * 40,
        f"  Lockout threshold:     {policy.lockout_threshold} attempts" +
            (" (no lockout)" if policy.lockout_threshold == 0 else ""),
        f"  Lockout duration:      {policy.lockout_duration} minutes",
        f"  Observation window:    {policy.observation_window} minutes",
        f"  Min password length:   {policy.min_length} characters",
        f"  Max password age:      {policy.max_age} days" +
            (" (never expires)" if policy.max_age == 0 else ""),
        "",
        "Safe Spray Parameters",
        "-" * 40,
        f"  Attempts per round:    {policy.safe_spray_attempts}",
        f"  Delay between rounds:  {policy.spray_delay_minutes} minutes",
    ]

    if not policy.has_lockout:
        lines.append("")
        lines.append("  WARNING: No lockout policy detected!")
        lines.append("  Exercise caution - may still have monitoring.")

    return "\n".join(lines)
