"""
Result aggregation from multiple enumerators.

Merges and deduplicates results, then converts to CommandSuggester format.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from .base import EnumerationResult


@dataclass
class AggregatedResult:
    """
    Combined results from all enumerators.

    Provides unified view with deduplication.
    """
    # Metadata
    target: str
    successful_enumerators: List[str] = field(default_factory=list)
    failed_enumerators: List[str] = field(default_factory=list)

    # Domain info (first non-null wins)
    domain: Optional[str] = None
    dc_hostname: Optional[str] = None
    dc_ip: Optional[str] = None

    # Deduplicated entities (keyed by normalized name)
    users: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    computers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    shares: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Password policy (take first available)
    password_policy: Optional[Dict[str, Any]] = None

    # Per-enumerator results for debugging
    raw_results: List[EnumerationResult] = field(default_factory=list)

    # Additional metadata (guest access, etc.)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_query_records(self) -> Dict[str, List[Dict]]:
        """
        Convert aggregated results to CommandSuggester format.

        Returns dict mapping query_id -> list of records, matching
        the format expected by CommandSuggester.build_command_tables().
        """
        records: Dict[str, List[Dict]] = {}

        # AS-REP roastable users
        asrep_users = [
            {
                "User": data.get("upn", data.get("name", "")),
                "name": data.get("name", ""),
                "enabled": data.get("enabled", True),
            }
            for data in self.users.values()
            if data.get("asrep") and data.get("enabled", True)
        ]
        if asrep_users:
            records["quick-asrep-roastable"] = asrep_users

        # Kerberoastable users (have SPNs)
        spn_users = [
            {
                "User": data.get("upn", data.get("name", "")),
                "name": data.get("name", ""),
                "spns": data.get("spns", []),
                "enabled": data.get("enabled", True),
            }
            for data in self.users.values()
            if data.get("spn") and data.get("enabled", True)
        ]
        if spn_users:
            records["quick-kerberoast-targets"] = spn_users

        # Password policy for spray recommendations
        if self.password_policy:
            records["enum-password-policy"] = [{
                "domain": self.domain,
                "lockout_threshold": self.password_policy.get("lockout_threshold", 0),
                "lockout_duration": self.password_policy.get("lockout_duration", 30),
                "lockout_window": self.password_policy.get("lockout_window", 30),
                "complexity": self.password_policy.get("complexity", False),
                "min_length": self.password_policy.get("min_length", 0),
            }]

        # All enabled users for spray wordlist
        enabled_users = [
            {
                "User": data.get("upn", data.get("name", "")),
                "name": data.get("name", ""),
                "is_service": data.get("is_service", False),
            }
            for data in self.users.values()
            if data.get("enabled", True)
        ]
        if enabled_users:
            records["enum-user-list"] = enabled_users

        return records

    @property
    def asrep_roastable_users(self) -> List[Dict[str, Any]]:
        """Get list of AS-REP roastable users"""
        return [
            u for u in self.users.values()
            if u.get("asrep") and u.get("enabled", True)
        ]

    @property
    def service_accounts(self) -> List[Dict[str, Any]]:
        """Get list of service accounts"""
        return [
            u for u in self.users.values()
            if u.get("is_service") and u.get("enabled", True)
        ]

    @property
    def spray_safe_attempts(self) -> int:
        """Get safe number of spray attempts based on policy"""
        if not self.password_policy:
            return 1  # Conservative default
        threshold = self.password_policy.get("lockout_threshold", 0)
        if threshold == 0:
            return 999  # No lockout
        return max(1, threshold - 1)


def aggregate_results(results: List[EnumerationResult]) -> AggregatedResult:
    """
    Merge results from multiple enumerators.

    Deduplication strategy:
    - Users: Merge by username (case-insensitive), combine properties
    - Computers: Merge by FQDN
    - Groups: Merge by name
    - Shares: Merge by name
    """
    if not results:
        return AggregatedResult(target="")

    agg = AggregatedResult(
        target=results[0].dc_ip or "",
        raw_results=results
    )

    for result in results:
        if not result.success:
            agg.failed_enumerators.append(result.enumerator_id)
            continue

        agg.successful_enumerators.append(result.enumerator_id)

        # Domain info (first non-null wins)
        if not agg.domain and result.domain:
            agg.domain = result.domain
        if not agg.dc_hostname and result.dc_hostname:
            agg.dc_hostname = result.dc_hostname
        if not agg.dc_ip and result.dc_ip:
            agg.dc_ip = result.dc_ip

        # Merge users by name (case-insensitive)
        for user in result.users:
            key = user.get("name", "").lower()
            if not key:
                continue

            if key not in agg.users:
                agg.users[key] = user.copy()
            else:
                # Merge properties, prefer true for boolean security flags
                existing = agg.users[key]
                for k, v in user.items():
                    if k not in existing or existing[k] is None:
                        existing[k] = v
                    elif k in ("asrep", "spn", "pwnotreq", "pwnoexp"):
                        # For security flags, True wins (more conservative)
                        existing[k] = existing.get(k, False) or v
                    elif k == "spns" and isinstance(v, list):
                        # Merge SPN lists
                        existing_spns = set(existing.get("spns", []))
                        existing_spns.update(v)
                        existing["spns"] = list(existing_spns)

        # Merge computers
        for computer in result.computers:
            key = computer.get("fqdn", computer.get("name", "")).lower()
            if key and key not in agg.computers:
                agg.computers[key] = computer.copy()

        # Merge groups
        for group in result.groups:
            key = group.get("name", "").lower()
            if key and key not in agg.groups:
                agg.groups[key] = group.copy()

        # Merge shares
        for share in result.shares:
            key = share.get("name", "").lower()
            if key and key not in agg.shares:
                agg.shares[key] = share.copy()

        # Password policy (first one wins)
        if not agg.password_policy and result.password_policy:
            agg.password_policy = result.password_policy.copy()

    return agg
