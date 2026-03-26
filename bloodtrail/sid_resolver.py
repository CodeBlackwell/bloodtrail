"""
SID Resolver - Maps Security Identifiers to Names

Builds a cache from BloodHound JSON exports and resolves SIDs to
human-readable names with object types.

Supports both directory and ZIP file data sources.
"""

import json
import re
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Union
from dataclasses import dataclass, field

from .config import WELL_KNOWN_SIDS, DOMAIN_RIDS
from .data_source import DataSource, create_data_source


@dataclass
class ResolverStats:
    """Statistics from SID resolution"""
    total_resolved: int = 0
    from_cache: int = 0
    from_wellknown: int = 0
    from_domain_rid: int = 0
    unresolved: int = 0
    unresolved_sids: List[str] = field(default_factory=list)


class SIDResolver:
    """
    Resolves Security Identifiers (SIDs) to names and object types.

    Builds a cache from BloodHound JSON exports and handles:
    - Well-known SIDs (BUILTIN groups, special identities)
    - Domain-relative RIDs (Administrator, Domain Admins, etc.)
    - Custom objects from BloodHound collection

    Example:
        resolver = SIDResolver(Path("/path/to/bh/json"))
        name, obj_type = resolver.resolve("S-1-5-21-xxx-512")
        # Returns ("DOMAIN ADMINS@DOMAIN.COM", "Group")
    """

    def __init__(self, bh_data_source: Optional[Union[Path, DataSource]] = None):
        """
        Initialize the SID resolver.

        Args:
            bh_data_source: Path to directory/ZIP or DataSource object
        """
        self._cache: Dict[str, Tuple[str, str]] = {}
        self._domain_sids: Dict[str, str] = {}  # domain_sid -> domain_name
        self.stats = ResolverStats()

        # Load well-known SIDs first
        self._cache.update(WELL_KNOWN_SIDS)

        # Load from BloodHound data if provided
        if bh_data_source:
            self._load_all_sids(bh_data_source)

    def resolve(self, sid: str) -> Tuple[str, str]:
        """
        Resolve a SID to (name, object_type).

        Returns:
            Tuple of (name, object_type) or (sid, "Unknown") if unresolved
        """
        self.stats.total_resolved += 1

        # Check direct cache first
        if sid in self._cache:
            self.stats.from_cache += 1
            return self._cache[sid]

        # Check well-known SIDs
        if sid in WELL_KNOWN_SIDS:
            self.stats.from_wellknown += 1
            return WELL_KNOWN_SIDS[sid]

        # Try domain-relative RID resolution
        resolved = self._resolve_domain_rid(sid)
        if resolved:
            self.stats.from_domain_rid += 1
            return resolved

        # Handle domain-prefixed SIDs (e.g., "CORP.COM-S-1-5-32-544")
        if "-S-1-5-" in sid:
            # Extract the SID portion after domain prefix
            parts = sid.split("-S-1-5-")
            if len(parts) == 2:
                domain_prefix = parts[0]
                raw_sid = "S-1-5-" + parts[1]

                # Try resolving the raw SID
                if raw_sid in self._cache:
                    name, obj_type = self._cache[raw_sid]
                    # Prefix with domain if not already present
                    if "@" not in name and domain_prefix:
                        name = f"{name}@{domain_prefix}"
                    return (name, obj_type)

                if raw_sid in WELL_KNOWN_SIDS:
                    name, obj_type = WELL_KNOWN_SIDS[raw_sid]
                    if "@" not in name and domain_prefix:
                        name = f"{name}@{domain_prefix}"
                    return (name, obj_type)

        # Unresolved
        self.stats.unresolved += 1
        if sid not in self.stats.unresolved_sids:
            self.stats.unresolved_sids.append(sid)
        return (sid, "Unknown")

    def _resolve_domain_rid(self, sid: str) -> Optional[Tuple[str, str]]:
        """
        Resolve domain-relative RIDs like S-1-5-21-xxx-xxx-xxx-512 (Domain Admins)
        """
        # Pattern: S-1-5-21-{domain_id_parts}-{RID}
        match = re.match(r"^(S-1-5-21-\d+-\d+-\d+)-(\d+)$", sid)
        if not match:
            return None

        domain_sid = match.group(1)
        rid = int(match.group(2))

        if rid in DOMAIN_RIDS:
            base_name, obj_type = DOMAIN_RIDS[rid]
            # Get domain name if known
            domain_name = self._domain_sids.get(domain_sid, "UNKNOWN")
            full_name = f"{base_name.upper()}@{domain_name}"
            return (full_name, obj_type)

        return None

    def _load_all_sids(self, data_source: Union[Path, DataSource]):
        """Load SIDs from all BloodHound JSON files in directory or ZIP"""
        # Convert Path to DataSource if needed
        if isinstance(data_source, (str, Path)):
            data_source = create_data_source(Path(data_source))

        json_files = data_source.list_json_files()
        if not json_files:
            raise FileNotFoundError(f"No JSON files found in: {data_source.source_path}")

        # Load each file type using the data source iterator
        for filename, data in data_source.iter_json_files():
            fname = filename.lower()

            # Extract based on file type
            if "users" in fname:
                self._extract_from_objects(data, "User")
            elif "computers" in fname:
                self._extract_from_objects(data, "Computer")
            elif "groups" in fname:
                self._extract_from_objects(data, "Group")
            elif "domains" in fname:
                self._extract_domains(data)
            elif "gpos" in fname:
                self._extract_from_objects(data, "GPO")
            elif "ous" in fname:
                self._extract_from_objects(data, "OU")
            elif "containers" in fname:
                self._extract_from_objects(data, "Container")

    def _extract_from_objects(self, data: dict, obj_type: str):
        """Extract SID→Name mappings from BloodHound objects"""
        for item in data.get("data", []):
            sid = item.get("ObjectIdentifier")
            name = item.get("Properties", {}).get("name")

            if sid and name:
                self._cache[sid] = (name, obj_type)

    def _extract_domains(self, data: dict):
        """Extract domain information and SID mappings"""
        for item in data.get("data", []):
            sid = item.get("ObjectIdentifier")
            name = item.get("Properties", {}).get("name")
            domain_sid = item.get("Properties", {}).get("domainsid")

            if sid and name:
                self._cache[sid] = (name, "Domain")

            # Track domain SID → domain name for RID resolution
            if domain_sid and name:
                self._domain_sids[domain_sid] = name

    def get_stats(self) -> dict:
        """Return resolution statistics"""
        return {
            "total_resolved": self.stats.total_resolved,
            "from_cache": self.stats.from_cache,
            "from_wellknown": self.stats.from_wellknown,
            "from_domain_rid": self.stats.from_domain_rid,
            "unresolved": self.stats.unresolved,
            "unresolved_sids": self.stats.unresolved_sids[:10],  # First 10
            "cache_size": len(self._cache),
            "domains_tracked": len(self._domain_sids),
        }

    def __len__(self):
        return len(self._cache)

    def __contains__(self, sid: str):
        return sid in self._cache
