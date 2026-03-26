"""
Target Sources for Auto Password Spray

Generates target lists for password spraying:
- Users: Usernames to spray against (from Neo4j or custom file)
- Machines: Target IPs/hostnames to spray (from Neo4j or custom file)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Dict, Any


@dataclass
class Target:
    """
    Single target with metadata.

    Attributes:
        value: The target value (username or IP/hostname)
        target_type: Type of target ('user' or 'machine')
        source: Where this came from (neo4j, file)
        metadata: Additional info (e.g., access type, enabled status)
    """
    value: str
    target_type: str  # 'user' or 'machine'
    source: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.value, self.target_type))

    def __eq__(self, other):
        if not isinstance(other, Target):
            return False
        return self.value == other.value and self.target_type == other.target_type


class TargetSource(ABC):
    """Abstract base class for target sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable source name."""
        pass

    @property
    @abstractmethod
    def target_type(self) -> str:
        """Type of targets this source provides ('user' or 'machine')."""
        pass

    @abstractmethod
    def get_targets(self) -> List[Target]:
        """Retrieve targets from this source."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this source is accessible."""
        pass

    def get_values(self) -> List[str]:
        """Get just the target values (convenience method)."""
        return [t.value for t in self.get_targets()]


class Neo4jUserSource(TargetSource):
    """
    Extract users from Neo4j BloodHound data.

    Supports filtering by:
    - Enabled/disabled status
    - Already pwned status
    - All users
    """

    def __init__(self, neo4j_config, user_filter: str = "enabled"):
        """
        Initialize Neo4j user source.

        Args:
            neo4j_config: Neo4jConfig object with connection details
            user_filter: Filter mode - 'all', 'enabled', 'non-pwned'
        """
        self.config = neo4j_config
        self.user_filter = user_filter
        self._driver = None

    @property
    def name(self) -> str:
        return f"Neo4j Users ({self.user_filter})"

    @property
    def target_type(self) -> str:
        return "user"

    def _connect(self):
        """Establish Neo4j connection."""
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
        return self._driver

    def is_available(self) -> bool:
        """Check if Neo4j is accessible."""
        try:
            driver = self._connect()
            with driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception:
            return False

    def get_targets(self) -> List[Target]:
        """Extract users based on filter."""
        if not self.is_available():
            return []

        targets = []

        try:
            driver = self._connect()
            with driver.session() as session:
                # Build query based on filter
                if self.user_filter == "all":
                    query = """
                        MATCH (u:User)
                        WHERE u.samaccountname IS NOT NULL
                          AND NOT u.name STARTS WITH 'KRBTGT'
                          AND NOT u.name STARTS WITH 'NT AUTHORITY'
                          AND NOT u.name CONTAINS '$'
                        RETURN u.samaccountname AS username,
                               u.enabled AS enabled,
                               u.pwned AS pwned
                        ORDER BY u.samaccountname
                    """
                elif self.user_filter == "non-pwned":
                    query = """
                        MATCH (u:User)
                        WHERE u.enabled = true
                          AND u.samaccountname IS NOT NULL
                          AND NOT u.name STARTS WITH 'KRBTGT'
                          AND NOT u.name STARTS WITH 'NT AUTHORITY'
                          AND NOT u.name CONTAINS '$'
                          AND (u.pwned IS NULL OR u.pwned = false)
                        RETURN u.samaccountname AS username,
                               u.enabled AS enabled,
                               u.pwned AS pwned
                        ORDER BY u.samaccountname
                    """
                else:  # enabled (default)
                    query = """
                        MATCH (u:User)
                        WHERE u.enabled = true
                          AND u.samaccountname IS NOT NULL
                          AND NOT u.name STARTS WITH 'KRBTGT'
                          AND NOT u.name STARTS WITH 'NT AUTHORITY'
                          AND NOT u.name CONTAINS '$'
                        RETURN u.samaccountname AS username,
                               u.enabled AS enabled,
                               u.pwned AS pwned
                        ORDER BY u.samaccountname
                    """

                result = session.run(query)

                for record in result:
                    username = record["username"]
                    if username:
                        targets.append(Target(
                            value=username,
                            target_type="user",
                            source="neo4j",
                            metadata={
                                "enabled": record.get("enabled", True),
                                "pwned": record.get("pwned", False),
                            }
                        ))

        except Exception:
            pass

        return targets

    def close(self):
        """Close Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._driver = None


class Neo4jMachineSource(TargetSource):
    """
    Extract machines/computers from Neo4j BloodHound data.

    Extracts computers with their IPs for targeting in spray attacks.
    """

    def __init__(self, neo4j_config, include_dc: bool = True, enabled_only: bool = True):
        """
        Initialize Neo4j machine source.

        Args:
            neo4j_config: Neo4jConfig object with connection details
            include_dc: Include domain controllers
            enabled_only: Only include enabled computers
        """
        self.config = neo4j_config
        self.include_dc = include_dc
        self.enabled_only = enabled_only
        self._driver = None

    @property
    def name(self) -> str:
        return "Neo4j Machines"

    @property
    def target_type(self) -> str:
        return "machine"

    def _connect(self):
        """Establish Neo4j connection."""
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
        return self._driver

    def is_available(self) -> bool:
        """Check if Neo4j is accessible."""
        try:
            driver = self._connect()
            with driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception:
            return False

    def get_targets(self) -> List[Target]:
        """Extract machines with IPs."""
        if not self.is_available():
            return []

        targets = []

        try:
            driver = self._connect()
            with driver.session() as session:
                # Query for computers with IPs
                # bloodtrail_ip is set by bloodtrail, also check BloodHound's properties
                query = """
                    MATCH (c:Computer)
                    WHERE c.name IS NOT NULL
                """

                if self.enabled_only:
                    query += " AND (c.enabled IS NULL OR c.enabled = true)"

                query += """
                    RETURN c.name AS hostname,
                           COALESCE(c.bloodtrail_ip, c.lastlogontimestamp) AS ip,
                           c.operatingsystem AS os,
                           c.enabled AS enabled,
                           EXISTS((c)<-[:MemberOf*1..]-(:Group {name: 'DOMAIN CONTROLLERS@' + split(c.name, '@')[1]})) AS is_dc
                    ORDER BY c.name
                """

                result = session.run(query)

                for record in result:
                    hostname = record["hostname"]
                    ip = record.get("ip")
                    is_dc = record.get("is_dc", False)

                    # Skip DCs if not included
                    if is_dc and not self.include_dc:
                        continue

                    if hostname:
                        # Use IP if available, otherwise hostname
                        value = ip if ip and self._is_valid_ip(ip) else hostname
                        targets.append(Target(
                            value=value,
                            target_type="machine",
                            source="neo4j",
                            metadata={
                                "hostname": hostname,
                                "ip": ip,
                                "os": record.get("os"),
                                "is_dc": is_dc,
                                "enabled": record.get("enabled", True),
                            }
                        ))

        except Exception:
            pass

        return targets

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        """Check if value looks like an IP address."""
        if not value:
            return False
        parts = str(value).split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def close(self):
        """Close Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._driver = None


class FileTargetSource(TargetSource):
    """
    User-specified target file (users or machines).

    Reads targets from a text file (one per line).
    """

    def __init__(self, file_path: Path, target_type: str = "user"):
        """
        Initialize file target source.

        Args:
            file_path: Path to target file
            target_type: Type of targets ('user' or 'machine')
        """
        self.path = Path(file_path)
        self._target_type = target_type

    @property
    def name(self) -> str:
        return f"File ({self.path.name})"

    @property
    def target_type(self) -> str:
        return self._target_type

    def is_available(self) -> bool:
        """Check if file exists and is readable."""
        return self.path.exists() and self.path.is_file()

    def get_targets(self) -> List[Target]:
        """Read targets from file."""
        if not self.is_available():
            return []

        targets = []

        try:
            with open(self.path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    value = line.strip()
                    if value and not value.startswith('#'):
                        targets.append(Target(
                            value=value,
                            target_type=self._target_type,
                            source="file",
                        ))
        except Exception:
            pass

        return targets


@dataclass
class TargetManager:
    """
    Orchestrates target gathering from multiple sources.

    Handles:
    - Adding/removing sources
    - Deduplication across sources
    - Filtering by target type
    - Statistics tracking
    """

    user_sources: List[TargetSource] = field(default_factory=list)
    machine_sources: List[TargetSource] = field(default_factory=list)

    def add_user_source(self, source: TargetSource) -> None:
        """Add a user target source."""
        if source.target_type == "user":
            self.user_sources.append(source)

    def add_machine_source(self, source: TargetSource) -> None:
        """Add a machine target source."""
        if source.target_type == "machine":
            self.machine_sources.append(source)

    def get_users(self) -> List[str]:
        """
        Get unique usernames from all user sources.

        Returns:
            List of unique usernames
        """
        seen: Set[str] = set()
        users: List[str] = []

        for source in self.user_sources:
            if not source.is_available():
                continue

            for target in source.get_targets():
                if target.value not in seen:
                    seen.add(target.value)
                    users.append(target.value)

        return users

    def get_machines(self) -> List[str]:
        """
        Get unique machine IPs/hostnames from all machine sources.

        Returns:
            List of unique machine targets
        """
        seen: Set[str] = set()
        machines: List[str] = []

        for source in self.machine_sources:
            if not source.is_available():
                continue

            for target in source.get_targets():
                if target.value not in seen:
                    seen.add(target.value)
                    machines.append(target.value)

        return machines

    def get_statistics(self) -> dict:
        """
        Get statistics about available targets.

        Returns:
            Dict with counts by source and type
        """
        users = self.get_users()
        machines = self.get_machines()

        return {
            "user_count": len(users),
            "machine_count": len(machines),
            "user_sources": [s.name for s in self.user_sources if s.is_available()],
            "machine_sources": [s.name for s in self.machine_sources if s.is_available()],
            "user_sources_unavailable": [s.name for s in self.user_sources if not s.is_available()],
            "machine_sources_unavailable": [s.name for s in self.machine_sources if not s.is_available()],
        }
