"""
BloodHound Trail - Pwned User Tracking

Track compromised users in Neo4j with credential context and provide
follow-up commands based on their access level to machines.

Usage:
    tracker = PwnedTracker(Neo4jConfig())
    tracker.connect()

    # Mark user as pwned
    result = tracker.mark_pwned(
        "PETE@CORP.COM",
        cred_type="password",
        cred_value="Summer2024!",
        source_machine="CLIENT75.CORP.COM",
        notes="From SAM dump"
    )

    # Get follow-up commands for pwned user
    access = tracker.get_pwned_user_access("PETE@CORP.COM")

    # List all pwned users
    pwned = tracker.list_pwned_users()
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
import time

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from .config import Neo4jConfig
from .policy_parser import PasswordPolicy


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class MachineAccess:
    """Access entry for a pwned user on a machine."""
    computer: str
    access_types: List[str]  # AdminTo, CanRDP, CanPSRemote, etc.
    privilege_level: str     # local-admin, user-level, dcom-exec
    sessions: List[str] = field(default_factory=list)  # Privileged users with sessions
    computer_ip: Optional[str] = None  # Resolved IP address from Neo4j


@dataclass
class PwnedUser:
    """Represents a pwned user with metadata."""
    name: str
    pwned_at: datetime
    cred_types: List[str] = field(default_factory=list)   # Multiple credential types
    cred_values: List[str] = field(default_factory=list)  # Corresponding values (parallel arrays)
    source_machine: Optional[str] = None
    notes: Optional[str] = None
    access: List[MachineAccess] = field(default_factory=list)
    domain_level_access: Optional[str] = None  # domain-admin if DCSync/GenericAll on Domain
    gmsa_access: List[str] = field(default_factory=list)  # gMSA accounts user can read passwords for

    @property
    def cred_type(self) -> str:
        """Primary credential type (first in list) for backward compatibility."""
        return self.cred_types[0] if self.cred_types else "password"

    @property
    def cred_value(self) -> str:
        """Primary credential value (first in list) for backward compatibility."""
        return self.cred_values[0] if self.cred_values else ""

    def get_credential(self, cred_type: str) -> Optional[str]:
        """Get credential value for a specific type."""
        try:
            idx = self.cred_types.index(cred_type)
            return self.cred_values[idx]
        except (ValueError, IndexError):
            return None

    def has_credential_type(self, cred_type: str) -> bool:
        """Check if user has a specific credential type."""
        return cred_type in self.cred_types

    @property
    def username(self) -> str:
        """Extract username from UPN format."""
        if "@" in self.name:
            return self.name.split("@")[0]
        return self.name

    @property
    def domain(self) -> str:
        """Extract domain from UPN format."""
        if "@" in self.name:
            return self.name.split("@")[1]
        return ""


@dataclass
class PwnedResult:
    """Result from pwned tracking operations."""
    success: bool
    user: Optional[str] = None
    error: Optional[str] = None
    access: List[MachineAccess] = field(default_factory=list)
    domain_level_access: Optional[str] = None


# =============================================================================
# PRIVILEGE LEVEL MAPPING
# =============================================================================

# Map BloodHound edge types to privilege levels
EDGE_TO_PRIVILEGE = {
    "AdminTo": "local-admin",
    "CanRDP": "user-level",
    "CanPSRemote": "user-level",
    "ExecuteDCOM": "dcom-exec",
    "HasSession": "session-harvest",  # Not direct access, but cred harvest opportunity
    # Credential access edges (effective local-admin)
    "ReadLAPSPassword": "cred-access",
    "AllowedToAct": "rbcd-capable",
}

# Domain-level access edges (checked separately)
DOMAIN_ADMIN_EDGES = {"GetChanges", "GetChangesAll", "GenericAll", "DCSync"}


# =============================================================================
# CREDENTIAL TYPES
# =============================================================================

CRED_TYPES = {"password", "ntlm-hash", "kerberos-ticket", "certificate"}


# =============================================================================
# PWNED TRACKER CLASS
# =============================================================================

class PwnedTracker:
    """
    Tracks pwned users in Neo4j and provides follow-up command suggestions.

    Stores pwned state as Neo4j node properties on User nodes:
    - pwned: boolean
    - pwned_at: integer (Unix timestamp)
    - pwned_cred_types: array[string] (multiple credential types)
    - pwned_cred_values: array[string] (corresponding credential values - parallel array)
    - pwned_source_machine: string
    - pwned_notes: string

    Example:
        tracker = PwnedTracker(Neo4jConfig())
        tracker.connect()

        # Mark user as pwned
        result = tracker.mark_pwned(
            "PETE@CORP.COM",
            cred_type="password",
            cred_value="Summer2024!",
            source_machine="CLIENT75.CORP.COM"
        )

        # Show follow-up commands
        if result.success:
            for access in result.access:
                print(f"{access.computer}: {access.privilege_level}")
    """

    def __init__(self, config: Neo4jConfig):
        self.config = config
        self.driver = None

    def connect(self) -> bool:
        """Connect to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except (ServiceUnavailable, AuthError) as e:
            self.driver = None
            return False

    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            self.driver = None

    def _ensure_connected(self) -> bool:
        """Ensure we have a valid connection."""
        if self.driver is None:
            return self.connect()
        return True

    # =========================================================================
    # MARK/UNMARK PWNED
    # =========================================================================

    def mark_pwned(
        self,
        user: str,
        cred_type: str,
        cred_value: str,
        source_machine: Optional[str] = None,
        notes: Optional[str] = None
    ) -> PwnedResult:
        """
        Mark a user as pwned in Neo4j.

        Args:
            user: User principal name (UPN format: USER@DOMAIN.COM)
            cred_type: Credential type (password, ntlm-hash, kerberos-ticket, certificate)
            cred_value: The actual credential (stored for auto-fill in commands)
            source_machine: Machine where credential was obtained
            notes: Additional notes about the compromise

        Returns:
            PwnedResult with success status and user's access paths
        """
        # Validate cred_type
        if cred_type not in CRED_TYPES:
            return PwnedResult(
                success=False,
                error=f"Invalid cred_type: {cred_type}. Must be one of: {', '.join(CRED_TYPES)}"
            )

        # Normalize user name to uppercase
        user = user.upper()

        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                # Check if user exists and get current credentials
                check_result = session.run("""
                    MATCH (u:User {name: $user_name})
                    RETURN u.name AS User,
                           u.pwned_cred_types AS CredTypes,
                           u.pwned_cred_values AS CredValues
                """, {"user_name": user})

                check_record = check_result.single()
                if not check_record:
                    return PwnedResult(
                        success=False,
                        error=f"User not found in BloodHound: {user}"
                    )

                # Get existing credentials or initialize empty arrays
                existing_types = check_record["CredTypes"] or []
                existing_values = check_record["CredValues"] or []

                # Check if this credential type already exists
                if cred_type in existing_types:
                    # Update existing credential value
                    idx = existing_types.index(cred_type)
                    existing_values[idx] = cred_value
                else:
                    # Append new credential
                    existing_types.append(cred_type)
                    existing_values.append(cred_value)

                # Mark user as pwned with updated credential arrays
                result = session.run("""
                    MATCH (u:User {name: $user_name})
                    SET u.pwned = true,
                        u.pwned_at = $timestamp,
                        u.pwned_cred_types = $cred_types,
                        u.pwned_cred_values = $cred_values,
                        u.pwned_source_machine = $source_machine,
                        u.pwned_notes = $notes
                    RETURN u.name AS User
                """, {
                    "user_name": user,
                    "timestamp": int(time.time()),
                    "cred_types": existing_types,
                    "cred_values": existing_values,
                    "source_machine": source_machine,
                    "notes": notes
                })

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error=f"Failed to update user: {user}"
                    )

                # Get user's access paths
                access = self._get_user_access(session, user)
                domain_level = self._get_domain_level_access(session, user)

                return PwnedResult(
                    success=True,
                    user=user,
                    access=access,
                    domain_level_access=domain_level
                )

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    def unmark_pwned(self, user: str) -> PwnedResult:
        """
        Remove pwned status from a user.

        Args:
            user: User principal name (UPN format)

        Returns:
            PwnedResult with success status
        """
        user = user.upper()

        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User {name: $user_name})
                    REMOVE u.pwned, u.pwned_at, u.pwned_cred_types,
                           u.pwned_cred_values, u.pwned_source_machine, u.pwned_notes
                    RETURN u.name AS User
                """, {"user_name": user})

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error=f"User not found: {user}"
                    )

                return PwnedResult(success=True, user=user)

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    def remove_credential(self, user: str, cred_type: str) -> PwnedResult:
        """
        Remove a specific credential type from a pwned user.

        Keeps arrays in sync - removes from both cred_types and cred_values.
        If no credentials remain, user stays pwned but with empty arrays.

        Args:
            user: User principal name (UPN format)
            cred_type: Credential type to remove (password, ntlm-hash, etc.)

        Returns:
            PwnedResult with success status
        """
        user = user.upper()

        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                # Get current credentials
                check_result = session.run("""
                    MATCH (u:User {name: $user_name})
                    WHERE u.pwned = true
                    RETURN u.pwned_cred_types AS CredTypes,
                           u.pwned_cred_values AS CredValues
                """, {"user_name": user})

                check_record = check_result.single()
                if not check_record:
                    return PwnedResult(
                        success=False,
                        error=f"User not found or not pwned: {user}"
                    )

                existing_types = list(check_record["CredTypes"] or [])
                existing_values = list(check_record["CredValues"] or [])

                # Check if credential type exists
                if cred_type not in existing_types:
                    return PwnedResult(
                        success=False,
                        error=f"Credential type '{cred_type}' not found for user {user}"
                    )

                # Remove from both arrays (keeping them in sync)
                idx = existing_types.index(cred_type)
                existing_types.pop(idx)
                existing_values.pop(idx)

                # Update user with new arrays
                result = session.run("""
                    MATCH (u:User {name: $user_name})
                    SET u.pwned_cred_types = $cred_types,
                        u.pwned_cred_values = $cred_values
                    RETURN u.name AS User
                """, {
                    "user_name": user,
                    "cred_types": existing_types,
                    "cred_values": existing_values
                })

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error=f"Failed to update user: {user}"
                    )

                return PwnedResult(success=True, user=user)

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    # =========================================================================
    # LIST/QUERY PWNED USERS
    # =========================================================================

    def list_pwned_users(self) -> List[PwnedUser]:
        """
        List all pwned users with their access paths.

        Returns:
            List of PwnedUser objects with access information
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User)
                    WHERE u.pwned = true
                    RETURN u.name AS User,
                           u.pwned_at AS PwnedAt,
                           u.pwned_cred_types AS CredTypes,
                           u.pwned_cred_values AS CredValues,
                           u.pwned_source_machine AS SourceMachine,
                           u.pwned_notes AS Notes
                    ORDER BY u.pwned_at DESC
                """)

                users = []
                for record in result:
                    user_name = record["User"]

                    # Get access for this user
                    access = self._get_user_access(session, user_name)
                    domain_level = self._get_domain_level_access(session, user_name)
                    gmsa = self._get_gmsa_access(session, user_name)

                    # Convert timestamp
                    pwned_at = record["PwnedAt"]
                    if pwned_at:
                        pwned_at = datetime.fromtimestamp(pwned_at)
                    else:
                        pwned_at = datetime.now()

                    # Handle arrays (with backward compat for old single-value data)
                    cred_types = record["CredTypes"] or []
                    cred_values = record["CredValues"] or []

                    users.append(PwnedUser(
                        name=user_name,
                        pwned_at=pwned_at,
                        cred_types=list(cred_types),
                        cred_values=list(cred_values),
                        source_machine=record["SourceMachine"],
                        notes=record["Notes"],
                        access=access,
                        domain_level_access=domain_level,
                        gmsa_access=gmsa,
                    ))

                return users

        except Exception:
            return []

    def get_pwned_user(self, user: str) -> Optional[PwnedUser]:
        """
        Get a specific pwned user's information.

        Args:
            user: User principal name (UPN format)

        Returns:
            PwnedUser object or None if not found/not pwned
        """
        user = user.upper()

        if not self._ensure_connected():
            return None

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User {name: $user_name})
                    WHERE u.pwned = true
                    RETURN u.name AS User,
                           u.pwned_at AS PwnedAt,
                           u.pwned_cred_types AS CredTypes,
                           u.pwned_cred_values AS CredValues,
                           u.pwned_source_machine AS SourceMachine,
                           u.pwned_notes AS Notes
                """, {"user_name": user})

                record = result.single()
                if not record:
                    return None

                access = self._get_user_access(session, user)
                domain_level = self._get_domain_level_access(session, user)
                gmsa = self._get_gmsa_access(session, user)

                pwned_at = record["PwnedAt"]
                if pwned_at:
                    pwned_at = datetime.fromtimestamp(pwned_at)
                else:
                    pwned_at = datetime.now()

                # Handle arrays
                cred_types = record["CredTypes"] or []
                cred_values = record["CredValues"] or []

                return PwnedUser(
                    name=user,
                    pwned_at=pwned_at,
                    cred_types=list(cred_types),
                    cred_values=list(cred_values),
                    source_machine=record["SourceMachine"],
                    notes=record["Notes"],
                    access=access,
                    domain_level_access=domain_level,
                    gmsa_access=gmsa,
                )

        except Exception:
            return None

    def is_pwned(self, user: str) -> bool:
        """
        Check if a user is marked as pwned.

        Args:
            user: User principal name (UPN format)

        Returns:
            True if user is pwned, False otherwise
        """
        user = user.upper()

        if not self._ensure_connected():
            return False

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User {name: $user_name})
                    RETURN u.pwned AS Pwned
                """, {"user_name": user})

                record = result.single()
                if record:
                    return record["Pwned"] == True
                return False

        except Exception:
            return False

    def get_user_spns(self, user: str) -> List[str]:
        """
        Get a user's Service Principal Names (SPNs).

        SPNs indicate which services a user account runs. Service accounts
        often have local admin access on machines where their services run,
        even if BloodHound doesn't detect this via AdminTo edges.

        Args:
            user: User principal name (UPN format)

        Returns:
            List of SPN strings (e.g., ["HTTP/web04.corp.com", "HTTP/web04"])
        """
        user = user.upper()

        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User {name: $user_name})
                    RETURN u.serviceprincipalnames AS SPNs
                """, {"user_name": user})

                record = result.single()
                if record and record["SPNs"]:
                    return list(record["SPNs"])
                return []

        except Exception:
            return []

    # =========================================================================
    # ACCESS PATH QUERIES
    # =========================================================================

    def _get_user_access(self, session, user: str) -> List[MachineAccess]:
        """
        Get all machine access paths for a user.

        Includes both direct access AND inherited access through group membership
        (e.g., DOMAIN ADMINS members have AdminTo on all computers).

        Returns list of MachineAccess with privilege levels derived from edge types.
        """
        # Query for BOTH direct access AND inherited access through groups
        # Includes: AdminTo, CanRDP, CanPSRemote, ExecuteDCOM, ReadLAPSPassword, AllowedToAct
        result = session.run("""
            // Direct access
            MATCH (u:User {name: $user_name})-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|ReadLAPSPassword|AllowedToAct]->(c:Computer)
            OPTIONAL MATCH (c)<-[:HasSession]-(priv:User)
            WHERE priv.admincount = true
            WITH c, type(r) AS AccessType, null AS InheritedFrom, collect(DISTINCT priv.name) AS PrivSessions
            RETURN c.name AS Computer,
                   c.bloodtrail_ip AS ComputerIP,
                   collect(DISTINCT AccessType) AS AccessTypes,
                   InheritedFrom,
                   PrivSessions

            UNION

            // Inherited access through group membership
            MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|ReadLAPSPassword|AllowedToAct]->(c:Computer)
            OPTIONAL MATCH (c)<-[:HasSession]-(priv:User)
            WHERE priv.admincount = true
            WITH c, type(r) AS AccessType, g.name AS InheritedFrom, collect(DISTINCT priv.name) AS PrivSessions
            RETURN c.name AS Computer,
                   c.bloodtrail_ip AS ComputerIP,
                   collect(DISTINCT AccessType) AS AccessTypes,
                   InheritedFrom,
                   PrivSessions
        """, {"user_name": user})

        # Deduplicate by computer, keeping all access types
        seen_computers = {}
        for record in result:
            computer = record["Computer"]
            computer_ip = record.get("ComputerIP") or ""
            access_types = record["AccessTypes"]

            if computer in seen_computers:
                # Merge access types
                existing = seen_computers[computer]
                existing["access_types"] = list(set(existing["access_types"]) | set(access_types))
                # Merge sessions
                existing["sessions"] = list(set(existing["sessions"]) | set(record["PrivSessions"] or []))
                # Update IP if not already set
                if computer_ip and not existing.get("computer_ip"):
                    existing["computer_ip"] = computer_ip
                continue

            seen_computers[computer] = {
                "access_types": access_types,
                "sessions": record["PrivSessions"] or [],
                "inherited_from": record["InheritedFrom"],
                "computer_ip": computer_ip,
            }

        access_list = []
        for computer, data in seen_computers.items():
            access_types = data["access_types"]

            # Determine highest privilege level (ordered by impact)
            priv_level = "unknown"
            if "AdminTo" in access_types:
                priv_level = "local-admin"
            elif "ReadLAPSPassword" in access_types:
                priv_level = "cred-access"  # Can get local admin creds
            elif "AllowedToAct" in access_types:
                priv_level = "rbcd-capable"  # RBCD impersonation = effective admin
            elif "ExecuteDCOM" in access_types:
                priv_level = "dcom-exec"
            elif access_types:  # CanRDP or CanPSRemote
                priv_level = "user-level"

            access_list.append(MachineAccess(
                computer=computer,
                access_types=access_types,
                privilege_level=priv_level,
                sessions=data["sessions"],
                computer_ip=data.get("computer_ip", "")
            ))

        return access_list

    def _get_gmsa_access(self, session, user: str) -> List[str]:
        """
        Get gMSA (Group Managed Service Account) access for a user.

        gMSA accounts are User nodes, not Computer nodes, so they need separate tracking.
        ReadGMSAPassword edge grants ability to retrieve the service account password.

        Returns list of gMSA account names the user can read passwords for.
        """
        result = session.run("""
            // Direct gMSA access
            MATCH (u:User {name: $user_name})-[:ReadGMSAPassword]->(gmsa:User)
            RETURN gmsa.name AS ServiceAccount

            UNION

            // Inherited gMSA access through group membership
            MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[:ReadGMSAPassword]->(gmsa:User)
            RETURN gmsa.name AS ServiceAccount
        """, {"user_name": user})

        return list(set(record["ServiceAccount"] for record in result))

    def _get_domain_level_access(self, session, user: str) -> Optional[str]:
        """
        Check if user has domain-level privileges (direct or inherited through groups).

        Checks:
        1. Direct DCSync rights (GetChanges + GetChangesAll)
        2. Inherited DCSync through group membership (e.g., DOMAIN ADMINS)
        3. GenericAll on Domain
        4. Membership in Domain Admins / Enterprise Admins (implicit DCSync)

        Returns 'domain-admin' if user has these rights, None otherwise.
        """
        # Check for direct DCSync rights (GetChanges + GetChangesAll)
        result = session.run("""
            MATCH (u:User {name: $user_name})-[r:GetChanges|GetChangesAll]->(d:Domain)
            WITH u, d, collect(DISTINCT type(r)) AS Rights
            WHERE 'GetChanges' IN Rights AND 'GetChangesAll' IN Rights
            RETURN d.name AS Domain, 'DCSync' AS Via
        """, {"user_name": user})

        if result.single():
            return "domain-admin"

        # Check for inherited DCSync through group membership
        result = session.run("""
            MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[r:GetChanges|GetChangesAll]->(d:Domain)
            WITH g, d, collect(DISTINCT type(r)) AS Rights
            WHERE 'GetChanges' IN Rights AND 'GetChangesAll' IN Rights
            RETURN d.name AS Domain, 'DCSync' AS Via
        """, {"user_name": user})

        if result.single():
            return "domain-admin"

        # Check membership in Domain Admins / Enterprise Admins (implicit DCSync)
        result = session.run("""
            MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)
            WHERE g.name STARTS WITH 'DOMAIN ADMINS@'
               OR g.name STARTS WITH 'ENTERPRISE ADMINS@'
               OR g.objectid ENDS WITH '-512'
               OR g.objectid ENDS WITH '-519'
            RETURN g.name AS AdminGroup
            LIMIT 1
        """, {"user_name": user})

        if result.single():
            return "domain-admin"

        # Check for direct GenericAll on Domain
        result = session.run("""
            MATCH (u:User {name: $user_name})-[:GenericAll]->(d:Domain)
            RETURN d.name AS Domain, 'GenericAll' AS Via
        """, {"user_name": user})

        if result.single():
            return "domain-admin"

        # Check for inherited GenericAll through group membership
        result = session.run("""
            MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[:GenericAll]->(d:Domain)
            RETURN d.name AS Domain, 'GenericAll' AS Via
        """, {"user_name": user})

        if result.single():
            return "domain-admin"

        return None

    def get_pwned_user_access(self, user: str) -> List[MachineAccess]:
        """
        Get access paths for a specific user.

        Public wrapper around _get_user_access.
        """
        user = user.upper()

        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                return self._get_user_access(session, user)
        except Exception:
            return []

    # =========================================================================
    # PRIORITY QUERIES
    # =========================================================================

    def get_cred_harvest_targets(self) -> List[Dict[str, Any]]:
        """
        Find machines where pwned users have admin AND privileged users have sessions.

        These are high-priority targets for credential harvesting.

        Returns:
            List of dicts with pwned_user, target, privileged_sessions
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (pwned:User {pwned: true})-[:AdminTo]->(c:Computer)<-[:HasSession]-(priv:User)
                    WHERE priv.admincount = true
                    RETURN pwned.name AS PwnedUser,
                           pwned.pwned_cred_types AS CredTypes,
                           pwned.pwned_cred_values AS CredValues,
                           c.name AS Target,
                           collect(DISTINCT priv.name) AS PrivilegedSessions
                    ORDER BY size(collect(DISTINCT priv.name)) DESC
                """)

                targets = []
                for record in result:
                    cred_types = record["CredTypes"] or []
                    cred_values = record["CredValues"] or []
                    targets.append({
                        "pwned_user": record["PwnedUser"],
                        "cred_types": list(cred_types),
                        "cred_values": list(cred_values),
                        "cred_type": cred_types[0] if cred_types else "password",  # Primary for backward compat
                        "cred_value": cred_values[0] if cred_values else "",
                        "target": record["Target"],
                        "privileged_sessions": record["PrivilegedSessions"]
                    })

                return targets

        except Exception:
            return []

    def get_all_machines_with_ips(self) -> List[Dict[str, Optional[str]]]:
        """
        Get all Computer nodes with their resolved IP addresses (if any).

        Returns:
            List of dicts with 'name' (hostname) and 'ip' (IP or None)
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (c:Computer)
                    RETURN c.name AS name, c.bloodtrail_ip AS ip
                    ORDER BY c.name
                """)

                return [{"name": record["name"], "ip": record["ip"]} for record in result]

        except Exception:
            return []

    def get_all_users_with_access(self) -> List[Dict[str, Any]]:
        """
        Get ALL users with machine access (AdminTo, CanRDP, CanPSRemote, ExecuteDCOM, ReadLAPSPassword).

        Returns both direct access and inherited access through group membership.
        Used by --spray-tailored to generate targeted commands.

        Returns:
            List of dicts with: user, computer, access_type, ip, inherited_from
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    // Direct access
                    MATCH (u:User)-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|ReadLAPSPassword]->(c:Computer)
                    WHERE u.enabled = true OR u.enabled IS NULL
                    RETURN u.name AS User, c.name AS Computer, type(r) AS AccessType,
                           c.bloodtrail_ip AS IP, null AS InheritedFrom

                    UNION

                    // Inherited through groups
                    MATCH (u:User)-[:MemberOf*1..]->(g:Group)-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|ReadLAPSPassword]->(c:Computer)
                    WHERE u.enabled = true OR u.enabled IS NULL
                    RETURN u.name AS User, c.name AS Computer, type(r) AS AccessType,
                           c.bloodtrail_ip AS IP, g.name AS InheritedFrom
                """)

                access_list = []
                for record in result:
                    access_list.append({
                        "user": record["User"],
                        "computer": record["Computer"],
                        "access_type": record["AccessType"],
                        "ip": record["IP"],
                        "inherited_from": record["InheritedFrom"],
                    })

                return access_list

        except Exception as e:
            print(f"[!] Error querying user access: {e}")
            return []

    def get_escalation_paths(self, max_hops: int = 6) -> List[Dict[str, Any]]:
        """
        Find shortest paths from any pwned user to Domain Admins.

        Args:
            max_hops: Maximum path length

        Returns:
            List of dicts with pwned_user, path, hops
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (pwned:User {pwned: true})
                    MATCH p=shortestPath((pwned)-[*1..$max_hops]->(da:Group))
                    WHERE da.name =~ '(?i).*DOMAIN ADMINS.*'
                    RETURN pwned.name AS PwnedUser,
                           pwned.pwned_cred_types AS CredTypes,
                           [n IN nodes(p) | n.name] AS Path,
                           length(p) AS Hops
                    ORDER BY Hops ASC
                    LIMIT 10
                """, {"max_hops": max_hops})

                paths = []
                for record in result:
                    cred_types = record["CredTypes"] or []
                    paths.append({
                        "pwned_user": record["PwnedUser"],
                        "cred_types": list(cred_types),
                        "cred_type": cred_types[0] if cred_types else "password",  # Primary for backward compat
                        "path": record["Path"],
                        "hops": record["Hops"]
                    })

                return paths

        except Exception:
            return []

    # =========================================================================
    # DOMAIN CONFIGURATION
    # =========================================================================

    def get_domain_config(self) -> Optional[Dict[str, Any]]:
        """
        Get domain configuration from Neo4j.

        Returns config dict with keys:
            - domain: Domain name (e.g., CORP.COM)
            - dc_hostname: DC hostname (e.g., DC1.CORP.COM)
            - dc_ip: DC IP address (e.g., 192.168.50.70)
            - domain_sid: Domain SID (e.g., S-1-5-21-1987370270-658905905-1781884369)
            - lhost: Attacker IP for callbacks (e.g., 192.168.45.200)
            - lport: Attacker port for callbacks (e.g., 443)

        Config is stored as properties on the Domain node:
            - bloodtrail_dc_ip
            - bloodtrail_dc_hostname
            - bloodtrail_domain_sid
            - bloodtrail_lhost
            - bloodtrail_lport

        Returns None if no domain found in BloodHound data.
        """
        if not self._ensure_connected():
            return None

        try:
            with self.driver.session() as session:
                # Get domain info and any stored config
                result = session.run("""
                    MATCH (d:Domain)
                    RETURN d.name AS domain,
                           d.bloodtrail_dc_ip AS dc_ip,
                           d.bloodtrail_dc_hostname AS dc_hostname,
                           d.bloodtrail_domain_sid AS domain_sid,
                           d.bloodtrail_lhost AS lhost,
                           d.bloodtrail_lport AS lport
                    LIMIT 1
                """)

                record = result.single()
                if not record:
                    return None

                domain = record["domain"]

                # If DC hostname not set, try to find it from Domain Controllers
                dc_hostname = record["dc_hostname"]
                if not dc_hostname:
                    dc_result = session.run("""
                        MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
                        WHERE g.name =~ '(?i)DOMAIN CONTROLLERS@.*'
                        RETURN c.name AS dc_hostname
                        LIMIT 1
                    """)
                    dc_record = dc_result.single()
                    if dc_record:
                        dc_hostname = dc_record["dc_hostname"]

                return {
                    "domain": domain,
                    "dc_hostname": dc_hostname,
                    "dc_ip": record["dc_ip"],
                    "domain_sid": record["domain_sid"],
                    "lhost": record["lhost"],
                    "lport": record["lport"],
                }

        except Exception:
            return None

    def set_callback_config(self, lhost: str, lport: int) -> PwnedResult:
        """
        Store attacker LHOST and LPORT for reverse shell templates.

        Args:
            lhost: Attacker IP address for callbacks
            lport: Attacker port for callbacks

        Returns:
            PwnedResult with success status
        """
        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain)
                    SET d.bloodtrail_lhost = $lhost,
                        d.bloodtrail_lport = $lport
                    RETURN d.name AS domain
                """, {"lhost": lhost, "lport": lport})

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error="No domain found. Import BloodHound data first."
                    )

                return PwnedResult(success=True, user=record["domain"])

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    def set_dc_ip(self, dc_ip: str, dc_hostname: str = None) -> PwnedResult:
        """
        Store DC IP address in Neo4j for command auto-population.

        Args:
            dc_ip: IP address of the Domain Controller
            dc_hostname: Optional DC hostname (auto-detected if not provided)

        Returns:
            PwnedResult with success status
        """
        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                # Check if domain exists
                check_result = session.run("""
                    MATCH (d:Domain)
                    RETURN d.name AS domain
                    LIMIT 1
                """)

                check_record = check_result.single()
                if not check_record:
                    return PwnedResult(
                        success=False,
                        error="No domain found in BloodHound data. Import data first."
                    )

                # Build SET clause dynamically
                set_clause = "d.bloodtrail_dc_ip = $dc_ip"
                params = {"dc_ip": dc_ip}

                if dc_hostname:
                    set_clause += ", d.bloodtrail_dc_hostname = $dc_hostname"
                    params["dc_hostname"] = dc_hostname

                # Update domain with DC config
                result = session.run(f"""
                    MATCH (d:Domain)
                    SET {set_clause}
                    RETURN d.name AS domain
                """, params)

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error="Failed to update domain configuration"
                    )

                return PwnedResult(success=True, user=record["domain"])

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    def set_domain_sid(self, domain_sid: str) -> PwnedResult:
        """
        Store Domain SID in Neo4j for Golden/Silver ticket auto-population.

        The Domain SID is the same for all objects in the domain.
        Format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX (without user RID)

        Args:
            domain_sid: Domain SID (e.g., S-1-5-21-1987370270-658905905-1781884369)

        Returns:
            PwnedResult with success status
        """
        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        # Validate SID format
        if not domain_sid.startswith("S-1-5-21-"):
            return PwnedResult(
                success=False,
                error="Invalid SID format. Expected: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX"
            )

        # Strip any trailing RID if user accidentally included it
        parts = domain_sid.split("-")
        if len(parts) > 7:
            # User included the RID, strip it
            domain_sid = "-".join(parts[:7])
            print(f"[*] Stripped RID, using domain SID: {domain_sid}")

        try:
            with self.driver.session() as session:
                # Check if domain exists
                check_result = session.run("""
                    MATCH (d:Domain)
                    RETURN d.name AS domain
                    LIMIT 1
                """)

                check_record = check_result.single()
                if not check_record:
                    return PwnedResult(
                        success=False,
                        error="No domain found in BloodHound data. Import data first."
                    )

                # Update domain with SID
                result = session.run("""
                    MATCH (d:Domain)
                    SET d.bloodtrail_domain_sid = $domain_sid
                    RETURN d.name AS domain
                """, {"domain_sid": domain_sid})

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error="Failed to update domain SID"
                    )

                return PwnedResult(success=True, user=record["domain"])

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    def clear_domain_config(self) -> PwnedResult:
        """
        Clear stored domain configuration.

        Returns:
            PwnedResult with success status
        """
        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain)
                    REMOVE d.bloodtrail_dc_ip, d.bloodtrail_dc_hostname, d.bloodtrail_domain_sid,
                           d.bloodtrail_lhost, d.bloodtrail_lport
                    RETURN d.name AS domain
                """)

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error="No domain found"
                    )

                return PwnedResult(success=True, user=record["domain"])

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    # =========================================================================
    # PASSWORD POLICY STORAGE
    # =========================================================================

    def set_password_policy(self, policy: PasswordPolicy) -> PwnedResult:
        """
        Store password policy on Domain node for safe spray planning.

        Policy is stored as Neo4j properties on the Domain node:
            - bloodtrail_policy_lockout_threshold
            - bloodtrail_policy_lockout_duration
            - bloodtrail_policy_observation_window
            - bloodtrail_policy_min_length
            - bloodtrail_policy_max_age
            - bloodtrail_policy_min_age
            - bloodtrail_policy_history
            - bloodtrail_policy_updated_at

        Args:
            policy: PasswordPolicy dataclass from policy_parser

        Returns:
            PwnedResult with success status
        """
        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain)
                    SET d.bloodtrail_policy_lockout_threshold = $threshold,
                        d.bloodtrail_policy_lockout_duration = $duration,
                        d.bloodtrail_policy_observation_window = $window,
                        d.bloodtrail_policy_min_length = $min_length,
                        d.bloodtrail_policy_max_age = $max_age,
                        d.bloodtrail_policy_min_age = $min_age,
                        d.bloodtrail_policy_history = $history,
                        d.bloodtrail_policy_updated_at = $timestamp
                    RETURN d.name AS domain
                """, {
                    "threshold": policy.lockout_threshold,
                    "duration": policy.lockout_duration,
                    "window": policy.observation_window,
                    "min_length": policy.min_length,
                    "max_age": policy.max_age,
                    "min_age": policy.min_age,
                    "history": policy.history,
                    "timestamp": int(time.time()),
                })

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error="No domain found in BloodHound data. Import data first."
                    )

                return PwnedResult(success=True, user=record["domain"])

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    def get_password_policy(self) -> Optional[PasswordPolicy]:
        """
        Retrieve stored password policy from Domain node.

        Returns:
            PasswordPolicy dataclass or None if not set
        """
        if not self._ensure_connected():
            return None

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain)
                    RETURN d.bloodtrail_policy_lockout_threshold AS threshold,
                           d.bloodtrail_policy_lockout_duration AS duration,
                           d.bloodtrail_policy_observation_window AS window,
                           d.bloodtrail_policy_min_length AS min_length,
                           d.bloodtrail_policy_max_age AS max_age,
                           d.bloodtrail_policy_min_age AS min_age,
                           d.bloodtrail_policy_history AS history,
                           d.bloodtrail_policy_updated_at AS updated_at
                    LIMIT 1
                """)

                record = result.single()
                if not record or record["threshold"] is None:
                    return None

                return PasswordPolicy(
                    lockout_threshold=record["threshold"] or 0,
                    lockout_duration=record["duration"] or 30,
                    observation_window=record["window"] or 30,
                    min_length=record["min_length"] or 0,
                    max_age=record["max_age"] or 0,
                    min_age=record["min_age"] or 0,
                    history=record["history"] or 0,
                )

        except Exception:
            return None

    def clear_password_policy(self) -> PwnedResult:
        """
        Clear stored password policy from Domain node.

        Returns:
            PwnedResult with success status
        """
        if not self._ensure_connected():
            return PwnedResult(success=False, error="Could not connect to Neo4j")

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain)
                    REMOVE d.bloodtrail_policy_lockout_threshold,
                           d.bloodtrail_policy_lockout_duration,
                           d.bloodtrail_policy_observation_window,
                           d.bloodtrail_policy_min_length,
                           d.bloodtrail_policy_max_age,
                           d.bloodtrail_policy_min_age,
                           d.bloodtrail_policy_history,
                           d.bloodtrail_policy_updated_at
                    RETURN d.name AS domain
                """)

                record = result.single()
                if not record:
                    return PwnedResult(
                        success=False,
                        error="No domain found"
                    )

                return PwnedResult(success=True, user=record["domain"])

        except Exception as e:
            return PwnedResult(success=False, error=str(e))

    # =========================================================================
    # AUTO-SPRAY SUPPORT METHODS
    # =========================================================================

    def get_all_users(self) -> List[str]:
        """
        Get all user SAM account names from Neo4j.

        Returns:
            List of usernames (samaccountname)
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User)
                    WHERE u.samaccountname IS NOT NULL
                      AND NOT u.name STARTS WITH 'KRBTGT'
                      AND NOT u.name STARTS WITH 'NT AUTHORITY'
                      AND NOT u.name CONTAINS '$'
                    RETURN u.samaccountname AS username
                    ORDER BY u.samaccountname
                """)
                return [r["username"] for r in result if r["username"]]
        except Exception:
            return []

    def get_enabled_users(self) -> List[str]:
        """
        Get enabled user SAM account names for spraying.

        Excludes:
        - Disabled accounts
        - KRBTGT and NT AUTHORITY system accounts
        - Machine accounts (ending in $)

        Returns:
            List of usernames (samaccountname)
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User)
                    WHERE u.enabled = true
                      AND u.samaccountname IS NOT NULL
                      AND NOT u.name STARTS WITH 'KRBTGT'
                      AND NOT u.name STARTS WITH 'NT AUTHORITY'
                      AND NOT u.name CONTAINS '$'
                    RETURN u.samaccountname AS username
                    ORDER BY u.samaccountname
                """)
                return [r["username"] for r in result if r["username"]]
        except Exception:
            return []

    def get_non_pwned_users(self) -> List[str]:
        """
        Get users that haven't been marked as pwned yet.

        Useful for targeting only un-compromised accounts in a spray.

        Returns:
            List of usernames (samaccountname)
        """
        if not self._ensure_connected():
            return []

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User)
                    WHERE u.enabled = true
                      AND u.samaccountname IS NOT NULL
                      AND NOT u.name STARTS WITH 'KRBTGT'
                      AND NOT u.name STARTS WITH 'NT AUTHORITY'
                      AND NOT u.name CONTAINS '$'
                      AND (u.pwned IS NULL OR u.pwned = false)
                    RETURN u.samaccountname AS username
                    ORDER BY u.samaccountname
                """)
                return [r["username"] for r in result if r["username"]]
        except Exception:
            return []

    def mark_pwned_batch(self, results: List[dict]) -> int:
        """
        Batch mark users as pwned from spray results.

        Args:
            results: List of dicts with keys:
                - username: User's samaccountname
                - password: Password that worked
                - is_admin: Whether user has admin access (optional)

        Returns:
            Number of users successfully marked as pwned
        """
        if not self._ensure_connected():
            return 0

        if not results:
            return 0

        marked = 0

        try:
            with self.driver.session() as session:
                for entry in results:
                    username = entry.get("username", "")
                    password = entry.get("password", "")
                    is_admin = entry.get("is_admin", False)

                    if not username or not password:
                        continue

                    # Find user by samaccountname and mark as pwned
                    result = session.run("""
                        MATCH (u:User)
                        WHERE toLower(u.samaccountname) = toLower($username)
                        SET u.pwned = true,
                            u.pwned_at = timestamp(),
                            u.pwned_cred_types = CASE
                                WHEN u.pwned_cred_types IS NULL THEN ['password']
                                WHEN NOT 'password' IN u.pwned_cred_types
                                    THEN u.pwned_cred_types + ['password']
                                ELSE u.pwned_cred_types
                            END,
                            u.pwned_cred_values = CASE
                                WHEN u.pwned_cred_values IS NULL THEN [$password]
                                WHEN NOT $password IN u.pwned_cred_values
                                    THEN u.pwned_cred_values + [$password]
                                ELSE u.pwned_cred_values
                            END,
                            u.pwned_notes = COALESCE(u.pwned_notes, '') +
                                CASE WHEN u.pwned_notes IS NOT NULL THEN '\\n' ELSE '' END +
                                'Auto-spray: ' + $password +
                                CASE WHEN $is_admin THEN ' (ADMIN)' ELSE '' END
                        RETURN u.name AS name
                    """, username=username, password=password, is_admin=is_admin)

                    if result.single():
                        marked += 1

        except Exception:
            pass

        return marked


# =============================================================================
# DC DISCOVERY FUNCTIONS
# =============================================================================

class DiscoveryError(Exception):
    """DC discovery failed."""
    pass


def discover_dc_ip(domain: str, user: str, password: str, timeout: int = 30) -> str:
    """
    Run crackmapexec to get DC IP from domain name.

    Args:
        domain: Domain name (e.g., CORP.COM)
        user: Domain username
        password: User password
        timeout: Command timeout in seconds

    Returns:
        DC IP address

    Raises:
        DiscoveryError: If discovery fails
    """
    import subprocess
    import re
    import shutil

    # Check if crackmapexec is installed
    if not shutil.which("crackmapexec"):
        raise DiscoveryError("crackmapexec not installed. Install with: sudo apt install crackmapexec")

    cmd = ["crackmapexec", "smb", domain, "-u", user, "-p", password]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse IP from output: "SMB  192.168.50.70  445  DC1"
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            return match.group(1)

        # Check for auth failure
        if "STATUS_LOGON_FAILURE" in result.stdout or "STATUS_LOGON_FAILURE" in result.stderr:
            raise DiscoveryError(f"Authentication failed for {user}@{domain}")

        raise DiscoveryError(f"Could not discover DC IP for {domain}. Output: {result.stdout[:200]}")

    except subprocess.TimeoutExpired:
        raise DiscoveryError(f"Timeout connecting to {domain} (>{timeout}s)")
    except FileNotFoundError:
        raise DiscoveryError("crackmapexec not found in PATH")


def discover_dc_hostname(dc_ip: str, user: str, password: str, timeout: int = 30) -> str:
    """
    Run crackmapexec to get DC hostname from IP.

    Args:
        dc_ip: DC IP address
        user: Domain username
        password: User password
        timeout: Command timeout in seconds

    Returns:
        DC hostname (e.g., DC1)

    Raises:
        DiscoveryError: If discovery fails
    """
    import subprocess
    import re

    cmd = ["crackmapexec", "smb", dc_ip, "-u", user, "-p", password]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse hostname from output: "SMB  192.168.50.70  445  DC1"
        match = re.search(r'445\s+(\w+)', result.stdout)
        if match:
            return match.group(1)

        raise DiscoveryError(f"Could not discover DC hostname for {dc_ip}")

    except subprocess.TimeoutExpired:
        raise DiscoveryError(f"Timeout connecting to {dc_ip} (>{timeout}s)")


def update_etc_hosts(entry: str) -> bool:
    """
    Add DC entry to /etc/hosts (requires sudo).

    Args:
        entry: Full hosts entry (e.g., "192.168.50.70 dc1.corp.com dc1 corp.com")

    Returns:
        True if added, False if already exists
    """
    import subprocess

    dc_ip = entry.split()[0]

    # Check if already exists
    try:
        with open('/etc/hosts', 'r') as f:
            if dc_ip in f.read():
                print(f"[*] {dc_ip} already in /etc/hosts")
                return False
    except PermissionError:
        pass  # Will fail on write anyway

    # Append using sudo tee
    cmd = f'echo "{entry}" | sudo tee -a /etc/hosts'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[+] Added to /etc/hosts")
        return True
    else:
        print(f"[!] Failed to update /etc/hosts: {result.stderr}")
        return False
