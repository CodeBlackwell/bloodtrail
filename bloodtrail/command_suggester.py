"""
Blood-trail Attack Command Suggester v2

Generates DRY, tabular attack command suggestions based on BloodHound query results.
Maps query findings to CRACK command database entries with:
- Array field expansion (AdminOnComputers, RDPTargets, etc.)
- Group name filtering (skip invalid targets like "DOMAIN CONTROLLERS@...")
- Access-type aware command selection
- Domain/DC inference from UPN format
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from .mappings.query_loader import QUERY_COMMAND_MAPPINGS
from .mappings.edge_mappings import EDGE_COMMAND_MAPPINGS
from .mappings.text_utils import (
    SENSITIVE_PLACEHOLDERS,
    extract_domain,
    extract_username,
    infer_dc_hostname,
    is_group_name,
)
from .mappings.access_types import (
    ACCESS_TYPE_PHASES,
    ACCESS_TYPE_REWARDS,
    get_reason,
)
from .mappings.command_fill import fill_command

# Type hint for PwnedUser (avoid circular import)
if False:  # TYPE_CHECKING
    from .pwned_tracker import PwnedUser


# =============================================================================
# DATA CLASSES - DRY tabular output
# =============================================================================

@dataclass
class TargetEntry:
    """Single row in command table - one user→target combination"""
    user: str                          # Who has access (UPN format)
    target: str                        # Computer FQDN or user target
    ready_command: str                 # Copy-paste ready command
    domain: str                        # Extracted domain
    access_type: Optional[str] = None  # AdminTo, CanRDP, etc.
    reason: str = ""                   # Why this command is suggested
    warnings: List[str] = field(default_factory=list)  # Validation warnings

    def to_dict(self) -> Dict:
        return {
            "user": self.user,
            "target": self.target,
            "ready_command": self.ready_command,
            "domain": self.domain,
            "access_type": self.access_type,
            "reason": self.reason,
            "warnings": self.warnings,
        }


@dataclass
class CommandTable:
    """Single command with multiple targets - DRY output format"""
    command_id: str
    name: str
    template: str                      # Shown ONCE (not repeated per target)
    access_type: Optional[str]         # AdminTo, CanRDP, CanPSRemote, etc.
    targets: List[TargetEntry] = field(default_factory=list)
    variables_needed: List[str] = field(default_factory=list)
    context: str = ""                  # Why this command
    domain_level: bool = False         # True for DCSync, etc.
    example: str = ""                  # Complete example with filled variables
    objective: str = ""                # What the command intends to achieve
    rewards: str = ""                  # Practical applications of data acquired
    post_success: List[Dict] = field(default_factory=list)  # Next steps after success
    permissions_required: str = ""     # What permissions needed to run command
    is_discovery: bool = False         # True for Kerberoast, AS-REP, etc.
    is_coercion: bool = False          # True for PetitPotam, Coercer, etc.

    @property
    def phase(self) -> str:
        """Get attack phase for grouping"""
        return ACCESS_TYPE_PHASES.get(self.access_type, "Other")

    @property
    def priority_score(self) -> int:
        """Get priority score for impact-based sorting within phases.

        Higher score = higher impact = shown first.
        Used by display functions to sort commands within phase groups.
        """
        from .mappings.access_types import ACCESS_TYPE_PRIORITY
        return ACCESS_TYPE_PRIORITY.get(self.access_type, 0)

    @property
    def target_count(self) -> int:
        return len(self.targets)

    def to_dict(self) -> Dict:
        return {
            "command_id": self.command_id,
            "name": self.name,
            "template": self.template,
            "example": self.example,
            "objective": self.objective,
            "rewards": self.rewards,
            "access_type": self.access_type,
            "targets": [t.to_dict() for t in self.targets],
            "variables_needed": self.variables_needed,
            "context": self.context,
            "phase": self.phase,
            "target_count": self.target_count,
            "post_success": self.post_success,
            "permissions_required": self.permissions_required,
            "is_discovery": self.is_discovery,
            "is_coercion": self.is_coercion,
        }


# Legacy dataclasses for backward compatibility
@dataclass
class CommandSuggestion:
    """Single command suggestion with template and ready-to-run versions"""
    command_id: str
    name: str
    context: str
    template: str
    ready_to_run: str
    variables_filled: Dict[str, str] = field(default_factory=dict)
    variables_needed: List[str] = field(default_factory=list)
    oscp_relevance: str = "medium"

    def to_dict(self) -> Dict:
        return {
            "command_id": self.command_id,
            "name": self.name,
            "context": self.context,
            "template": self.template,
            "ready_to_run": self.ready_to_run,
            "variables_filled": self.variables_filled,
            "variables_needed": self.variables_needed,
            "oscp_relevance": self.oscp_relevance,
        }


@dataclass
class AttackSequence:
    """Multi-step attack chain built from BloodHound path"""
    name: str
    description: str
    path_nodes: List[str]
    edge_types: List[str]
    steps: List[CommandSuggestion] = field(default_factory=list)

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "path_nodes": self.path_nodes,
            "edge_types": self.edge_types,
            "steps": [s.to_dict() for s in self.steps],
            "total_steps": self.total_steps,
        }


# =============================================================================
# VALIDATION HELPERS - Check conditions that may cause command failure
# =============================================================================

def is_stale_password(timestamp: Any, years: int = 2) -> bool:
    """
    Check if password is older than specified years.

    Args:
        timestamp: Unix epoch (seconds/milliseconds) or Windows FILETIME
        years: Threshold in years (default: 2)

    Returns:
        True if password is stale
    """
    if timestamp is None or timestamp == 0 or timestamp == -1:
        return False

    from datetime import datetime
    try:
        ts = int(timestamp)
        # Handle milliseconds
        if ts > 32503680000:  # Year 3000 in seconds
            ts = ts // 1000
        # Handle Windows FILETIME
        if ts > 100000000000000:
            ts = (ts // 10000000) - 11644473600

        age_seconds = datetime.now().timestamp() - ts
        return age_seconds > (years * 365 * 24 * 3600)
    except (ValueError, TypeError, OverflowError):
        return False


def has_both_dcsync_rights(record: Dict) -> bool:
    """
    Check if DCSync principal has BOTH GetChanges AND GetChangesAll.

    Some queries return individual rights; both are required for DCSync.
    """
    # Check if Rights field exists (some queries aggregate rights)
    rights = record.get("Rights", [])
    if isinstance(rights, list) and len(rights) > 0:
        has_gc = any("GetChanges" in str(r) and "All" not in str(r) for r in rights)
        has_gca = any("GetChangesAll" in str(r) for r in rights)
        return has_gc and has_gca

    # Check individual right fields
    right = record.get("Right", "")
    if right:
        # Single right query - can't validate both, assume partial
        # Return True only if we see evidence of both
        return False

    # Can't determine, assume OK to avoid false warnings
    return True


def validate_target_entry(record: Dict, access_type: Optional[str]) -> List[str]:
    """
    Check for conditions that may cause command failure.

    Args:
        record: Query result record with user/target data
        access_type: Edge type (AdminTo, DCSync, ADCSESC1, etc.)

    Returns:
        List of warning strings to display
    """
    warnings = []

    # Check account disabled
    enabled = record.get("enabled")
    if enabled is False:  # Explicitly False, not None
        warnings.append("[DISABLED]")

    # Check password age (stale if > 2 years)
    pwdlastset = (
        record.get("pwdlastset") or
        record.get("PasswordLastSet") or
        record.get("passwordlastset")
    )
    if pwdlastset and is_stale_password(pwdlastset):
        warnings.append("[STALE CRED]")

    # Check DCSync has both rights
    if access_type == "DCSync":
        if not has_both_dcsync_rights(record):
            warnings.append("[PARTIAL RIGHTS]")

    # Check ESC1 properties (enrolleesuppliessubject must be true)
    if access_type and "ADCSESC1" in str(access_type):
        ess = record.get("enrolleesuppliessubject")
        if ess is False:  # Explicitly False
            warnings.append("[NOT ESC1]")

    return warnings


# =============================================================================
# COMMAND SUGGESTER - Main engine
# =============================================================================

class CommandSuggester:
    """
    Generates attack command suggestions from bloodtrail query results.

    v2 Features:
    - DRY tabular output via build_command_tables()
    - Array field expansion (AdminOnComputers, RDPTargets, etc.)
    - Group name filtering (DOMAIN CONTROLLERS, etc.)
    - Access-type aware command selection
    - Domain/DC inference from UPN format

    Example:
        suggester = CommandSuggester()

        # New DRY approach - get tables for tabular display
        tables = suggester.build_command_tables(
            "lateral-adminto-nonpriv",
            [{"User": "MIKE@CORP.COM", "AdminOnComputers": ["CLIENT75.CORP.COM"]}]
        )

        # Legacy approach - individual suggestions
        suggestions = suggester.suggest_for_query(
            "quick-asrep-roastable",
            [{"User": "MIKE@CORP.COM", "IsPrivileged": False}]
        )
    """

    def __init__(self, commands_db_path: Optional[Path] = None):
        if commands_db_path is None:
            # bloodtrail/command_suggester.py -> crack/db/data/commands
            # Path: tools/post/bloodtrail/command_suggester.py
            # Go up: bloodtrail -> post -> tools -> crack (4 levels)
            crack_root = Path(__file__).parent.parent.parent.parent
            commands_db_path = crack_root / "db" / "data" / "commands"

        self.commands_db_path = commands_db_path
        self.commands: Dict[str, Dict] = {}
        self._load_commands()

    def _load_commands(self):
        """Load all command definitions from CRACK database"""
        if not self.commands_db_path.exists():
            return

        for json_file in self.commands_db_path.rglob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                for cmd in data.get("commands", []):
                    if "id" in cmd:
                        self.commands[cmd["id"]] = cmd
            except Exception:
                continue

    # =========================================================================
    # NEW v2 API - DRY tabular output
    # =========================================================================

    def build_command_tables(
        self,
        query_id: str,
        records: List[Dict],
        pwned_users: Optional[Dict[str, Any]] = None,
        dc_ip: Optional[str] = None,
    ) -> List[CommandTable]:
        """
        Build DRY command tables from query results.

        Handles:
        - Array field expansion (AdminOnComputers -> multiple targets)
        - Group name filtering (skip DOMAIN CONTROLLERS@... etc.)
        - Access-type aware command selection
        - Domain/DC inference
        - Auto-fill credentials for pwned users

        Args:
            query_id: Blood-trail query ID
            records: Query result records from Neo4j
            pwned_users: Dict mapping username (uppercase) to PwnedUser objects
            dc_ip: Domain Controller IP from stored config (for <DC_IP> placeholder)

        Returns:
            List of CommandTable objects for tabular display
        """
        mapping = QUERY_COMMAND_MAPPINGS.get(query_id)
        if not mapping or mapping == "BUILD_SEQUENCE":
            return []

        # Ensure mapping is a dict
        if not isinstance(mapping, dict):
            return []

        tables: Dict[str, CommandTable] = {}
        cmd_ids = mapping.get("commands", [])
        access_type = mapping.get("access_type")
        context = mapping.get("context", "")
        domain_level = mapping.get("domain_level", False)

        # Check if this is a discovery command (Kerberoast, AS-REP, etc.)
        is_discovery = mapping.get("discovery_command", False)

        for record in records:
            # Handle principal field for privesc queries (DCSync, etc.)
            principal = self._get_field(record, mapping, "principal_field", None)
            if principal and mapping.get("filter_groups"):
                if is_group_name(principal):
                    continue  # Skip groups like DOMAIN CONTROLLERS@...

            # For discovery commands, target_field holds what we discovered
            if is_discovery:
                discovered = self._get_field(record, mapping, "target_field", None)
                if not discovered:
                    continue
                domain = extract_domain(discovered) if discovered else ""

                # For auth-free commands (AS-REP roast), discovered user IS the target
                # For auth-required commands (Kerberoast), use pwned credentials
                if mapping.get("auth_free"):
                    user = discovered  # Discovered user is the command target
                elif mapping.get("user_is_discovered"):
                    # Password-in-description: discovered user is who we authenticate AS
                    user = extract_username(discovered)
                else:
                    # Pick first pwned user with password for auth-required discovery
                    user = "<USER>"
                    if pwned_users:
                        for upn, pwned in pwned_users.items():
                            if pwned.get_credential("password"):
                                user = upn
                                break

                # Determine target: DC for user-centric discovery, otherwise discovered item
                if mapping.get("target_is_dc"):
                    # Target is the DC, not the discovered user
                    dc_host = infer_dc_hostname(domain) if domain else ""
                    targets = [dc_host] if dc_host else [discovered]
                    target_ips = [dc_ip] if dc_ip else []
                else:
                    targets = [discovered]  # What we found
                    target_ips = []  # Discovery commands don't have IPs
            else:
                # Standard command: user has access to target

                # Check for coercion commands (special handling)
                # Coercion: attacker uses own creds, CoercionHost is LISTENER, target is what we coerce
                if mapping.get("is_coercion"):
                    listener = self._get_field(record, mapping, "listener_field", None)
                    listener_ip = self._get_field(record, mapping, "listener_ip_field", None)
                    coerce_target = self._get_field(record, mapping, "target_field", None)

                    if not listener or not coerce_target:
                        continue

                    # Extract domain from listener (unconstrained delegation host)
                    domain = extract_domain(listener) if listener and "@" in listener else ""
                    if not domain and "." in listener:
                        # Extract from FQDN: DC1.CORP.COM -> CORP.COM
                        parts = listener.split(".")
                        if len(parts) >= 2:
                            domain = ".".join(parts[1:])

                    # Build entries for each coercion command
                    for cmd_id in cmd_ids:
                        if cmd_id not in tables:
                            cmd = self.commands.get(cmd_id, {})
                            if not cmd:
                                continue
                            rewards = context if context else ACCESS_TYPE_REWARDS.get(
                                access_type, ACCESS_TYPE_REWARDS.get(None, "")
                            )
                            tables[cmd_id] = CommandTable(
                                command_id=cmd_id,
                                name=cmd.get("name", cmd_id),
                                template=cmd.get("command", ""),
                                access_type=access_type,
                                targets=[],
                                variables_needed=self._get_sensitive_placeholders(cmd),
                                context=context,
                                domain_level=domain_level,
                                example=self._build_example(cmd),
                                objective=cmd.get("description", ""),
                                rewards=rewards,
                                post_success=mapping.get("post_success", []),
                                permissions_required=mapping.get("permissions_required", ""),
                                is_discovery=is_discovery,
                                is_coercion=True,  # Mark as coercion command
                            )

                        # For coercion: don't fill username (attacker provides own creds)
                        # Fill listener_ip and target_ip instead
                        ready = fill_command(
                            template=tables[cmd_id].template,
                            username="",  # Attacker provides creds - leave placeholder
                            target=coerce_target,
                            target_ip="",  # Target is what we coerce (domain/DC)
                            domain=domain,
                            dc_ip=dc_ip or "",
                            listener_ip=listener_ip or "",
                        )

                        reason = get_reason(
                            access_type=access_type,
                            user=listener,
                            target=coerce_target,
                            context=context
                        )

                        warnings = validate_target_entry(record, access_type)

                        tables[cmd_id].targets.append(TargetEntry(
                            user=listener,        # Display: unconstrained delegation host
                            target=coerce_target, # Display: what we're coercing
                            ready_command=ready,
                            domain=domain,
                            access_type=access_type,
                            reason=reason,
                            warnings=warnings,
                        ))

                    continue  # Skip normal processing for coercion records

                # Check for user_array_field pattern (multiple users → single target)
                if "user_array_field" in mapping:
                    user_array = record.get(mapping["user_array_field"], [])
                    if not isinstance(user_array, list):
                        user_array = [user_array] if user_array else []

                    # Get single target from target_field
                    single_target = self._get_field(record, mapping, "target_field", None)
                    if not single_target:
                        continue

                    # Get IP for single target (if available) - NEW
                    single_target_ip = ""
                    if "target_ip_field" in mapping:
                        single_target_ip = record.get(mapping["target_ip_field"], "") or ""

                    # Filter group names from user array if configured
                    if mapping.get("filter_groups"):
                        user_array = [u for u in user_array if u and not is_group_name(u)]

                    # Process each user with the same target
                    for user_principal in user_array:
                        if not user_principal:
                            continue
                        user_domain = extract_domain(user_principal)

                        # Build entries for each command
                        for cmd_id in cmd_ids:
                            if cmd_id not in tables:
                                cmd = self.commands.get(cmd_id, {})
                                if not cmd:
                                    continue
                                rewards = context if context else ACCESS_TYPE_REWARDS.get(
                                    access_type, ACCESS_TYPE_REWARDS.get(None, "")
                                )
                                tables[cmd_id] = CommandTable(
                                    command_id=cmd_id,
                                    name=cmd.get("name", cmd_id),
                                    template=cmd.get("command", ""),
                                    access_type=access_type,
                                    targets=[],
                                    variables_needed=self._get_sensitive_placeholders(cmd),
                                    context=context,
                                    domain_level=domain_level,
                                    example=self._build_example(cmd),
                                    objective=cmd.get("description", ""),
                                    rewards=rewards,
                                    post_success=mapping.get("post_success", []),
                                    permissions_required=mapping.get("permissions_required", ""),
                                    is_discovery=is_discovery,
                                )

                            # Look up pwned credentials for this user
                            password = ""
                            ntlm_hash = ""
                            if pwned_users and user_principal.upper() in pwned_users:
                                pwned = pwned_users[user_principal.upper()]
                                password = pwned.get_credential("password") or ""
                                ntlm_hash = pwned.get_credential("ntlm-hash") or ""

                            ready = fill_command(
                                template=tables[cmd_id].template,
                                username=user_principal,
                                target=single_target,
                                target_ip=single_target_ip,  # NEW: Pass IP
                                domain=user_domain,
                                dc_ip=dc_ip or "",  # DC IP from stored config
                                password=password,
                                ntlm_hash=ntlm_hash,
                            )

                            reason = get_reason(
                                access_type=access_type,
                                user=user_principal,
                                target=single_target,
                                context=context
                            )

                            warnings = validate_target_entry(record, access_type)

                            tables[cmd_id].targets.append(TargetEntry(
                                user=user_principal,
                                target=single_target,
                                ready_command=ready,
                                domain=user_domain,
                                access_type=access_type,
                                reason=reason,
                                warnings=warnings,
                            ))
                    continue  # Skip normal processing for this record

                # Normal pattern: single user → multiple targets
                # Get user principal - check principal_field first if no user_field
                user = self._get_field(record, mapping, "user_field", None)
                if not user and principal:
                    user = principal  # For DCSync, principal IS the user with the right
                if not user:
                    user = self._get_field(record, mapping, "user_field", "User")

                # Extract domain from UPN
                domain = extract_domain(user) if user else ""

                # Get targets - expand array fields or use single target
                targets = self._get_targets(record, mapping, user)

                # Get IPs (parallel to targets) - NEW
                target_ips = self._get_target_ips(record, mapping)

            # For domain_level commands, target is the domain DC
            if mapping.get("domain_level") and not targets:
                dc_host = infer_dc_hostname(domain)
                targets = [dc_host]
                # Use stored DC IP if available, otherwise fallback to FQDN
                target_ips = [dc_ip] if dc_ip else []

            # Dynamic access type from result (for owned-* queries)
            record_access_type = access_type
            if mapping.get("access_type_field"):
                record_access_type = record.get(mapping["access_type_field"], access_type)

            # Build entries for each command
            for cmd_id in cmd_ids:
                if cmd_id not in tables:
                    cmd = self.commands.get(cmd_id, {})
                    if not cmd:
                        continue
                    # Get rewards: use context if available, else lookup by access type
                    rewards = context if context else ACCESS_TYPE_REWARDS.get(
                        record_access_type,
                        ACCESS_TYPE_REWARDS.get(None, "")
                    )
                    tables[cmd_id] = CommandTable(
                        command_id=cmd_id,
                        name=cmd.get("name", cmd_id),
                        template=cmd.get("command", ""),
                        access_type=record_access_type,
                        targets=[],
                        variables_needed=self._get_sensitive_placeholders(cmd),
                        context=context,
                        domain_level=domain_level,
                        example=self._build_example(cmd),
                        objective=cmd.get("description", ""),
                        rewards=rewards,
                        post_success=mapping.get("post_success", []),
                        permissions_required=mapping.get("permissions_required", ""),
                        is_discovery=is_discovery,
                    )

                # Add target entries
                for idx, target in enumerate(targets):
                    if not target:
                        continue

                    # Filter group names used as targets
                    if is_group_name(target):
                        continue

                    # Get corresponding IP for this target (if available)
                    target_ip = ""
                    if idx < len(target_ips):
                        target_ip = target_ips[idx] or ""

                    # Look up pwned credentials for this user
                    password = ""
                    ntlm_hash = ""
                    if pwned_users and user.upper() in pwned_users:
                        pwned = pwned_users[user.upper()]
                        password = pwned.get_credential("password") or ""
                        ntlm_hash = pwned.get_credential("ntlm-hash") or ""

                    ready = fill_command(
                        template=tables[cmd_id].template,
                        username=user,
                        target=target,
                        target_ip=target_ip,  # NEW: Pass IP (preferred over FQDN)
                        domain=domain,
                        dc_ip=dc_ip or "",  # DC IP from stored config
                        password=password,
                        ntlm_hash=ntlm_hash,
                    )

                    # Generate reason for this command suggestion
                    if is_discovery:
                        # For discovery commands, reason explains what was found
                        reason = context if context else "Discovered target"
                        # Include Description field if present (for password-in-description, etc.)
                        description = record.get("Description", "")
                        if description:
                            # Show the actual description (e.g., "Temp password is Thestrokes23")
                            reason = description
                    else:
                        reason = get_reason(
                            access_type=record_access_type,
                            user=user,
                            target=target,
                            context=context
                        )

                    # Validate target entry for potential issues
                    warnings = validate_target_entry(record, record_access_type)

                    # For discovery commands, show discovered target in user column
                    display_user = target if is_discovery else user

                    tables[cmd_id].targets.append(TargetEntry(
                        user=display_user,
                        target=target if not is_discovery else domain,  # Domain for discovery
                        ready_command=ready,
                        domain=domain,
                        access_type=record_access_type,
                        reason=reason,
                        warnings=warnings,
                    ))

        # Deduplicate targets within each table
        for table in tables.values():
            table.targets = self._deduplicate_targets(table.targets)

        return list(tables.values())

    def _get_field(
        self,
        record: Dict,
        mapping: Dict,
        field_key: str,
        default_field: Optional[str]
    ) -> str:
        """Get field value from record using mapping config"""
        field_name = mapping.get(field_key, default_field)
        if not field_name:
            return ""
        return str(record.get(field_name, ""))

    def _get_targets(
        self,
        record: Dict,
        mapping: Dict,
        user: str
    ) -> List[str]:
        """
        Extract targets from record, handling array fields.

        Scenarios:
        1. Array field (AdminOnComputers, RDPTargets) -> expand to list
        2. Single target field (Computer, Target) -> single-item list
        3. Target is user (AS-REP roast) -> user as target
        """
        # Case 1: Array field
        if "array_field" in mapping:
            array_val = record.get(mapping["array_field"], [])
            if isinstance(array_val, list):
                return [str(t) for t in array_val if t]
            elif array_val:
                return [str(array_val)]

        # Case 2: Single target field
        if "target_field" in mapping:
            target = record.get(mapping["target_field"], "")
            return [str(target)] if target else []

        # Case 3: Target is user (for Kerberoast, AS-REP roast)
        if mapping.get("target_is_user"):
            return [user] if user else []

        # Fallback: try common target fields
        for field in ["Target", "Computer", "Victim", "Machine"]:
            if field in record:
                return [str(record[field])]

        return []

    def _get_target_ips(
        self,
        record: Dict,
        mapping: Dict
    ) -> List[Optional[str]]:
        """
        Extract IP addresses from record (parallel to targets).

        Returns list of IPs matching 1:1 with targets from _get_targets().
        Returns None for entries where IP unavailable.

        Scenarios:
        1. Array IP field (AdminOnIPs, RDPTargetIPs) -> expand to list
        2. Single IP field (ComputerIP, TargetIP) -> single-item list
        3. No IP field -> return empty list (will fallback to FQDN)

        Args:
            record: Query result record from Neo4j
            mapping: QUERY_COMMAND_MAPPINGS entry

        Returns:
            List of IP addresses (or None for unresolved computers)

        Examples:
            >>> # With array IPs
            >>> record = {"AdminOnComputers": ["DC1", "FILES04"], "AdminOnIPs": ["10.0.0.1", "10.0.0.15"]}
            >>> _get_target_ips(record, {"array_ip_field": "AdminOnIPs"})
            ['10.0.0.1', '10.0.0.15']

            >>> # No IPs available
            >>> record = {"Computer": "DC1"}
            >>> _get_target_ips(record, {})
            []
        """
        # Case 1: Array IP field (parallel to array_field)
        if "array_ip_field" in mapping:
            array_val = record.get(mapping["array_ip_field"], [])
            if isinstance(array_val, list):
                # Convert None values to empty strings for consistency
                return [str(ip) if ip else "" for ip in array_val]
            elif array_val:
                return [str(array_val)]

        # Case 2: Single IP field (parallel to target_field)
        if "target_ip_field" in mapping:
            ip = record.get(mapping["target_ip_field"], "")
            return [str(ip)] if ip else [""]

        # No IP fields defined - return empty list
        # (Command generator will fallback to FQDN)
        return []

    def _fill_command(
        self,
        template: str,
        user: str,
        target: str,
        domain: str
    ) -> str:
        """Fill command template with extracted values"""
        result = template

        # User-related placeholders - use just username (not full UPN)
        result = result.replace("<USERNAME>", extract_username(user))
        result = result.replace("<USER>", extract_username(user))

        # Target-related placeholders
        result = result.replace("<TARGET>", target)
        result = result.replace("<COMPUTER>", target)

        # Domain-related placeholders - lowercase for tool compatibility
        result = result.replace("<DOMAIN>", domain.lower() if domain else "")

        # DC inference
        dc_host = infer_dc_hostname(domain)
        result = result.replace("<DC_IP>", dc_host)
        result = result.replace("<DC>", dc_host)

        return result

    def _get_sensitive_placeholders(self, cmd: Dict) -> List[str]:
        """Find sensitive placeholders that should NOT be auto-filled"""
        template = cmd.get("command", "")
        remaining = re.findall(r'<[A-Z_]+>', template)
        return [p for p in remaining if p in SENSITIVE_PLACEHOLDERS]

    def _build_example(self, cmd: Dict) -> str:
        """
        Build complete example command from variable examples.

        Uses the 'example' field from each variable definition to create
        a fully populated command example.
        """
        template = cmd.get("command", "")
        if not template:
            return ""

        variables = cmd.get("variables", [])
        if not variables:
            return template  # No variables to fill

        result = template
        for var in variables:
            var_name = var.get("name", "")
            var_example = var.get("example", "")
            if var_name and var_example:
                result = result.replace(var_name, str(var_example))

        return result

    def _deduplicate_targets(self, targets: List[TargetEntry]) -> List[TargetEntry]:
        """Remove duplicate user+target combinations"""
        seen = set()
        unique = []
        for entry in targets:
            key = (entry.user, entry.target)
            if key not in seen:
                seen.add(key)
                unique.append(entry)
        return unique

    # =========================================================================
    # LEGACY API - backward compatible
    # =========================================================================

    def suggest_for_query(
        self,
        query_id: str,
        records: List[Dict],
        max_per_record: int = 3,
        max_total: int = 10
    ) -> Union[List[CommandSuggestion], List[AttackSequence]]:
        """
        Generate command suggestions for a query result.
        (Legacy API - kept for backward compatibility)
        """
        mapping = QUERY_COMMAND_MAPPINGS.get(query_id)
        if not mapping:
            return []

        if mapping == "BUILD_SEQUENCE":
            return self._build_sequences(query_id, records)

        # For dict-style mappings, convert to legacy format
        if isinstance(mapping, dict):
            cmd_ids = mapping.get("commands", [])
            context = mapping.get("context", "")
            mapping = [{"command_id": cid, "context": context} for cid in cmd_ids]

        suggestions = []
        seen_commands = set()

        for record in records[:max_total]:
            for cmd_info in mapping[:max_per_record]:
                cmd_id = cmd_info["command_id"]
                target = self._extract_target(record)
                key = (cmd_id, target)
                if key in seen_commands:
                    continue
                seen_commands.add(key)

                suggestion = self._create_suggestion(
                    cmd_id,
                    cmd_info["context"],
                    record
                )
                if suggestion:
                    suggestions.append(suggestion)

                if len(suggestions) >= max_total:
                    break
            if len(suggestions) >= max_total:
                break

        return suggestions

    def _extract_target(self, record: Dict) -> str:
        """Extract primary target identifier from record"""
        for f in ["Computer", "Target", "Victim", "User", "Principal"]:
            if f in record:
                return str(record[f])
        return ""

    def _create_suggestion(
        self,
        cmd_id: str,
        context: str,
        record: Dict
    ) -> Optional[CommandSuggestion]:
        """Create a single command suggestion with variable substitution"""
        cmd = self.commands.get(cmd_id)
        if not cmd:
            return None

        template = cmd.get("command", "")
        if not template:
            return None

        # Extract values from record
        user = ""
        target = ""
        domain = ""

        for f in ["User", "Principal", "ServiceAccount", "HighValueTarget", "Attacker"]:
            if f in record:
                user = str(record[f])
                domain = extract_domain(user)
                break

        for f in ["Computer", "Target", "Victim", "Machine", "Workstation"]:
            if f in record:
                target = str(record[f])
                break

        # Fill command
        ready = self._fill_command(template, user, target, domain)
        filled = {}

        if user:
            filled["<USERNAME>"] = user
        if target:
            filled["<TARGET>"] = target
        if domain:
            filled["<DOMAIN>"] = domain

        # Find remaining sensitive placeholders
        remaining = re.findall(r'<[A-Z_]+>', ready)
        needed = [p for p in remaining if p in SENSITIVE_PLACEHOLDERS]

        oscp_rel = cmd.get("oscp_relevance", "medium")
        if not oscp_rel:
            tags = cmd.get("tags", [])
            for tag in tags:
                if tag.startswith("OSCP:"):
                    oscp_rel = tag.split(":")[1].lower()
                    break

        return CommandSuggestion(
            command_id=cmd_id,
            name=cmd.get("name", cmd_id),
            context=context,
            template=template,
            ready_to_run=ready,
            variables_filled=filled,
            variables_needed=needed,
            oscp_relevance=oscp_rel,
        )

    def _build_sequences(
        self,
        query_id: str,
        records: List[Dict],
        max_sequences: int = 3
    ) -> List[AttackSequence]:
        """Build multi-step attack sequences from path query results"""
        sequences = []

        for record in records[:max_sequences]:
            path = self._extract_path(record)
            edges = self._extract_edges(record)

            if not path or not edges:
                continue

            steps = []
            for i, edge in enumerate(edges):
                cmd_ids = EDGE_COMMAND_MAPPINGS.get(edge, [])
                if not cmd_ids:
                    continue

                cmd_id = cmd_ids[0]
                context_record = {}
                if i + 1 < len(path):
                    context_record["Target"] = path[i + 1]
                    context_record["Computer"] = path[i + 1]
                if i < len(path):
                    context_record["User"] = path[i]
                    context_record["Principal"] = path[i]

                step = self._create_suggestion(
                    cmd_id,
                    f"Step {i + 1}: {edge}",
                    context_record
                )
                if step:
                    steps.append(step)

            if steps:
                path_str = " -> ".join(path[:4])
                if len(path) > 4:
                    path_str += f" -> ... ({len(path)} total)"

                sequences.append(AttackSequence(
                    name=f"Path: {path_str}",
                    description=f"{len(steps)}-step attack chain via {', '.join(edges[:3])}",
                    path_nodes=path,
                    edge_types=edges,
                    steps=steps,
                ))

        return sequences

    def _extract_path(self, record: Dict) -> List[str]:
        """Extract path nodes from query result"""
        for f in ["Path", "path", "Nodes", "nodes"]:
            if f in record:
                val = record[f]
                if isinstance(val, list):
                    return [str(n) for n in val]
                elif isinstance(val, str):
                    return [n.strip() for n in val.split("->")]
        return []

    def _extract_edges(self, record: Dict) -> List[str]:
        """Extract edge types from query result"""
        for f in ["EdgeTypes", "edgeTypes", "Edges", "edges", "RelationshipTypes"]:
            if f in record:
                val = record[f]
                if isinstance(val, list):
                    return [str(e) for e in val]
                elif isinstance(val, str):
                    return [e.strip() for e in val.split(",")]
        return []

    def get_commands_for_edge(self, edge_type: str) -> List[CommandSuggestion]:
        """Get all commands applicable for a specific edge type"""
        cmd_ids = EDGE_COMMAND_MAPPINGS.get(edge_type, [])
        suggestions = []

        for cmd_id in cmd_ids:
            suggestion = self._create_suggestion(
                cmd_id,
                f"Exploit {edge_type} relationship",
                {}
            )
            if suggestion:
                suggestions.append(suggestion)

        return suggestions

    def suggest_for_owned_user(
        self,
        user: str,
        access_types: List[Dict]
    ) -> List[CommandSuggestion]:
        """Generate suggestions for an owned user's access"""
        suggestions = []
        seen = set()

        for access in access_types:
            target = access.get("Target", access.get("Computer", ""))
            access_type = access.get("AccessType", "AdminTo")

            cmd_ids = EDGE_COMMAND_MAPPINGS.get(access_type, [])

            for cmd_id in cmd_ids[:2]:
                key = (cmd_id, target)
                if key in seen:
                    continue
                seen.add(key)

                record = {
                    "User": user,
                    "Target": target,
                    "Computer": target,
                }

                suggestion = self._create_suggestion(
                    cmd_id,
                    f"{access_type} to {target}",
                    record
                )
                if suggestion:
                    suggestions.append(suggestion)

        return suggestions

    # =========================================================================
    # ATTACK PATH RECOMMENDATIONS - DRY orchestration of existing components
    # =========================================================================

    def recommend_attack_paths(
        self,
        pwned_user: str,
        domain: str,
        query_runner: Any,  # QueryRunner - avoid circular import
        dc_ip: Optional[str] = None,
    ) -> List[AttackSequence]:
        """
        Recommend attack paths for a pwned user based on their AD position.

        Composes existing queries and command mappings - no new infrastructure.
        Checks prerequisite queries to validate attack chains are viable.

        Args:
            pwned_user: User principal name (e.g., "SVC-ALFRESCO@HTB.LOCAL")
            domain: Domain name (e.g., "htb.local")
            query_runner: QueryRunner instance for executing Cypher queries
            dc_ip: Domain Controller IP for command templates

        Returns:
            List of viable AttackSequence objects ranked by impact
        """
        recommendations = []

        # Find all mappings with attack_chain definitions
        for query_id, mapping in QUERY_COMMAND_MAPPINGS.items():
            if not isinstance(mapping, dict):
                continue

            chain = mapping.get("attack_chain")
            if not chain:
                continue

            # Check prerequisite queries
            prereq_queries = mapping.get("prerequisite_queries", [])
            prereqs_met = True
            prereq_results = {}

            for prereq_id in prereq_queries:
                try:
                    result = query_runner.run_query(
                        prereq_id,
                        {"USER": pwned_user}
                    )
                    if not result.records:
                        prereqs_met = False
                        break
                    prereq_results[prereq_id] = result.records
                except Exception:
                    prereqs_met = False
                    break

            if prereqs_met:
                # Build AttackSequence from chain definition
                sequence = self._build_attack_chain(
                    chain,
                    pwned_user,
                    domain,
                    dc_ip or "",
                    prereq_results
                )
                if sequence:
                    recommendations.append(sequence)

        return self._rank_attack_sequences(recommendations)

    def _build_attack_chain(
        self,
        chain: Dict,
        user: str,
        domain: str,
        dc_ip: str,
        prereq_results: Dict[str, List[Dict]],
    ) -> Optional[AttackSequence]:
        """
        Build AttackSequence from chain definition using existing infrastructure.

        Args:
            chain: Attack chain definition from query_mappings.json
            user: Pwned user principal name
            domain: Domain name
            dc_ip: Domain Controller IP
            prereq_results: Results from prerequisite queries

        Returns:
            AttackSequence with steps, or None if chain is invalid
        """
        steps = []

        for step_def in chain.get("steps", []):
            cmd_id = step_def.get("command")
            if not cmd_id:
                continue

            # Build context record for command generation
            record = {
                "User": user,
                "Domain": domain,
            }

            # Create suggestion using existing method
            suggestion = self._create_suggestion(
                cmd_id,
                step_def.get("why", step_def.get("name", "")),
                record
            )

            if suggestion:
                # Enhance with step metadata
                suggestion.context = f"Step {step_def.get('step_id', len(steps)+1)}: {step_def.get('name', '')}"
                if step_def.get("why"):
                    suggestion.context += f"\nWHY: {step_def['why']}"
                if step_def.get("verification"):
                    suggestion.context += f"\nVERIFY: {step_def['verification']}"
                if step_def.get("context") == "on_target":
                    suggestion.context += "\n[Run on target]"
                elif step_def.get("context") == "kali":
                    suggestion.context += "\n[Run on Kali]"

                steps.append(suggestion)

        if not steps:
            return None

        # Build path nodes from prereq results
        path_nodes = [user]
        if prereq_results:
            for prereq_id, records in prereq_results.items():
                for record in records:
                    if "Group" in record:
                        path_nodes.append(record["Group"])
                    if "Domain" in record:
                        path_nodes.append(record["Domain"])

        return AttackSequence(
            name=chain.get("name", "Unknown Attack Chain"),
            description=chain.get("description", ""),
            path_nodes=path_nodes,
            edge_types=[],  # Could be populated from chain definition
            steps=steps,
        )

    def _rank_attack_sequences(
        self,
        sequences: List[AttackSequence]
    ) -> List[AttackSequence]:
        """
        Rank attack sequences by impact and complexity.

        Priority:
        1. DCSync paths (domain compromise)
        2. Shorter paths (fewer steps)
        3. Paths with fewer prerequisites
        """
        def score(seq: AttackSequence) -> tuple:
            # Higher score = higher priority
            is_dcsync = any(
                "dcsync" in step.name.lower() or "dcsync" in step.context.lower()
                for step in seq.steps
            )
            return (
                1 if is_dcsync else 0,  # DCSync paths first
                -seq.total_steps,       # Fewer steps preferred
            )

        return sorted(sequences, key=score, reverse=True)

    def get_attack_chains(self) -> List[Dict]:
        """
        Get all defined attack chains from query mappings.

        Returns:
            List of attack chain definitions with metadata
        """
        chains = []
        for query_id, mapping in QUERY_COMMAND_MAPPINGS.items():
            if not isinstance(mapping, dict):
                continue
            chain = mapping.get("attack_chain")
            if chain:
                chains.append({
                    "query_id": query_id,
                    "chain_id": chain.get("id"),
                    "name": chain.get("name"),
                    "description": chain.get("description"),
                    "severity": chain.get("severity", "unknown"),
                    "oscp_relevance": chain.get("oscp_relevance", "unknown"),
                    "step_count": len(chain.get("steps", [])),
                    "prerequisite_queries": mapping.get("prerequisite_queries", []),
                })
        return chains
