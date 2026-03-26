"""
WizardState - State management for BloodTrail Wizard mode.

Provides persistence for wizard flow state including:
- Target information and detected services
- User selections and progress
- Findings and credentials discovered
- Access level tracking for iterative enumeration
- Checkpoint/resume capability
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional, Any


class AccessLevel(IntEnum):
    """
    Access level hierarchy for iterative enumeration.

    Higher levels unlock additional enumeration capabilities.
    When access level changes, re-enumeration is triggered.
    """
    ANONYMOUS = 0     # No credentials - anonymous enumeration only
    USER = 1          # Valid domain user credentials
    ADMIN = 2         # Local admin on target(s)
    DOMAIN_ADMIN = 3  # Domain Admin - engagement complete


@dataclass
class WizardState:
    """
    State container for wizard mode execution.

    Tracks all wizard progress including detection results, user choices,
    and discovered findings. Supports serialization for resume capability.

    Fields:
        target: Target IP or hostname
        domain: AD domain name (if detected)
        current_step: Current wizard step ID
        detected_services: List of detected services (port, name, version)
        detected_domain: Detected domain name from LDAP/Kerberos
        detected_dc: Detected domain controller hostname
        selected_mode: User-selected mode (auto/guided/skip)
        skip_steps: List of step IDs user chose to skip
        completed_steps: List of step IDs that have been completed
        findings: List of finding IDs discovered during enumeration
        credentials: List of discovered credentials (username, password, source)
        started_at: ISO timestamp when wizard started
        last_checkpoint: ISO timestamp of last state save

    Iterative Attack Loop Fields:
        access_level: Current access level (Anonymous, User, Admin, DA)
        last_enum_level: Access level at last enumeration (for re-enum trigger)
        current_cycle: Current attack cycle number (for display)
        current_user: Username of current authenticated context
        current_password: Password/hash for current authenticated context
        bloodhound_collected: Whether BloodHound data has been collected
        attack_complete: Whether engagement objective achieved
    """

    target: str
    domain: Optional[str] = None
    current_step: str = "detect"
    detected_services: List[Dict[str, Any]] = field(default_factory=list)
    detected_domain: Optional[str] = None
    detected_dc: Optional[str] = None
    selected_mode: str = "auto"
    skip_steps: List[str] = field(default_factory=list)
    completed_steps: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    started_at: Optional[str] = None
    last_checkpoint: Optional[str] = None

    # Iterative Attack Loop Fields
    access_level: int = AccessLevel.ANONYMOUS
    last_enum_level: int = AccessLevel.ANONYMOUS
    current_cycle: int = 0
    current_user: Optional[str] = None
    current_password: Optional[str] = None
    bloodhound_collected: bool = False
    attack_complete: bool = False

    def __post_init__(self):
        """Auto-set started_at if not provided."""
        if self.started_at is None:
            self.started_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize state to dictionary for JSON persistence.

        Returns:
            Dictionary with all state fields
        """
        return {
            "target": self.target,
            "domain": self.domain,
            "current_step": self.current_step,
            "detected_services": self.detected_services,
            "detected_domain": self.detected_domain,
            "detected_dc": self.detected_dc,
            "selected_mode": self.selected_mode,
            "skip_steps": self.skip_steps,
            "completed_steps": self.completed_steps,
            "findings": self.findings,
            "credentials": self.credentials,
            "started_at": self.started_at,
            "last_checkpoint": self.last_checkpoint,
            # Iterative attack loop fields
            "access_level": self.access_level,
            "last_enum_level": self.last_enum_level,
            "current_cycle": self.current_cycle,
            "current_user": self.current_user,
            "current_password": self.current_password,
            "bloodhound_collected": self.bloodhound_collected,
            "attack_complete": self.attack_complete,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WizardState":
        """
        Deserialize state from dictionary.

        Args:
            data: Dictionary with state fields (from JSON)

        Returns:
            WizardState instance with populated fields
        """
        return cls(
            target=data["target"],
            domain=data.get("domain"),
            current_step=data.get("current_step", "detect"),
            detected_services=data.get("detected_services", []),
            detected_domain=data.get("detected_domain"),
            detected_dc=data.get("detected_dc"),
            selected_mode=data.get("selected_mode", "auto"),
            skip_steps=data.get("skip_steps", []),
            completed_steps=data.get("completed_steps", []),
            findings=data.get("findings", []),
            credentials=data.get("credentials", []),
            started_at=data.get("started_at"),
            last_checkpoint=data.get("last_checkpoint"),
            # Iterative attack loop fields
            access_level=data.get("access_level", AccessLevel.ANONYMOUS),
            last_enum_level=data.get("last_enum_level", AccessLevel.ANONYMOUS),
            current_cycle=data.get("current_cycle", 0),
            current_user=data.get("current_user"),
            current_password=data.get("current_password"),
            bloodhound_collected=data.get("bloodhound_collected", False),
            attack_complete=data.get("attack_complete", False),
        )

    def save(self, target: str) -> Path:
        """
        Save state to JSON file.

        Args:
            target: Target IP or hostname (used for filename)

        Returns:
            Path to saved state file

        File location: ~/.crack/wizard_state/<target>.json
        """
        # Create state directory
        state_dir = Path.home() / ".crack" / "wizard_state"
        state_dir.mkdir(parents=True, exist_ok=True)

        # Use target as filename (sanitized)
        safe_target = target.replace(":", "_").replace("/", "_")
        state_file = state_dir / f"{safe_target}.json"

        # Update checkpoint timestamp
        self.last_checkpoint = datetime.now().isoformat()

        # Write JSON
        with open(state_file, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

        return state_file

    @classmethod
    def load(cls, target: str) -> Optional["WizardState"]:
        """
        Load state from JSON file.

        Args:
            target: Target IP or hostname (used for filename lookup)

        Returns:
            WizardState instance if file exists, None otherwise

        File location: ~/.crack/wizard_state/<target>.json
        """
        # Construct expected file path
        state_dir = Path.home() / ".crack" / "wizard_state"
        safe_target = target.replace(":", "_").replace("/", "_")
        state_file = state_dir / f"{safe_target}.json"

        # Check if file exists
        if not state_file.exists():
            return None

        # Load and deserialize
        try:
            with open(state_file) as f:
                data = json.load(f)
            return cls.from_dict(data)
        except (json.JSONDecodeError, KeyError, ValueError):
            # Corrupted file - return None instead of crashing
            return None

    # ==========================================================================
    # Iterative Attack Loop Helpers
    # ==========================================================================

    def should_reenumerate(self) -> bool:
        """
        Check if re-enumeration is needed due to access level change.

        Returns True if current access level is higher than when we
        last enumerated (e.g., gained credentials).
        """
        return self.access_level > self.last_enum_level

    def update_access_level(
        self,
        new_level: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bool:
        """
        Update access level when credentials are obtained.

        Args:
            new_level: New AccessLevel value
            username: Username for new access level
            password: Password/hash for new access level

        Returns:
            True if level changed (triggers re-enumeration)
        """
        if new_level > self.access_level:
            self.access_level = new_level
            if username:
                self.current_user = username
            if password:
                self.current_password = password
            return True
        return False

    def add_credential(
        self,
        username: str,
        password: str,
        source: str,
        validated: bool = False,
    ) -> None:
        """
        Add a discovered credential to state.

        Args:
            username: Username
            password: Password or hash
            source: Where credential was found (e.g., 'asrep_crack')
            validated: Whether credential has been tested and works
        """
        cred = {
            "username": username,
            "password": password,
            "source": source,
            "validated": validated,
            "discovered_at": datetime.now().isoformat(),
        }

        # Avoid duplicates
        for existing in self.credentials:
            if (existing["username"] == username and
                existing["password"] == password):
                # Update validation status if newly validated
                if validated and not existing.get("validated"):
                    existing["validated"] = True
                return

        self.credentials.append(cred)

    def get_validated_credentials(self) -> List[Dict[str, str]]:
        """Get all validated credentials."""
        return [c for c in self.credentials if c.get("validated")]

    def get_access_level_name(self) -> str:
        """Get human-readable access level name."""
        level_names = {
            AccessLevel.ANONYMOUS: "Anonymous",
            AccessLevel.USER: "Domain User",
            AccessLevel.ADMIN: "Local Admin",
            AccessLevel.DOMAIN_ADMIN: "Domain Admin",
        }
        return level_names.get(self.access_level, "Unknown")

    def is_domain_admin(self) -> bool:
        """Check if Domain Admin has been achieved."""
        return self.access_level >= AccessLevel.DOMAIN_ADMIN
