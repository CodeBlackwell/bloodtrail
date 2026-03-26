"""
BloodTrail Interactive Session.

Main interaction loop for the recommendation engine.
Presents findings and recommendations one at a time.
"""

import subprocess
import shlex
from typing import Optional, Callable, List

from ..recommendation.engine import RecommendationEngine
from ..recommendation.models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
    Credential,
    CredentialType,
)
from .display import (
    display_finding,
    display_recommendation,
    display_credential_validated,
    display_stats,
    prompt_user,
)

# ANSI colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
D = "\033[90m"
X = "\033[0m"


class InteractiveSession:
    """
    Interactive session handler for BloodTrail.

    Manages the user interaction loop:
    1. Display findings as they arrive
    2. Present recommendations one at a time
    3. Execute commands on user approval
    4. Track state and progress
    """

    def __init__(
        self,
        engine: RecommendationEngine,
        auto_run: bool = False,
        verbose: bool = True,
    ):
        """
        Initialize interactive session.

        Args:
            engine: The recommendation engine
            auto_run: If True, automatically run recommendations
            verbose: If True, show detailed output
        """
        self.engine = engine
        self.auto_run = auto_run
        self.verbose = verbose
        self._running = False

        # Register callbacks
        self.engine.on_finding(self._on_finding)
        self.engine.on_recommendation(self._on_recommendation)

        # Pending items to present
        self._pending_findings: List[Finding] = []
        self._immediate_recommendations: List[Recommendation] = []

    def _on_finding(self, finding: Finding) -> None:
        """Callback when a new finding is added."""
        # Queue finding for display
        self._pending_findings.append(finding)

    def _on_recommendation(self, rec: Recommendation) -> None:
        """Callback when a new recommendation is added."""
        # If critical, flag for immediate attention
        if rec.priority == RecommendationPriority.CRITICAL:
            self._immediate_recommendations.append(rec)

    def start(self) -> None:
        """Start the interactive session."""
        self._running = True
        print(f"\n{C}BloodTrail Interactive Mode{X}")
        print(f"{D}Press Ctrl+C to exit, '?' for help{X}\n")

    def stop(self) -> None:
        """Stop the interactive session."""
        self._running = False
        print(f"\n{D}Session ended.{X}")
        print(display_stats(self.engine.get_stats()))

    def process_pending(self) -> bool:
        """
        Process any pending findings and recommendations.

        Returns True if there are more items to process.
        """
        # Display pending findings
        while self._pending_findings:
            finding = self._pending_findings.pop(0)
            if self.verbose:
                print(display_finding(finding))

        # Check for critical recommendations
        while self._immediate_recommendations:
            rec = self._immediate_recommendations.pop(0)
            self._present_recommendation(rec)

        return bool(self._pending_findings or self._immediate_recommendations)

    def run_recommendation_loop(self) -> None:
        """
        Main recommendation loop.

        Presents recommendations one at a time until:
        - No more pending recommendations
        - User quits
        """
        try:
            while self._running:
                # Process any pending items first
                self.process_pending()

                # Get next recommendation
                rec = self.engine.get_next_recommendation()
                if not rec:
                    print(f"\n{D}No more recommendations.{X}")
                    break

                # Present and handle
                if not self._present_recommendation(rec):
                    break

        except KeyboardInterrupt:
            print(f"\n{Y}Interrupted.{X}")
        finally:
            self.stop()

    def _present_recommendation(self, rec: Recommendation) -> bool:
        """
        Present a recommendation and handle user response.

        Returns:
            False if user wants to quit, True otherwise
        """
        print(display_recommendation(rec))

        if self.auto_run:
            response = 'r'
        else:
            response = prompt_user(
                f"{D}Action?{X}",
                options="rsq?"
            )

        if response == 'q':
            return False

        elif response == '?':
            self._show_help(rec)
            return self._present_recommendation(rec)  # Re-present

        elif response == 's':
            self.engine.skip_recommendation(rec.id)
            print(f"{D}Skipped.{X}")
            return True

        elif response == 'r':
            success = self._execute_recommendation(rec)
            if success:
                self.engine.complete_recommendation(rec.id)
            return True

        return True

    def _execute_recommendation(self, rec: Recommendation) -> bool:
        """
        Execute a recommendation.

        Returns:
            True if execution was successful
        """
        if rec.action_type == "run_command" and rec.command:
            return self._run_command(rec)

        elif rec.action_type == "tool_use":
            return self._run_tool(rec)

        elif rec.action_type == "manual_step":
            print(f"\n{Y}Manual step required:{X}")
            print(f"  {rec.description}")
            if rec.command:
                print(f"\n  {D}Suggested command:{X}")
                print(f"  {G}$ {rec.command}{X}")
            input(f"\n{D}Press Enter when done...{X}")
            return True

        return False

    def _run_command(self, rec: Recommendation) -> bool:
        """Run a shell command from recommendation."""
        if not rec.command:
            return False

        print(f"\n{D}Running:{X} {G}{rec.command}{X}\n")

        try:
            # Run command and capture output
            result = subprocess.run(
                rec.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Display output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(f"{R}{result.stderr}{X}")

            # Parse results for specific recommendation types
            return self._parse_command_result(rec, result)

        except subprocess.TimeoutExpired:
            print(f"{R}Command timed out{X}")
            return False
        except Exception as e:
            print(f"{R}Error: {e}{X}")
            return False

    def _parse_command_result(
        self,
        rec: Recommendation,
        result: subprocess.CompletedProcess,
    ) -> bool:
        """Parse command output and update state."""
        output = result.stdout + result.stderr

        # Check for credential validation (crackmapexec)
        if "crackmapexec" in rec.command and rec.metadata.get("username"):
            username = rec.metadata["username"]
            password = rec.metadata.get("password", "")

            # CME success indicators
            if "[+]" in output or "(Pwn3d!)" in output:
                is_admin = "(Pwn3d!)" in output
                access_level = "admin" if is_admin else "user"
                winrm = "winrm" in rec.command.lower()

                print(display_credential_validated(
                    username, password, access_level, winrm
                ))

                # Update engine state
                self.engine.add_credential(
                    username=username,
                    password=password,
                    validated=True,
                    access_level=access_level,
                    source_finding=rec.trigger_finding_id,
                    domain=self.engine.state.domain,
                )
                return True

            elif "[-]" in output or "STATUS_LOGON_FAILURE" in output:
                print(f"{R}✗ Credential invalid{X}")
                return False

        # Check for SMB enumeration (smbmap)
        if "smbmap" in rec.command:
            if "READ" in output or "WRITE" in output:
                print(f"{G}✓ Found accessible shares{X}")
                return True

        # Generic success check
        return result.returncode == 0

    def _run_tool(self, rec: Recommendation) -> bool:
        """Run an internal tool action."""
        tool_type = rec.metadata.get("decrypt_type")

        if tool_type == "vnc_des":
            from ..recommendation.decoders import decrypt_vnc_password

            encrypted_hex = rec.metadata.get("encrypted_hex", "")
            result = decrypt_vnc_password(encrypted_hex)

            if result.success:
                print(f"\n{G}✓ VNC password decrypted:{X} {result.decoded}")

                # Create credential finding
                # Try to determine username from context
                finding = self.engine.state.findings.get(rec.trigger_finding_id)
                if finding:
                    file_path = finding.target
                    # Try to extract username from path (e.g., ".../s.smith/...")
                    import re
                    match = re.search(r'/([a-zA-Z]\.[a-zA-Z]+)/', file_path)
                    if match:
                        username = match.group(1)
                        print(f"  {D}File was in {username}'s folder - likely their password{X}")

                        # Prompt to test as credential
                        if prompt_user(f"Test as password for {username}?", "yn") == 'y':
                            cred_finding = self.engine.create_ldap_attribute_finding(
                                username=username,
                                attribute_name="vnc_password",
                                attribute_value=result.decoded,
                                source="vnc_decrypt",
                            )
                            cred_finding.decoded_value = result.decoded
                            cred_finding.add_tag("likely_password")
                            self.engine.add_finding(cred_finding)

                return True
            else:
                print(f"{R}✗ Decryption failed: {result.notes}{X}")
                return False

        return False

    def _show_help(self, rec: Optional[Recommendation] = None) -> None:
        """Show help information."""
        print(f"""
{C}BloodTrail Interactive Help{X}

{D}Commands:{X}
  r  - Run the recommended action
  s  - Skip this recommendation
  q  - Quit interactive mode
  ?  - Show this help

{D}About Recommendations:{X}
  Recommendations are prioritized by urgency:
  {R}CRITICAL{X} - Act immediately (e.g., valid credential found)
  {Y}HIGH{X}     - Strong attack vector (e.g., AS-REP roastable)
  {C}MEDIUM{X}   - Worth investigating
  {D}LOW{X}      - Background task
  {D}INFO{X}     - For reference only
""")

        if rec:
            print(f"\n{D}Current recommendation:{X}")
            print(f"  {rec.description}")
            if rec.why:
                print(f"\n{D}Why this matters:{X}")
                print(f"  {rec.why}")
