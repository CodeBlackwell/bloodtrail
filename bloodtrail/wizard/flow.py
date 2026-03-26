"""
BloodTrail Wizard Flow Controller - Iterative Attack Loop.

The wizard uses an iterative attack loop rather than fixed steps:

Phase 1 (One-time):
    - Detection: Probe ports, identify DC
    - Mode Selection: Auto/Guided/Skip

Phase 2 (Iterative):
    ATTACK LOOP:
    ┌─────────────────────────────────────────────────────────────────┐
    │   ┌─────────┐     ┌──────────┐     ┌────────────────┐          │
    │   │ Discover│ ──► │ Analyze  │ ──► │ Present Action │          │
    │   └────┬────┘     └────┬─────┘     └───────┬────────┘          │
    │        │               │                    │                   │
    │        │               │                    ▼                   │
    │        │               │           [R]un / [S]kip / [Q]uit      │
    │        │               │                    │                   │
    │        │               │                    ▼                   │
    │        │               │           ┌────────────────┐           │
    │        │               │           │ Execute Action │           │
    │        │               │           └───────┬────────┘           │
    │        │               ▼                   │                    │
    │        │    New findings from action ◄─────┘                    │
    │        │               │                                        │
    │        └───────────────┘                                        │
    │                                                                 │
    │   Exit conditions:                                              │
    │   - User quits                                                  │
    │   - Domain admin achieved                                       │
    │   - All recommendations exhausted AND no new findings possible  │
    └─────────────────────────────────────────────────────────────────┘

Usage:
    # Fresh run
    flow = WizardFlow(target="10.10.10.161", resume=False)
    final_state = flow.run()

    # Resume
    flow = WizardFlow(target="10.10.10.161", resume=True)
    final_state = flow.run()
"""

from typing import Dict, Optional, List
from .state import WizardState, AccessLevel
from .steps import (
    WizardStep, StepResult, DetectStep, ChooseModeStep,
    EnumerateStep, AnalyzeStep, RecommendStep
)
from ..recommendation import BloodHoundAnalyzer

# ANSI color codes for progress display
C = "\033[96m"   # Cyan
Y = "\033[93m"   # Yellow
G = "\033[92m"   # Green
R = "\033[91m"   # Red
D = "\033[90m"   # Dim
M = "\033[95m"   # Magenta
BOLD = "\033[1m"
X = "\033[0m"    # Reset

# Box drawing for summary
BOX_TL = "┌"
BOX_TR = "┐"
BOX_BL = "└"
BOX_BR = "┘"
BOX_H = "─"
BOX_V = "│"


class WizardFlow:
    """
    Wizard flow controller with iterative attack loop.

    Manages step execution with state persistence and access level tracking.

    Attributes:
        state: Current wizard state (includes access level)
        context: Shared context dict for inter-step communication
        bh_analyzer: BloodHound analyzer for post-collection analysis
    """

    # One-time steps (Phase 1)
    INIT_STEPS: Dict[str, WizardStep] = {
        "detect": DetectStep(),
        "choose_mode": ChooseModeStep(),
    }

    # Iterative steps (Phase 2 - attack loop)
    LOOP_STEPS: Dict[str, WizardStep] = {
        "enumerate": EnumerateStep(),
        "analyze": AnalyzeStep(),
        "recommend": RecommendStep(),
    }

    def __init__(self, target: str, resume: bool = False):
        """
        Initialize wizard flow.

        Args:
            target: Target IP or hostname
            resume: If True, attempt to load saved state for target
        """
        self.target = target
        self.context: Dict = {}
        self.bh_analyzer = BloodHoundAnalyzer()

        # Resume logic
        if resume:
            loaded_state = WizardState.load(target)
            if loaded_state:
                self.state = loaded_state
                print(f"[*] Resuming from cycle {self.state.current_cycle}")
                print(f"    Access level: {self.state.get_access_level_name()}")
            else:
                self.state = WizardState(target=target)
                print(f"[*] No saved state found - starting fresh")
        else:
            self.state = WizardState(target=target)

    def run(self) -> WizardState:
        """
        Execute wizard flow with iterative attack loop.

        Phase 1: Run one-time initialization steps
        Phase 2: Run iterative attack loop until complete

        Returns:
            Final WizardState after completion
        """
        try:
            # Phase 1: One-time initialization
            if not self._run_init_phase():
                self._save_checkpoint()
                return self.state

            # Phase 2: Iterative attack loop
            self._run_attack_loop()

        except KeyboardInterrupt:
            print(f"\n{Y}[!] Interrupted{X} - saving progress...")
            self._save_checkpoint()
            print(f"\n{C}Resume with:{X} crack bloodtrail --wizard-resume {self.target}")
            raise

        # Final checkpoint
        self._save_checkpoint()

        # Display summary
        self._display_summary()

        return self.state

    def _run_init_phase(self) -> bool:
        """
        Run one-time initialization steps (Detection, Mode Selection).

        Returns:
            True if init completed successfully, False otherwise
        """
        init_sequence = ["detect", "choose_mode"]

        for step_id in init_sequence:
            # Skip if already completed
            if step_id in self.state.completed_steps:
                continue

            step = self.INIT_STEPS.get(step_id)
            if not step:
                continue

            # Check prerequisites
            if not step.can_run(self.state):
                print(f"{R}[!]{X} Init step '{step.title}' prerequisites not met")
                return False

            # Execute step
            print(f"\n{C}[INIT]{X} {BOLD}{step.title}{X}")
            try:
                result = step.run(self.state, self.context)

                if result.success:
                    if step_id not in self.state.completed_steps:
                        self.state.completed_steps.append(step_id)
                    if result.message:
                        print(f"  {G}→{X} {result.message}")
                    self._save_checkpoint()
                else:
                    print(f"{R}[!]{X} Init failed: {result.message}")
                    return False

            except Exception as e:
                print(f"{R}[!]{X} Error in '{step.title}': {e}")
                return False

        return True

    def _run_attack_loop(self) -> None:
        """
        Run iterative attack loop.

        Loop:
        1. Enumerate (if access level changed or first run)
        2. Analyze findings → generate recommendations
        3. Present recommendations one at a time
        4. Execute or skip
        5. Check for new access level or findings
        6. Repeat until done
        """
        max_cycles = 50  # Safety limit

        while self.state.current_cycle < max_cycles:
            self.state.current_cycle += 1

            # Display cycle header with access level
            access_level_str = self.state.get_access_level_name()
            print(f"\n{M}{'═' * 70}{X}")
            print(f" {M}CYCLE {self.state.current_cycle}{X}: {access_level_str} Enumeration")
            print(f"{M}{'═' * 70}{X}")

            # Check for Domain Admin (victory condition)
            if self.state.is_domain_admin():
                self._display_victory()
                self.state.attack_complete = True
                return

            # Step 1: Enumerate (if needed)
            if self.state.should_reenumerate() or self.state.current_cycle == 1:
                if not self._run_enumeration():
                    break

            # Step 2: Analyze
            if not self._run_analysis():
                break

            # Step 3: Run BloodHound analyzer if data was collected this cycle
            if self.state.bloodhound_collected:
                self._run_bloodhound_analysis()

            # Step 4: Recommendation loop
            action_taken = self._run_recommendation_loop()

            # If no action was taken and no recommendations, check if we're done
            if not action_taken:
                if not self.state.should_reenumerate():
                    print(f"\n{Y}[*]{X} No more actions available at current access level")
                    break
                # Otherwise, loop back and re-enumerate with new access

            # Save checkpoint after each cycle
            self._save_checkpoint()

    def _run_enumeration(self) -> bool:
        """
        Run enumeration step.

        Returns:
            True if successful, False otherwise
        """
        step = self.LOOP_STEPS["enumerate"]

        if not step.can_run(self.state):
            return False

        print(f"\n{C}[ENUMERATE]{X} Running enumerators...")

        try:
            result = step.run(self.state, self.context)

            if result.success:
                # Mark last enumeration level
                self.state.last_enum_level = self.state.access_level
                if result.message:
                    print(f"  {G}→{X} {result.message}")
                return True
            else:
                print(f"{R}[!]{X} Enumeration failed: {result.message}")
                return False

        except Exception as e:
            print(f"{R}[!]{X} Enumeration error: {e}")
            return False

    def _run_analysis(self) -> bool:
        """
        Run analysis step to generate recommendations from findings.

        Returns:
            True if successful, False otherwise
        """
        step = self.LOOP_STEPS["analyze"]

        if not step.can_run(self.state):
            return True  # Analysis is optional if no findings

        print(f"\n{C}[ANALYZE]{X} Processing findings...")

        try:
            result = step.run(self.state, self.context)

            if result.success:
                if result.message:
                    print(f"  {G}→{X} {result.message}")
                return True
            else:
                print(f"{Y}[!]{X} Analysis: {result.message}")
                return True  # Continue even if analysis has issues

        except Exception as e:
            print(f"{Y}[!]{X} Analysis error: {e}")
            return True

    def _run_bloodhound_analysis(self) -> None:
        """
        Run BloodHound analyzer after SharpHound collection.

        Detects privilege escalation paths like:
        - Account Operators membership
        - Exchange WriteDACL
        - Other ACL abuse paths
        """
        if not self.state.current_user or not self.state.domain:
            return

        if not self.bh_analyzer.is_neo4j_available():
            print(f"  {D}[BloodHound] Neo4j not available, skipping analysis{X}")
            return

        print(f"\n{C}[BLOODHOUND]{X} Analyzing attack paths...")

        findings = self.bh_analyzer.analyze_attack_paths(
            username=self.state.current_user,
            domain=self.state.domain,
        )

        if findings:
            print(f"  {G}→{X} Found {len(findings)} privilege escalation path(s)")

            # Add findings to context for analysis
            if "bh_findings" not in self.context:
                self.context["bh_findings"] = []
            self.context["bh_findings"].extend(findings)

            # Add finding IDs to state
            for f in findings:
                if f.id not in self.state.findings:
                    self.state.findings.append(f.id)

            # Re-run analysis to generate recommendations from BH findings
            self._run_analysis()

        # Clear flag so we don't re-analyze
        self.state.bloodhound_collected = False

    def _run_recommendation_loop(self) -> bool:
        """
        Run recommendation presentation loop.

        Presents ONE recommendation at a time, waits for user action.

        Returns:
            True if at least one action was taken, False otherwise
        """
        step = self.LOOP_STEPS["recommend"]
        action_taken = False

        while True:
            if not step.can_run(self.state):
                break

            try:
                result = step.run(self.state, self.context)

                if result.success:
                    action_taken = True

                    # Check for special result data
                    if result.data:
                        # Handle credential discovery
                        if "credential" in result.data:
                            cred = result.data["credential"]
                            self.state.add_credential(
                                username=cred.get("username", ""),
                                password=cred.get("password", ""),
                                source=cred.get("source", "unknown"),
                                validated=cred.get("validated", False),
                            )

                        # Handle access level change
                        if "new_access_level" in result.data:
                            new_level = result.data["new_access_level"]
                            username = result.data.get("username")
                            password = result.data.get("password")

                            if self.state.update_access_level(new_level, username, password):
                                print(f"\n  {G}★{X} {BOLD}ACCESS LEVEL CHANGED:{X} {self.state.get_access_level_name()}")
                                # Break to re-enumerate with new access
                                break

                        # Handle BloodHound collection
                        if result.data.get("bloodhound_collected"):
                            self.state.bloodhound_collected = True
                            # Break to run BH analysis
                            break

                    if result.message:
                        print(f"  {G}→{X} {result.message}")

                else:
                    # No more recommendations or user quit
                    if result.message and "quit" in result.message.lower():
                        return action_taken
                    break

            except Exception as e:
                print(f"{R}[!]{X} Recommendation error: {e}")
                break

        return action_taken

    def _display_victory(self) -> None:
        """Display Domain Admin achievement banner."""
        print(f"\n{G}{'═' * 70}{X}")
        print(f"{G}{BOX_V}{X} {BOLD}{G}★ DOMAIN ADMIN ACHIEVED ★{X}".ljust(79) + f"{G}{BOX_V}{X}")
        print(f"{G}{'═' * 70}{X}")

        print(f"\n{BOLD}Attack Path:{X}")
        print(f"  Anonymous → ", end="")
        if self.state.credentials:
            for i, cred in enumerate(self.state.credentials):
                if i > 0:
                    print(f" → ", end="")
                print(f"{cred['username']}", end="")
        print()

        print(f"\n{BOLD}Credentials Collected:{X}")
        for cred in self.state.credentials:
            validated = f"{G}✓{X}" if cred.get("validated") else f"{Y}?{X}"
            print(f"  {validated} {cred['username']}:{cred['password'][:20]}...")

    def _save_checkpoint(self) -> None:
        """Save current state as checkpoint."""
        try:
            self.state.save(self.target)
        except Exception as e:
            print(f"  {Y}[!]{X} Warning: Failed to save checkpoint: {e}")

    def _display_summary(self) -> None:
        """Display final wizard summary."""
        # Summary box header
        print(f"\n{G}{BOX_TL}{BOX_H * 70}{BOX_TR}{X}")
        title = " DOMAIN ADMIN" if self.state.is_domain_admin() else " Wizard Complete"
        print(f"{G}{BOX_V}{X} {BOLD}{title}{X}".ljust(80) + f"{G}{BOX_V}{X}")
        print(f"{G}{BOX_BL}{BOX_H * 70}{BOX_BR}{X}")

        # Summary details
        print(f"\n{BOLD}Summary:{X}")
        print(f"  {C}Attack cycles:{X} {self.state.current_cycle}")
        print(f"  {C}Final access level:{X} {self.state.get_access_level_name()}")
        print(f"  {C}Findings discovered:{X} {len(self.state.findings)}")
        print(f"  {C}Credentials found:{X} {len(self.state.credentials)}")

        if self.state.is_domain_admin():
            print(f"\n  {G}★{X} {BOLD}DOMAIN ADMIN ACHIEVED{X}")
        elif self.state.attack_complete:
            print(f"\n  {G}✓{X} All steps completed successfully")
        else:
            print(f"\n  {Y}⚠{X} Stopped at cycle: {self.state.current_cycle}")

        # List credentials
        if self.state.credentials:
            print(f"\n{BOLD}Credentials:{X}")
            for cred in self.state.credentials:
                validated = f"{G}✓{X}" if cred.get("validated") else f"{Y}?{X}"
                print(f"  {validated} {cred['username']}:{cred['password'][:30]}...")

        print()
