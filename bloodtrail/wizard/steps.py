"""
BloodTrail Wizard Step Framework.

Defines the step execution model and concrete step implementations.

Design Philosophy:
- Each step is self-contained with clear prerequisites
- Steps return explicit next-step routing
- Steps modify state for downstream steps
- Steps are skippable unless critical
"""

import socket
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class StepResult:
    """Result of step execution.

    Attributes:
        success: Whether step completed successfully
        next_step: ID of next step to execute
        message: Optional human-readable message
        data: Optional data dict for downstream steps
    """
    success: bool
    next_step: str
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class WizardStep(ABC):
    """Abstract base class for wizard steps.

    Each step implements:
    - can_run(): Check if prerequisites are met
    - run(): Execute step logic and return result

    Class Attributes:
        id: Unique step identifier
        title: Human-readable step name
        description: Brief description of what step does
        skippable: Whether user can skip this step
    """

    # Subclasses MUST define these
    id: str = ""
    title: str = ""
    description: str = ""
    skippable: bool = False

    @abstractmethod
    def can_run(self, state) -> bool:
        """Check if step can run given current state.

        Args:
            state: Current WizardState

        Returns:
            True if prerequisites are met
        """
        pass

    @abstractmethod
    def run(self, state, context: Dict) -> StepResult:
        """Execute step logic.

        Args:
            state: Current WizardState (mutable, modify in-place)
            context: Shared context dict for step communication

        Returns:
            StepResult with success status and next step
        """
        pass


class DetectStep(WizardStep):
    """Target detection and capability discovery.

    Probes target for common AD services:
    - Port 88: Kerberos (DC signature)
    - Port 389: LDAP (DC signature)
    - Port 445: SMB
    - Port 3389: RDP

    Updates state:
    - detected_services: List of open services
    - detected_dc: True if port 88 or 389 open
    - detected_domain: Domain name if discoverable via LDAP
    """

    id = "detect"
    title = "Target Detection"
    description = "Auto-detect target capabilities"
    skippable = False  # Critical step

    # AD service ports to probe
    AD_PORTS = {
        88: "kerberos",
        389: "ldap",
        445: "smb",
        3389: "rdp",
        636: "ldaps",
        3268: "gc",  # Global Catalog
    }

    def can_run(self, state) -> bool:
        """DetectStep can always run (no prerequisites)."""
        return True

    def run(self, state, context: Dict) -> StepResult:
        """Probe target and detect services.

        Args:
            state: WizardState to update
            context: Shared context (unused)

        Returns:
            StepResult with detected services
        """
        target = state.target
        detected = []

        print(f"\n  Probing {target} for AD services...")
        print(f"  {'─' * 70}")

        # Method 1: Fast socket probe for common ports
        for port, service_name in sorted(self.AD_PORTS.items()):
            print(f"  Port {port:5d} ({service_name:12s}) ... ", end="", flush=True)
            if self._is_port_open(target, port):
                detected.append({
                    "port": port,
                    "service": service_name,
                    "state": "open"
                })
                print("OPEN ✓")
            else:
                print("closed")

        print(f"  {'─' * 70}")

        # Update state with detected services
        state.detected_services = detected

        # Detect if target is likely a DC
        dc_ports = {88, 389}
        detected_ports = {s["port"] for s in detected}
        if dc_ports & detected_ports:  # Any DC port open
            state.detected_dc = True
            print(f"\n  ⚡ Target appears to be a Domain Controller (Kerberos/LDAP detected)")

        # Try to detect domain name via LDAP if available
        if 389 in detected_ports:
            print(f"\n  Querying LDAP for domain information...")
            print(f"  $ ldapsearch -x -H ldap://{target} -s base defaultNamingContext")
            domain = self._detect_domain_via_ldap(target)
            if domain:
                state.detected_domain = domain
                if not state.domain:
                    state.domain = domain
                print(f"  Domain detected: {domain}")
            else:
                print(f"  Could not determine domain name")

        # Build result message
        if detected:
            service_list = ", ".join(s["service"] for s in detected)
            message = f"Detected services: {service_list}"
            print(f"\n  Summary: {len(detected)} services open")
        else:
            message = "No AD services detected on common ports"
            print(f"\n  ⚠ No AD services detected on common ports")

        return StepResult(
            success=True,
            next_step="choose_mode",
            message=message,
            data={"detected_count": len(detected)}
        )

    def _is_port_open(self, target: str, port: int, timeout: int = 2) -> bool:
        """Check if port is open via socket connection.

        Args:
            target: IP or hostname
            port: Port number
            timeout: Connection timeout in seconds

        Returns:
            True if port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except (socket.error, socket.gaierror):
            return False

    def _detect_domain_via_ldap(self, target: str, timeout: int = 5) -> Optional[str]:
        """Detect domain name via LDAP RootDSE query.

        Reuses logic from enumerators/domain_detect.py.

        Args:
            target: IP or hostname
            timeout: Query timeout in seconds

        Returns:
            Domain name (e.g., 'CASCADE.LOCAL') or None
        """
        try:
            # Try to import and use existing domain detection
            from tools.post.bloodtrail.enumerators.domain_detect import detect_domain

            info = detect_domain(target, timeout)
            if info.domain:
                return info.domain.upper()

        except ImportError:
            # Fallback: manual LDAP query
            try:
                cmd = [
                    "ldapsearch", "-x", "-H", f"ldap://{target}",
                    "-s", "base", "defaultNamingContext"
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                # Parse: defaultNamingContext: DC=cascade,DC=local
                import re
                match = re.search(r'defaultNamingContext:\s*(.+)', proc.stdout, re.I)
                if match:
                    dn = match.group(1).strip()
                    # Convert DC=cascade,DC=local to CASCADE.LOCAL
                    parts = []
                    for component in dn.split(','):
                        component = component.strip()
                        if component.upper().startswith('DC='):
                            parts.append(component[3:])
                    if parts:
                        return '.'.join(parts).upper()

            except (subprocess.TimeoutExpired, Exception):
                pass

        return None


class ChooseModeStep(WizardStep):
    """Mode selection step.

    Presents three options:
    1. Auto (recommended) - Guided enumeration with recommendations
    2. Guided - Step-by-step manual control
    3. Skip - Go straight to analysis

    Updates state.selected_mode.
    """

    id = "choose_mode"
    title = "Choose Enumeration Mode"
    description = "Select how to proceed with enumeration"
    skippable = True

    def can_run(self, state) -> bool:
        """Can run if detection completed."""
        return "detect" in state.completed_steps or len(state.detected_services) > 0

    def run(self, state, context: Dict) -> StepResult:
        """Prompt user for mode selection.

        Presents three mode options:
        1. Auto (recommended) - Fully guided enumeration
        2. Guided - Step-by-step with manual approval
        3. Skip - Go straight to recommendations

        Args:
            state: WizardState to update
            context: Shared context

        Returns:
            StepResult with selected mode
        """
        # Import select_from_list for interactive selection
        from ..cli.interactive import select_from_list

        # Define mode options with descriptions
        modes = [
            "Auto - Run all enumerators automatically (recommended)",
            "Guided - Prompt before each enumerator, step-by-step control",
            "Skip - Go straight to recommendations (no enumeration)"
        ]

        # Present options and get user selection
        selection = select_from_list(
            items=modes,
            prompt="Choose enumeration mode",
            allow_manual=False
        )

        # Map selection to mode value
        if "Auto" in selection or selection == modes[0]:
            state.selected_mode = "auto"
            next_step = "enumerate"
            message = "Auto mode selected"
        elif "Guided" in selection or selection == modes[1]:
            state.selected_mode = "guided"
            next_step = "enumerate"
            message = "Guided mode selected"
        elif "Skip" in selection or selection == modes[2]:
            state.selected_mode = "skip"
            next_step = "recommend"
            message = "Skipping to recommendations"
        else:
            # Default to auto if something went wrong
            state.selected_mode = "auto"
            next_step = "enumerate"
            message = "Defaulting to auto mode"

        return StepResult(
            success=True,
            next_step=next_step,
            message=message,
            data={"mode": state.selected_mode}
        )


class EnumerateStep(WizardStep):
    """Enumeration step.

    Runs enumerators based on detected services and aggregates findings.

    Only runs enumerators relevant to detected services:
    - SMB (445) → enum4linux, rpcclient, lookupsid
    - LDAP (389) → ldapsearch
    - Kerberos (88) → kerbrute, GetNPUsers

    Updates state.findings with Finding IDs.
    """

    id = "enumerate"
    title = "Enumeration"
    description = "Run targeted enumeration based on detected services"
    skippable = True

    def can_run(self, state) -> bool:
        """Enumerate step can always run (no hard prerequisites)."""
        return True

    def run(self, state, context: Dict) -> StepResult:
        """Run enumerators and aggregate findings.

        Args:
            state: WizardState to update
            context: Shared context (stores finding_objects for analyze step)

        Returns:
            StepResult with findings count
        """
        # Import enumerators
        from ..enumerators import get_available_enumerators
        from ..enumerators.aggregator import aggregate_results
        from ..recommendation.models import Finding, FindingType

        target = state.target
        detected_ports = {s["port"] for s in state.detected_services}

        # Determine which enumerators to run based on detected services
        available_enums = get_available_enumerators()
        to_run = []

        # SMB-based enumerators (445)
        if 445 in detected_ports:
            smb_enums = ["enum4linux", "rpcclient", "lookupsid"]
            to_run.extend([e for e in available_enums if e.id in smb_enums])

        # LDAP-based enumerators (389, 636, 3268)
        if detected_ports & {389, 636, 3268}:
            ldap_enums = ["ldapsearch"]
            to_run.extend([e for e in available_enums if e.id in ldap_enums])

        # Kerberos-based enumerators (88)
        if 88 in detected_ports:
            kerb_enums = ["kerbrute", "getnpusers"]
            to_run.extend([e for e in available_enums if e.id in kerb_enums])

        # Remove duplicates (preserve order)
        seen = set()
        deduplicated = []
        for enum in to_run:
            if enum.id not in seen:
                seen.add(enum.id)
                deduplicated.append(enum)
        to_run = deduplicated

        # Check mode for interactive behavior
        is_guided = state.selected_mode == "guided"

        # Run enumerators
        print(f"\n  Running {len(to_run)} enumerators against {target}...")
        if is_guided:
            print(f"  Mode: GUIDED (will prompt before each enumerator)")
        else:
            print(f"  Mode: AUTO (running all enumerators)")
        print(f"  {'─' * 70}")

        results = []
        for enumerator in to_run:
            try:
                print(f"\n  [{enumerator.id.upper()}]")

                # Collect discovered users from previous enumerator results
                # This allows GetNPUsers to test for AS-REP roastable users
                discovered_users = []
                for r in results:
                    if hasattr(r, 'users') and r.users:
                        discovered_users.extend([u["name"] for u in r.users if "name" in u])
                discovered_users = list(set(discovered_users))  # Dedupe

                # Show the command being run
                cmd = None
                if hasattr(enumerator, 'get_command'):
                    if enumerator.id == "getnpusers":
                        cmd = enumerator.get_command(
                            target,
                            domain=state.domain,
                            user_list=discovered_users,
                        )
                    else:
                        cmd = enumerator.get_command(target, domain=state.domain)
                    print(f"  $ {cmd}")

                # In guided mode, prompt before running
                if is_guided:
                    response = input(f"  Run this enumerator? [Y/n/q]: ").strip().strip('\r\n').lower()
                    if response == 'q':
                        print(f"  Stopping enumeration...")
                        break
                    elif response == 'n':
                        print(f"  Skipped.")
                        continue
                    # Empty (Enter) defaults to 'y'

                # Run enumerator with appropriate parameters
                if enumerator.id == "getnpusers":
                    if not discovered_users:
                        print(f"  ⚠ Skipping - no users discovered yet")
                        continue
                    result = enumerator.run(
                        target,
                        domain=state.domain,
                        user_list=discovered_users,
                    )
                else:
                    result = enumerator.run(target, domain=state.domain)
                results.append(result)

                # Show command output (verbose)
                if result.success:
                    print(f"  Status: ✓ Success")
                    if hasattr(result, 'raw_output') and result.raw_output:
                        # Show first 20 lines of output
                        lines = result.raw_output.strip().split('\n')
                        if len(lines) > 20:
                            for line in lines[:20]:
                                print(f"    {line}")
                            print(f"    ... ({len(lines) - 20} more lines)")
                        else:
                            for line in lines:
                                print(f"    {line}")
                else:
                    print(f"  Status: ✗ Failed")
                    if hasattr(result, 'error') and result.error:
                        print(f"  Error: {result.error}")

                # In guided mode, pause after each result
                if is_guided and results:
                    input(f"  Press Enter to continue...")

            except Exception as e:
                print(f"  Status: ✗ Exception: {e}")

        # Aggregate results
        aggregated = aggregate_results(results)

        # Display aggregated findings (with defensive checks for mocks/empty data)
        print(f"\n  {'─' * 70}")
        print(f"  ENUMERATION RESULTS")
        print(f"  {'─' * 70}")

        # Domain info
        if hasattr(aggregated, 'domain') and aggregated.domain and isinstance(aggregated.domain, str):
            print(f"\n  Domain: {aggregated.domain}")
        if hasattr(aggregated, 'dc_hostname') and aggregated.dc_hostname and isinstance(aggregated.dc_hostname, str):
            print(f"  DC Hostname: {aggregated.dc_hostname}")
        if hasattr(aggregated, 'dc_ip') and aggregated.dc_ip and isinstance(aggregated.dc_ip, str):
            print(f"  DC IP: {aggregated.dc_ip}")

        # Users found
        users = getattr(aggregated, 'users', None)
        if users and isinstance(users, dict) and len(users) > 0:
            print(f"\n  Users Found: {len(users)}")
            for username, info in list(users.items())[:15]:
                flags = info.get('flags', []) if isinstance(info, dict) else []
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                print(f"    • {username}{flag_str}")
            if len(users) > 15:
                print(f"    ... and {len(users) - 15} more")

        # Groups found
        groups = getattr(aggregated, 'groups', None)
        if groups and isinstance(groups, dict) and len(groups) > 0:
            print(f"\n  Groups Found: {len(groups)}")
            for groupname in list(groups.keys())[:10]:
                print(f"    • {groupname}")
            if len(groups) > 10:
                print(f"    ... and {len(groups) - 10} more")

        # Shares found
        shares = getattr(aggregated, 'shares', None)
        if shares and isinstance(shares, dict) and len(shares) > 0:
            print(f"\n  Shares Found: {len(shares)}")
            for sharename, info in shares.items():
                access = info.get('access', 'unknown') if isinstance(info, dict) else 'unknown'
                print(f"    • \\\\{target}\\{sharename} ({access})")

        # Password policy
        policy = getattr(aggregated, 'password_policy', None)
        if policy and isinstance(policy, dict) and len(policy) > 0:
            print(f"\n  Password Policy:")
            for key, value in policy.items():
                print(f"    • {key}: {value}")

        # AS-REP Roastable
        asrep = getattr(aggregated, 'asrep_roastable_users', None)
        if asrep and isinstance(asrep, list) and len(asrep) > 0:
            print(f"\n  ⚠ AS-REP Roastable Users: {len(asrep)}")
            for user in asrep:
                if isinstance(user, dict):
                    print(f"    • {user.get('name', 'unknown')} (DONT_REQ_PREAUTH)")

        # Kerberoastable
        svc_accounts = getattr(aggregated, 'service_accounts', None)
        if svc_accounts and isinstance(svc_accounts, list) and len(svc_accounts) > 0:
            print(f"\n  ⚠ Kerberoastable Service Accounts: {len(svc_accounts)}")
            for user in svc_accounts:
                if isinstance(user, dict):
                    spns = user.get('spns', [])
                    spn_str = f" - {spns[0]}" if spns else ""
                    print(f"    • {user.get('name', 'unknown')}{spn_str}")

        print(f"\n  {'─' * 70}")

        # Convert to Finding objects and store in state
        finding_objects = {}

        # AS-REP roastable users
        for user in aggregated.asrep_roastable_users:
            finding = Finding(
                id=f"finding_asrep_{user['name']}",
                finding_type=FindingType.USER_FLAG,
                source="enumeration",
                target=user["name"],
                raw_value="DONT_REQ_PREAUTH",
                tags=["DONT_REQ_PREAUTH"],
                metadata={"username": user["name"]},
            )
            state.findings.append(finding.id)
            finding_objects[finding.id] = finding

        # Service accounts (Kerberoastable)
        for user in aggregated.service_accounts:
            finding = Finding(
                id=f"finding_spn_{user['name']}",
                finding_type=FindingType.USER_FLAG,
                source="enumeration",
                target=user["name"],
                raw_value="HAS_SPN",
                tags=["HAS_SPN"],
                metadata={"username": user["name"]},
            )
            state.findings.append(finding.id)
            finding_objects[finding.id] = finding

        # Password policy
        if aggregated.password_policy:
            finding = Finding(
                id="finding_password_policy",
                finding_type=FindingType.POLICY,
                source="enumeration",
                target=state.domain or state.target,
                raw_value=aggregated.password_policy,
                tags=["policy"],
                metadata=aggregated.password_policy,
            )
            state.findings.append(finding.id)
            finding_objects[finding.id] = finding

        # Store finding objects in context for analyze step
        context["finding_objects"] = finding_objects

        message = f"Discovered {len(state.findings)} findings"
        return StepResult(
            success=True,
            next_step="analyze",
            message=message,
            data={"finding_count": len(state.findings)}
        )


class AnalyzeStep(WizardStep):
    """Analysis step.

    Feeds findings to RecommendationEngine and generates prioritized recommendations.

    Prerequisites:
    - state.findings must not be empty

    Updates:
    - Creates RecommendationEngine
    - Feeds all findings via add_finding()
    - Stores engine in context for RecommendStep
    """

    id = "analyze"
    title = "Analysis"
    description = "Analyze findings and generate recommendations"
    skippable = False  # Critical step

    def can_run(self, state) -> bool:
        """Can run if we have findings to analyze."""
        return len(state.findings) > 0

    def run(self, state, context: Dict) -> StepResult:
        """Create engine, feed findings, generate recommendations.

        Args:
            state: WizardState with findings
            context: Shared context (reads finding_objects, stores engine)

        Returns:
            StepResult with recommendation count
        """
        from ..recommendation.engine import RecommendationEngine

        # Create recommendation engine
        engine = RecommendationEngine(
            target=state.target,
            domain=state.domain or state.detected_domain,
        )

        # Get finding objects from context (set by EnumerateStep)
        finding_objects = context.get("finding_objects", {})

        # Feed findings to engine
        print(f"\n  Processing {len(state.findings)} findings through recommendation engine...")
        print(f"  {'─' * 70}")

        total_recs = 0
        for finding_id in state.findings:
            finding = finding_objects.get(finding_id)
            if finding:
                print(f"\n  Finding: {finding_id}")
                print(f"    Type: {finding.finding_type.name}")
                print(f"    Target: {finding.target}")
                print(f"    Tags: {finding.tags}")

                recs = engine.add_finding(finding)
                if recs:
                    total_recs += len(recs)
                    print(f"    → Triggered {len(recs)} recommendation(s):")
                    for rec in recs:
                        print(f"      • [{rec.priority.name}] {rec.description}")
                else:
                    print(f"    → No recommendations triggered")

        # Get recommendation count
        rec_count = engine.get_pending_count()

        print(f"\n  {'─' * 70}")
        print(f"  Analysis Complete: {rec_count} recommendations queued")

        # Store engine in context for RecommendStep
        context["engine"] = engine

        message = f"Generated {rec_count} prioritized recommendations"
        return StepResult(
            success=True,
            next_step="recommend",
            message=message,
            data={"recommendation_count": rec_count}
        )


class RecommendStep(WizardStep):
    """Recommendation presentation step.

    Presents attack recommendations one at a time in interactive loop.

    Flow:
    1. Get next recommendation from engine
    2. Display using box() formatter
    3. Prompt: [R]un [S]kip [?]Why [Q]uit
    4. Handle user action
    5. Repeat until queue empty or user quits

    Tracks completed/skipped recommendations in engine state.
    """

    id = "recommend"
    title = "Recommendations"
    description = "Present attack recommendations one at a time"
    skippable = True

    def can_run(self, state) -> bool:
        """Can always run (even with empty queue)."""
        return True

    def run(self, state, context: Dict) -> StepResult:
        """Present recommendations one at a time.

        Args:
            state: WizardState
            context: Shared context (reads engine from AnalyzeStep)

        Returns:
            StepResult with success=True, next_step="done"
        """
        from ..interactive.display import box, prompt_user, C, D, G, Y, R, X, W
        from ..recommendation.engine import RecommendationEngine

        # Get engine from context (set by AnalyzeStep)
        engine = context.get("engine")

        # If no engine in context, create fresh one
        if not engine:
            print(f"  {D}No engine in context - creating fresh RecommendationEngine{X}")
            engine = RecommendationEngine(
                target=state.target,
                domain=state.domain,
            )

        # Main recommendation loop
        print(f"\n{C}{'=' * 74}{X}")
        print(f"{C} RECOMMENDATION LOOP{X}")
        print(f"{C}{'=' * 74}{X}\n")
        print(f"{D}Press '?' for help on any recommendation{X}\n")

        while True:
            # Get next recommendation
            rec = engine.get_next_recommendation()

            # No more recommendations - exit loop
            if not rec:
                print(f"\n{D}No more recommendations.{X}")
                break

            # Display recommendation in box
            content_lines = []
            content_lines.append(f"{rec.description}")
            content_lines.append("")

            if rec.command:
                content_lines.append(f"  {D}${X} {G}{rec.command}{X}")
                content_lines.append("")

            if rec.why:
                content_lines.append(f"  {D}Why:{X} {rec.why}")
                content_lines.append("")

            content_lines.append(f"  {D}[{W}R{D}]un  [{W}S{D}]kip  [{W}?{D}]Help  [{W}Q{D}]uit{X}")

            content = '\n'.join(content_lines)

            # Priority colors
            priority_colors = {
                "CRITICAL": R,
                "HIGH": Y,
                "MEDIUM": C,
                "LOW": D,
                "INFO": D,
            }
            color = priority_colors.get(rec.priority.name, C)

            print(box(
                f"RECOMMENDATION ({rec.priority.name})",
                content,
                color=color
            ))

            # Prompt for action
            response = prompt_user(
                f"{D}Action?{X}",
                options="rsq?"
            )

            # Handle user response
            if response == 'q':
                # Quit - exit loop gracefully
                print(f"\n{D}Exiting recommendation loop.{X}")
                break

            elif response == '?':
                # Show extended WHY explanation
                print(f"\n{Y}Why this matters:{X}")
                if rec.why:
                    print(f"  {rec.why}")
                else:
                    print(f"  {D}No additional explanation available.{X}")

                # Also show metadata if available
                if rec.metadata:
                    print(f"\n{D}Context:{X}")
                    for key, value in rec.metadata.items():
                        print(f"  {D}{key}:{X} {value}")

                print()  # Blank line before re-prompt

                # Re-prompt (loop will present same recommendation again)
                continue

            elif response == 's':
                # Skip recommendation
                engine.skip_recommendation(rec.id)
                print(f"{D}Skipped.{X}\n")

            elif response == 'r':
                # Run recommendation and process output for chaining
                success, new_recs = self._execute_command_with_chaining(rec, engine)

                if success:
                    print(f"{G}✓ Complete{X}")
                else:
                    print(f"{Y}⚠ Command completed with errors{X}")

                # Show queued follow-up recommendations
                if new_recs:
                    print(f"\n{C}→ Queued {len(new_recs)} follow-up recommendation(s):{X}")
                    for new_rec in new_recs:
                        print(f"  {D}•{X} {new_rec.description}")
                print()

        # Return success
        return StepResult(
            success=True,
            next_step="done",
            message="Recommendation loop complete",
            data={}
        )

    def _execute_command_with_chaining(self, rec, engine) -> tuple:
        """Execute recommendation command and process output for chaining.

        Args:
            rec: Recommendation object with command
            engine: RecommendationEngine for chaining

        Returns:
            Tuple of (success: bool, new_recommendations: list)
        """
        from ..interactive.display import D, G, R, X
        from .output_parser import OutputParser, ParseResult

        if not rec.command:
            print(f"{R}No command to execute{X}")
            return False, []

        print(f"\n{D}Running:{X} {G}{rec.command}{X}\n")

        try:
            # Run command with subprocess
            result = subprocess.run(
                rec.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Combine output
            output = result.stdout + result.stderr

            # Display output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(f"{R}{result.stderr}{X}")

            # Parse output based on command/attack type
            attack_type = rec.metadata.get("attack_type", "")
            parse_result = OutputParser.parse_output(
                command=rec.command,
                output=output,
                attack_type=attack_type,
            )

            # Determine success
            command_success = result.returncode == 0
            parse_success = parse_result.success

            # Use parse success if we extracted data, otherwise use command return code
            overall_success = parse_success if parse_result.extracted_data else command_success

            # Complete with result to trigger chaining
            new_recs = []
            if overall_success and parse_result.extracted_data:
                # Merge metadata from rec and parsed output
                merged_metadata = {
                    **rec.metadata,
                    **parse_result.extracted_data,
                }

                # Complete with result to trigger on_success chain
                new_recs = engine.complete_recommendation_with_result(
                    rec.id,
                    success=True,
                    metadata=merged_metadata,
                )
            else:
                # Simple completion without chaining
                engine.complete_recommendation(rec.id)

            return overall_success, new_recs

        except subprocess.TimeoutExpired:
            print(f"{R}Command timed out{X}")
            engine.complete_recommendation(rec.id)
            return False, []
        except Exception as e:
            print(f"{R}Error: {e}{X}")
            engine.complete_recommendation(rec.id)
            return False, []
