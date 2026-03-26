"""
BloodTrail CLI Analyze Commands

Commands for analyzing enumeration data:
- --detect: Run attack vector detection (Azure AD Connect, GPP, LAPS)
- --analyze-svc: Analyze service accounts for attack prioritization
- --analyze-reuse: Track password reuse patterns
- --crawl-smb: Crawl SMB shares for sensitive files
"""

from argparse import Namespace
from typing import Optional

from ..base import BaseCommandGroup
from ...core.formatters import Colors
from ...core.detection import (
    get_default_registry as get_detector_registry,
    DetectionResult,
)
from ...core.service_accounts import ServiceAccountAnalyzer
from ...core.password_reuse import PasswordReuseTracker
from ...core.models import DiscoveredCredential, SourceType, Confidence


class AnalyzeCommands(BaseCommandGroup):
    """
    Attack vector detection and analysis commands.

    These commands help identify attack opportunities and prioritize targets.
    """

    @classmethod
    def add_arguments(cls, parser) -> None:
        group = parser.add_argument_group("Analysis Commands")

        group.add_argument(
            "--detect",
            action="store_true",
            help="Detect attack vectors (Azure AD Connect, GPP, LAPS)",
        )

        group.add_argument(
            "--analyze-svc",
            action="store_true",
            help="Analyze service accounts for attack prioritization",
        )

        group.add_argument(
            "--analyze-reuse",
            metavar="CREDS_FILE",
            help="Analyze password reuse from credentials file",
        )

        group.add_argument(
            "--crawl-smb",
            metavar="HOST",
            help="Crawl SMB shares for sensitive files (requires -u/-p)",
        )

        group.add_argument(
            "--share",
            metavar="NAME",
            help="Specific share to crawl (with --crawl-smb)",
        )

        group.add_argument(
            "--hunt-sqlite",
            metavar="DB_FILE",
            help="Hunt SQLite database for credentials",
        )

        group.add_argument(
            "--chains",
            metavar="USER",
            help="Detect attack chains for owned user (e.g., svc-alfresco)",
        )

    @classmethod
    def handle(cls, args: Namespace) -> int:
        if args.detect:
            return cls._handle_detect(args)
        elif args.analyze_svc:
            return cls._handle_analyze_svc(args)
        elif args.analyze_reuse:
            return cls._handle_analyze_reuse(args)
        elif args.crawl_smb:
            return cls._handle_crawl_smb(args)
        elif args.hunt_sqlite:
            return cls._handle_hunt_sqlite(args)
        elif getattr(args, 'hunt_dotnet', None):
            return cls._handle_hunt_dotnet(args)
        elif getattr(args, 'parse_deleted', None):
            return cls._handle_parse_deleted(args)
        elif getattr(args, 'chains', None):
            return cls._handle_chains(args)
        return -1  # Not handled

    @classmethod
    def _handle_detect(cls, args: Namespace) -> int:
        """Run attack vector detection against BloodHound data."""
        conn = cls.require_neo4j(args)
        if not conn:
            return 1

        cls.print_header("ATTACK VECTOR DETECTION")

        registry = get_detector_registry()
        context = {
            "target_ip": getattr(args, 'dc_ip', '<DC_IP>'),
            "domain": getattr(args, 'domain', '<DOMAIN>'),
        }

        # Get users and groups from BloodHound
        users = []
        groups = []

        try:
            with conn.driver.session() as session:
                # Query Domain Controllers first to enrich context
                dc_result = session.run("""
                    MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
                    WHERE g.name STARTS WITH 'DOMAIN CONTROLLERS@'
                    RETURN c.name AS name LIMIT 1
                """)
                dc_record = dc_result.single()
                if dc_record and dc_record["name"]:
                    dc_hostname = dc_record["name"].split("@")[0]  # Remove domain suffix
                    context["dc_hostname"] = dc_hostname
                    # Also set target_ip to DC hostname if not already set
                    if context["target_ip"] == '<DC_IP>':
                        context["target_ip"] = dc_hostname

                # Query users
                result = session.run("MATCH (u:User) RETURN u.name AS name, u.description AS description LIMIT 500")
                users = [dict(r) for r in result]

                # Query groups
                result = session.run("""
                    MATCH (g:Group)
                    OPTIONAL MATCH (u:User)-[:MemberOf*1..]->(g)
                    RETURN g.name AS name, collect(DISTINCT u.name)[..10] AS members
                    LIMIT 200
                """)
                groups = [dict(r) for r in result]

        except Exception as e:
            cls.print_error(f"Failed to query BloodHound: {e}")
            conn.close()
            return 1

        # Run detectors
        results = registry.detect_all_ldap(users, groups, [], context)

        if not results:
            cls.print_warning("No attack vectors detected")
            print("\nNote: Detection works best with LDAP enumeration data imported to BloodHound.")
            conn.close()
            return 0

        # Display results
        for detection in results:
            cls._display_detection(detection)

        conn.close()
        return 0

    @classmethod
    def _display_detection(cls, detection: DetectionResult) -> None:
        """Display a single detection result with attack commands."""
        confidence_colors = {
            "confirmed": Colors.GREEN,
            "likely": Colors.YELLOW,
            "possible": Colors.CYAN,
        }
        color = confidence_colors.get(detection.confidence.value, "")

        print(f"\n{Colors.BOLD}{color}[{detection.confidence.value.upper()}] {detection.name}{Colors.RESET}")
        print(f"  Indicator: {detection.indicator}")

        print(f"\n  {Colors.BOLD}Evidence:{Colors.RESET}")
        for evidence in detection.evidence:
            print(f"    - {evidence}")

        if detection.attack_commands:
            print(f"\n  {Colors.BOLD}Attack Commands:{Colors.RESET}")
            for i, cmd in enumerate(detection.attack_commands[:5], 1):
                print(f"\n    [{i}] {cmd.description}")
                print(f"        {Colors.CYAN}$ {cmd.command}{Colors.RESET}")
                if cmd.explanation:
                    print(f"        {Colors.DIM}Why: {cmd.explanation}{Colors.RESET}")

        if detection.next_steps:
            print(f"\n  {Colors.BOLD}Next Steps:{Colors.RESET}")
            for step in detection.next_steps:
                print(f"    - {step}")

        if detection.references:
            print(f"\n  {Colors.BOLD}References:{Colors.RESET}")
            for ref in detection.references[:3]:
                print(f"    - {ref}")

    @classmethod
    def _handle_analyze_svc(cls, args: Namespace) -> int:
        """Analyze service accounts from BloodHound data."""
        conn = cls.require_neo4j(args)
        if not conn:
            return 1

        cls.print_header("SERVICE ACCOUNT ANALYSIS")

        context = {
            "target_ip": getattr(args, 'dc_ip', '<DC_IP>'),
            "domain": getattr(args, 'domain', '<DOMAIN>'),
        }

        analyzer = ServiceAccountAnalyzer()

        try:
            with conn.driver.session() as session:
                result = analyzer.analyze_from_bloodhound(session, context)
        except Exception as e:
            cls.print_error(f"Analysis failed: {e}")
            conn.close()
            return 1

        if not result.all_accounts:
            cls.print_warning("No service accounts identified")
            conn.close()
            return 0

        # Display report
        print(analyzer.get_report(result))

        # Display spray wordlist
        domain = context.get('domain', '')
        wordlist = analyzer.get_spray_wordlist(domain)
        print(f"\n{Colors.BOLD}Suggested Spray Wordlist:{Colors.RESET}")
        for pwd in wordlist[:10]:
            print(f"  {pwd}")
        print(f"  ... ({len(wordlist)} total)")

        conn.close()
        return 0

    @classmethod
    def _handle_analyze_reuse(cls, args: Namespace) -> int:
        """Analyze password reuse from credentials file."""
        creds_file = args.analyze_reuse

        cls.print_header("PASSWORD REUSE ANALYSIS")

        # Read credentials file
        try:
            with open(creds_file, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            cls.print_error(f"Failed to read {creds_file}: {e}")
            return 1

        tracker = PasswordReuseTracker()

        # Parse credentials (format: user:password or domain/user:password)
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            user_part, password = parts

            # Parse domain if present
            domain = None
            if '/' in user_part:
                domain, username = user_part.split('/', 1)
            elif '\\' in user_part:
                domain, username = user_part.split('\\', 1)
            else:
                username = user_part

            cred = DiscoveredCredential(
                username=username,
                secret=password,
                domain=domain,
                source=creds_file,
                source_type=SourceType.MANUAL,
                confidence=Confidence.CONFIRMED,
            )
            tracker.add_credential(cred)

        # Display report
        print(tracker.get_reuse_report())

        # Spray suggestions
        context = {
            "target_ip": getattr(args, 'dc_ip', '<DC_IP>'),
            "domain": getattr(args, 'domain', '<DOMAIN>'),
        }

        suggestions = tracker.get_spray_suggestions([], context)
        if suggestions:
            print(f"\n{Colors.BOLD}Spray Suggestions:{Colors.RESET}")
            for s in suggestions[:5]:
                print(f"\n  [{s.priority}] {s.action}")
                print(f"      {Colors.CYAN}$ {s.command}{Colors.RESET}")
                print(f"      {Colors.DIM}Why: {s.explanation}{Colors.RESET}")

        return 0

    @classmethod
    def _handle_crawl_smb(cls, args: Namespace) -> int:
        """Crawl SMB shares for sensitive files with recommendation engine."""
        try:
            from ...enumerators.smb_crawler import (
                SMBCrawler,
                generate_retrieval_command,
            )
            from ...recommendation import (
                process_smb_crawl,
                display_smb_summary,
            )
        except ImportError as e:
            cls.print_error(f"SMB crawler requires impacket: {e}")
            print("Install with: pip install impacket")
            return 1

        host = args.crawl_smb
        username = getattr(args, 'ad_username', None)
        password = getattr(args, 'ad_password', None)
        domain = getattr(args, 'domain', None) or ''  # Handle None from argparse

        if not username or not password:
            cls.print_error("SMB crawling requires credentials (-u/-p)")
            return 1

        cls.print_header(f"SMB SHARE CRAWL: {host}")

        try:
            crawler = SMBCrawler(
                host=host,
                username=username,
                password=password,
                domain=domain,
            )

            with crawler:
                # List shares
                shares = crawler.list_shares_detailed()
                print(f"\n{Colors.BOLD}Accessible Shares:{Colors.RESET}")
                readable_count = 0
                for share in shares:
                    if share.readable:
                        readable_count += 1
                        print(f"  {Colors.GREEN}✓{Colors.RESET} {share.name}")
                        if share.remark:
                            print(f"    {Colors.DIM}{share.remark}{Colors.RESET}")
                    else:
                        print(f"  {Colors.RED}✗{Colors.RESET} {share.name} {Colors.DIM}(access denied){Colors.RESET}")

                if readable_count == 0:
                    print(f"\n{Colors.YELLOW}No readable shares found.{Colors.RESET}")
                    return 0

                # Filter to specific share if requested
                target_shares = [args.share] if args.share else None

                # Crawl and extract
                print(f"\n{Colors.BOLD}Crawling for sensitive files...{Colors.RESET}")
                crawl_result = crawler.crawl_and_extract(shares=target_shares)

                # Process through recommendation engine
                summary = process_smb_crawl(
                    crawl_result=crawl_result,
                    target=host,
                    domain=domain,
                )

                # Display enhanced summary with recommendations
                print(display_smb_summary(summary))

                # Show file retrieval commands for high-priority files
                high_priority = [f for f in crawl_result.files
                                if f.interesting_score >= 50]
                if high_priority:
                    print(f"\n{Colors.BOLD}FILE RETRIEVAL COMMANDS{Colors.RESET}")
                    print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
                    for f in sorted(high_priority, key=lambda x: -x.interesting_score)[:5]:
                        cmd = generate_retrieval_command(
                            file=f,
                            host=host,
                            username=username,
                            password=password,
                            domain=domain,
                        )
                        print(f"  {Colors.DIM}# {f.path}{Colors.RESET}")
                        print(f"  {Colors.CYAN}$ {cmd}{Colors.RESET}")
                        print()

                # Show raw credentials if any were extracted
                if crawl_result.credentials:
                    print(f"\n{Colors.BOLD}EXTRACTED CREDENTIALS{Colors.RESET}")
                    print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
                    for cred in crawl_result.credentials:
                        print(f"  {Colors.GREEN}{cred.upn}{Colors.RESET}")
                        print(f"    Source: {cred.source}")
                        print(f"    Confidence: {cred.confidence.value}")
                    print()

        except Exception as e:
            cls.print_error(f"SMB crawl failed: {e}")
            import traceback
            traceback.print_exc()
            return 1

        return 0

    @classmethod
    def _handle_hunt_sqlite(cls, args: Namespace) -> int:
        """Hunt SQLite database for credentials."""
        from ...recommendation import (
            process_sqlite_hunt,
            display_sqlite_summary,
        )
        from pathlib import Path

        db_path = args.hunt_sqlite
        target = getattr(args, 'dc_ip', None) or getattr(args, 'target', '<TARGET>')
        domain = getattr(args, 'domain', None)

        # Verify file exists
        if not Path(db_path).exists():
            cls.print_error(f"Database file not found: {db_path}")
            return 1

        cls.print_header(f"SQLITE CREDENTIAL HUNT: {db_path}")

        try:
            summary = process_sqlite_hunt(db_path, target, domain)
            print(display_sqlite_summary(summary))

            # If encrypted credentials found, provide guidance
            if summary.encrypted_creds > 0:
                print(f"\n{Colors.YELLOW}{Colors.BOLD}ENCRYPTED CREDENTIALS DETECTED{Colors.RESET}")
                print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
                print("  To decrypt these credentials:")
                print("  1. Look for .exe/.dll files in the same directory or share")
                print("  2. Decompile .NET assemblies with dnSpy or ILSpy")
                print("  3. Search for 'AesManaged', 'RijndaelManaged', or encryption keys")
                print("  4. Check for IV/nonce values in the database or config files")
                print()

            # Show next steps based on findings
            if summary.recommendations:
                print(f"\n{Colors.BOLD}RECOMMENDED ACTIONS{Colors.RESET}")
                print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
                for i, rec in enumerate(summary.recommendations[:5], 1):
                    priority_color = (
                        Colors.RED if rec.priority.value <= 1
                        else Colors.YELLOW if rec.priority.value <= 2
                        else Colors.CYAN
                    )
                    print(f"\n  {priority_color}[{rec.priority.name}]{Colors.RESET} {rec.description}")
                    print(f"  {Colors.DIM}Why: {rec.why}{Colors.RESET}")
                    if rec.command:
                        print(f"  {Colors.CYAN}$ {rec.command}{Colors.RESET}")

        except Exception as e:
            cls.print_error(f"SQLite hunt failed: {e}")
            import traceback
            traceback.print_exc()
            return 1

        return 0

    @classmethod
    def _handle_hunt_dotnet(cls, args: Namespace) -> int:
        """Hunt .NET assembly for secrets."""
        from ...hunters import DotNetHunter, format_dotnet_result
        from pathlib import Path

        file_path = args.hunt_dotnet

        # Verify file exists
        if not Path(file_path).exists():
            cls.print_error(f"File not found: {file_path}")
            return 1

        cls.print_header(f".NET ASSEMBLY HUNT: {file_path}")

        try:
            hunter = DotNetHunter()
            result = hunter.hunt(file_path)
            print(format_dotnet_result(result))

            if not result.is_dotnet:
                print(f"\n{Colors.YELLOW}Not a .NET assembly. Try with a .exe or .dll file.{Colors.RESET}")
                return 1

            # If encryption detected, show decryption workflow
            if result.has_encryption:
                print(f"\n{Colors.YELLOW}{Colors.BOLD}NEXT STEPS{Colors.RESET}")
                print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
                print("  1. Download assembly to Windows machine with dnSpy")
                print("  2. Open in dnSpy: File → Open → select the .exe/.dll")
                print("  3. Search (Ctrl+Shift+K) for encryption patterns:")
                for pattern in result.encryption_patterns[:3]:
                    print(f"     - {pattern}")
                print("  4. Find Key and IV assignments near CreateEncryptor()")
                print("  5. Use extracted key to decrypt credentials")
                print()

                # Show example decryption command if we have secrets
                if result.secrets:
                    for secret in result.secrets[:1]:
                        if secret.secret_type.value in ('base64_blob', 'aes_key'):
                            print(f"  {Colors.CYAN}Potential key found: {secret.value[:40]}...{Colors.RESET}")
                print()

        except Exception as e:
            cls.print_error(f".NET hunt failed: {e}")
            import traceback
            traceback.print_exc()
            return 1

        return 0

    @classmethod
    def _handle_parse_deleted(cls, args: Namespace) -> int:
        """Parse AD Recycle Bin output for legacy passwords."""
        from ...hunters import DeletedObjectsParser, format_deleted_objects_result
        from pathlib import Path

        file_path = args.parse_deleted
        target = getattr(args, 'target', None) or getattr(args, 'dc_ip', '<TARGET>')
        domain = getattr(args, 'domain', None)

        # Verify file exists
        if not Path(file_path).exists():
            cls.print_error(f"File not found: {file_path}")
            return 1

        cls.print_header(f"AD RECYCLE BIN PARSER")

        try:
            parser = DeletedObjectsParser()
            result = parser.parse_ldif(file_path)
            print(format_deleted_objects_result(result))

            # If legacy passwords found, show test commands
            if result.found_passwords:
                print(f"\n{Colors.BOLD}TEST THESE CREDENTIALS{Colors.RESET}")
                print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")

                for obj in result.objects_with_passwords:
                    if obj.legacy_password and obj.samaccountname:
                        domain_flag = f"-d {domain}" if domain else ""
                        cmd = f"crackmapexec smb {target} -u {obj.samaccountname} -p '{obj.legacy_password}' {domain_flag}".strip()
                        print(f"\n  {Colors.CYAN}$ {cmd}{Colors.RESET}")
                        print(f"  {Colors.DIM}(Password from {obj.legacy_password_attr}){Colors.RESET}")

                print()

        except Exception as e:
            cls.print_error(f"Parse failed: {e}")
            import traceback
            traceback.print_exc()
            return 1

        return 0

    @classmethod
    def _handle_chains(cls, args: Namespace) -> int:
        """Detect and display attack chains from BloodHound data.

        This command:
        1. Runs BloodHound queries to detect attack paths
        2. Identifies viable attack chains (e.g., Exchange WriteDACL → DCSync)
        3. Generates step-by-step recommendations with commands

        Example usage:
            bloodtrail --chains svc-alfresco -d htb.local
        """
        from ...recommendation import (
            BloodHoundAnalyzer,
            AttackState,
            ChainDetector,
            ATTACK_CHAINS,
        )

        conn = cls.require_neo4j(args)
        if not conn:
            return 1

        username = args.chains
        domain = getattr(args, 'domain', None)
        target = getattr(args, 'dc_ip', None) or getattr(args, 'target', None)
        password = getattr(args, 'ad_password', None)

        if not domain:
            cls.print_error("Domain required: use -d/--domain")
            conn.close()
            return 1

        cls.print_header(f"ATTACK CHAIN DETECTION: {username}@{domain}")

        # Step 1: Run BloodHound analysis to get findings
        print(f"\n{Colors.BOLD}[1] Analyzing BloodHound data...{Colors.RESET}")
        analyzer = BloodHoundAnalyzer(verbose=True)
        findings = analyzer.analyze_attack_paths(username, domain)

        if not findings:
            cls.print_warning("No attack paths found for this user")
            print("\nPossible reasons:")
            print("  - User not found in BloodHound data")
            print("  - No exploitable group memberships")
            print("  - BloodHound data may be incomplete")
            conn.close()
            return 0

        # Step 2: Create attack state and add findings
        print(f"\n{Colors.BOLD}[2] Detected {len(findings)} finding(s):{Colors.RESET}")
        state = AttackState(target=target or "<DC_IP>", domain=domain)

        for finding in findings:
            state.add_finding(finding)
            tags_str = ", ".join(finding.tags[:3])
            print(f"  {Colors.GREEN}✓{Colors.RESET} {finding.decoded_value or finding.target}")
            print(f"    {Colors.DIM}Tags: {tags_str}{Colors.RESET}")

        # Step 3: Detect viable attack chains
        print(f"\n{Colors.BOLD}[3] Checking attack chains...{Colors.RESET}")
        detector = ChainDetector(state)
        viable_chains = detector.detect_viable_chains()

        if not viable_chains:
            print(f"\n{Colors.YELLOW}No complete attack chains detected.{Colors.RESET}")
            print("\nIndividual findings above may still be useful.")
            print("Try running with --detect for other attack vectors.")
            conn.close()
            return 0

        # Step 4: Display viable chains with recommendations
        print(f"\n{Colors.GREEN}{Colors.BOLD}Found {len(viable_chains)} viable attack chain(s)!{Colors.RESET}")

        # Build context for command generation
        context = {
            "target": target or "<DC_IP>",
            "domain": domain,
            "username": username,
            "password": password or "<PASSWORD>",
            "new_user": "bloodtrail",
            "new_pass": "B1oodTr@il123!",
            "admin_hash": "<ADMIN_HASH>",
        }

        for chain in viable_chains:
            cls._display_chain(chain, detector, context)

        conn.close()
        return 0

    @classmethod
    def _display_chain(cls, chain, detector, context) -> None:
        """Display a single attack chain with step-by-step commands."""
        print(f"\n{'═' * 70}")
        print(f"{Colors.BOLD}{Colors.RED}[{chain.priority.name}] {chain.name}{Colors.RESET}")
        print(f"{'═' * 70}")
        print(f"\n{chain.description}")
        print(f"\n{Colors.CYAN}OSCP Relevance:{Colors.RESET} {chain.oscp_relevance}")

        # Show requirements
        reqs = detector.get_chain_requirements(chain)
        print(f"\n{Colors.BOLD}Prerequisites:{Colors.RESET}")
        for tag in reqs['present']:
            print(f"  {Colors.GREEN}✓{Colors.RESET} {tag}")

        # Generate recommendations
        recommendations = detector.generate_chain_recommendations(chain, context)

        print(f"\n{Colors.BOLD}Attack Steps ({len(chain.steps)} total):{Colors.RESET}")
        print(f"{'─' * 70}")

        for i, rec in enumerate(recommendations, 1):
            step = chain.steps[i - 1]
            platform_icon = "🖥️ " if step.platform == "target" else "🐧"

            print(f"\n{Colors.BOLD}Step {i}: {step.name}{Colors.RESET} {platform_icon}")
            print(f"{Colors.DIM}Platform: {step.platform.upper()}{Colors.RESET}")
            print(f"\n  {Colors.YELLOW}WHY:{Colors.RESET}")
            for line in step.why.split('\n'):
                print(f"  {line}")

            print(f"\n  {Colors.CYAN}COMMAND:{Colors.RESET}")
            # Format command for display (handle multi-line)
            cmd_lines = rec.command.split('\n') if rec.command else []
            for line in cmd_lines:
                if line.strip():
                    print(f"  {Colors.GREEN}${Colors.RESET} {line}")

            # Show missing variables if any
            if rec.metadata.get('missing_vars'):
                missing = rec.metadata['missing_vars']
                print(f"\n  {Colors.YELLOW}Note: Replace placeholders: {', '.join(missing)}{Colors.RESET}")

            if step.on_success_note:
                print(f"\n  {Colors.GREEN}On success:{Colors.RESET} {step.on_success_note}")

            if step.metadata.get('requires_upload'):
                print(f"  {Colors.YELLOW}Requires upload:{Colors.RESET} {step.metadata['requires_upload']}")

        print(f"\n{'─' * 70}")
        print(f"{Colors.BOLD}Copy-Paste Quick Reference:{Colors.RESET}")
        print(f"{'─' * 70}")

        # Show condensed commands for quick copy-paste
        for i, rec in enumerate(recommendations, 1):
            step = chain.steps[i - 1]
            print(f"\n# Step {i}: {step.name} [{step.platform}]")
            for line in (rec.command or "").split('\n'):
                if line.strip() and not line.strip().startswith('#'):
                    print(line)
