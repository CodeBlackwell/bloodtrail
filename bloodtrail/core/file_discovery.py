"""
File Discovery Framework

Abstract base for discovering and scoring interesting files across different
sources (SMB shares, local filesystem, WinRM, etc.).

Provides:
- DiscoveredFile: Metadata about found files
- FileDiscoveryBase: ABC for discovery implementations
- Scoring heuristics for prioritizing credential-likely files

Example:
    class SMBCrawler(FileDiscoveryBase):
        def crawl(self, source, max_depth=3):
            # Yield DiscoveredFile for each interesting file
            ...

    crawler = SMBCrawler(host, creds)
    for file in crawler.crawl("users$"):
        if file.interesting_score > 50:
            content = crawler.read_file(file)
            # Parse for credentials...
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set
import fnmatch
import re


@dataclass
class DiscoveredFile:
    """
    Metadata about a discovered file.

    Tracks location, size, and interest score for prioritization.
    Content is loaded lazily via FileDiscoveryBase.read_file().
    """
    path: str                    # Relative path within source
    source: str                  # Full source URL: "smb://host/share" or "/local/path"
    size: int = 0                # File size in bytes
    modified_time: Optional[datetime] = None
    content: Optional[bytes] = None  # Loaded lazily
    interesting_score: int = 0   # 0-100, higher = more likely to contain creds
    score_reasons: List[str] = field(default_factory=list)

    @property
    def full_path(self) -> str:
        """Full path combining source and relative path."""
        if self.source.endswith('/'):
            return f"{self.source}{self.path}"
        return f"{self.source}/{self.path}"

    @property
    def filename(self) -> str:
        """Just the filename without path."""
        return Path(self.path).name

    @property
    def extension(self) -> str:
        """File extension (lowercase, with dot)."""
        return Path(self.path).suffix.lower()

    def __repr__(self) -> str:
        return f"DiscoveredFile({self.path}, score={self.interesting_score})"


class FileDiscoveryBase(ABC):
    """
    Abstract base for file discovery across different sources.

    Implementations provide source-specific logic for:
    - Listing available sources (shares, directories)
    - Crawling sources for files
    - Reading file content
    - Suggesting next steps after discovery

    Scoring is implemented in the base class for consistency.
    """

    # === Configurable patterns (override in subclasses if needed) ===

    # File extensions likely to contain credentials
    INTERESTING_EXTENSIONS: Set[str] = {
        # Config files
        '.xml', '.config', '.conf', '.cfg', '.ini', '.json', '.yaml', '.yml',
        # Scripts (may contain hardcoded creds)
        '.ps1', '.bat', '.cmd', '.vbs', '.sh',
        # Text files
        '.txt', '.log', '.env',
        # Database
        '.sql', '.db', '.sqlite',
        # Certificates/keys
        '.pem', '.key', '.pfx', '.p12', '.crt',
        # Office (macros may contain creds)
        '.xlsm', '.docm',
    }

    # Filenames that are high-value targets
    INTERESTING_NAMES: Set[str] = {
        # Windows deployment
        'unattend.xml', 'sysprep.xml', 'autounattend.xml',
        # GPP
        'groups.xml', 'services.xml', 'scheduledtasks.xml',
        'datasources.xml', 'printers.xml', 'drives.xml',
        # Web configs
        'web.config', 'app.config', 'appsettings.json',
        'connectionstrings.config',
        # Environment
        '.env', '.env.local', '.env.production', '.env.development',
        # Scripts with creds
        'startup.bat', 'login.bat', 'mount.bat',
        # Azure
        'azure.xml', 'azuread.xml',
        # Passwords
        'passwords.txt', 'credentials.txt', 'secrets.txt',
        'password.txt', 'creds.txt', 'logins.txt',
        # Database
        'database.yml', 'db.conf', 'mysql.conf',
        # SSH
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        'authorized_keys', 'known_hosts',
        # VNC
        'ultravnc.ini', '.vnc',
        # Misc
        'shadow', 'passwd', 'htpasswd', '.htpasswd',
        'wp-config.php', 'config.php', 'settings.php',
        # Corporate notices (may contain default passwords)
        'notice.txt', 'readme.txt', 'instructions.txt',
        'welcome.txt', 'getting_started.txt', 'new_employee.txt',
        'onboarding.txt', 'setup.txt', 'install.txt',
    }

    # Directories to prioritize
    INTERESTING_DIRS: Set[str] = {
        'sysvol', 'netlogon', 'scripts', 'policies',
        'backup', 'backups', 'archive',
        'admin', 'administrator', 'root',
        'config', 'configs', 'configuration',
        'credential', 'credentials', 'creds',
        'password', 'passwords',
        'secret', 'secrets',
        'key', 'keys',
        '.ssh', '.gnupg',
        'www', 'wwwroot', 'htdocs', 'public_html',
        # HR/Corporate directories (Cicada pattern - default passwords in notices)
        'hr', 'human_resources', 'humanresources',
        'it', 'helpdesk', 'support',
        'onboarding', 'new_hire', 'newhire',
        'shared', 'public', 'common',
    }

    # Patterns to skip (performance optimization)
    SKIP_PATTERNS: Set[str] = {
        '*.dll', '*.exe', '*.msi', '*.sys', '*.ocx',
        '*.png', '*.jpg', '*.jpeg', '*.gif', '*.bmp', '*.ico',
        '*.mp3', '*.mp4', '*.avi', '*.mkv', '*.wav',
        '*.zip', '*.rar', '*.7z', '*.tar', '*.gz',
        'desktop.ini', 'thumbs.db', '.ds_store',
        'ntuser.dat*', 'usrclass.dat*',
    }

    # Keywords in content that suggest credentials
    CONTENT_KEYWORDS: Set[str] = {
        'password', 'passwd', 'pwd', 'secret', 'credential',
        'apikey', 'api_key', 'token', 'auth',
        'connectionstring', 'connection_string',
        'private_key', 'privatekey',
    }

    # === Abstract methods (implement in subclasses) ===

    @abstractmethod
    def list_sources(self) -> List[str]:
        """
        List available sources to crawl.

        Returns:
            List of source identifiers (share names, directory paths, etc.)
        """
        pass

    @abstractmethod
    def crawl(
        self,
        source: str,
        max_depth: int = 3,
        max_files: int = 1000
    ) -> Iterator[DiscoveredFile]:
        """
        Crawl a source for interesting files.

        Args:
            source: Source identifier from list_sources()
            max_depth: Maximum directory depth to traverse
            max_files: Maximum files to return (prevent runaway)

        Yields:
            DiscoveredFile for each interesting file found
        """
        pass

    @abstractmethod
    def read_file(self, file: DiscoveredFile, max_size: int = 10_000_000) -> bytes:
        """
        Read content of a discovered file.

        Args:
            file: DiscoveredFile to read
            max_size: Maximum bytes to read (default 10MB)

        Returns:
            File content as bytes
        """
        pass

    # === Concrete methods (shared implementation) ===

    def should_skip(self, filename: str) -> bool:
        """Check if file should be skipped based on patterns."""
        filename_lower = filename.lower()
        for pattern in self.SKIP_PATTERNS:
            if fnmatch.fnmatch(filename_lower, pattern.lower()):
                return True
        return False

    def score_file(self, file: DiscoveredFile) -> int:
        """
        Calculate interest score for a file.

        Scoring factors:
        - Extension match: +20
        - Filename match: +40
        - Directory path keywords: +15
        - Small size (likely config): +10
        - Recent modification: +5

        Returns:
            Score 0-100, higher = more interesting
        """
        score = 0
        reasons = []

        filename = file.filename.lower()
        extension = file.extension.lower()
        path_lower = file.path.lower()

        # Extension scoring
        if extension in self.INTERESTING_EXTENSIONS:
            score += 20
            reasons.append(f"extension:{extension}")

        # Exact filename match (highest value)
        if filename in {n.lower() for n in self.INTERESTING_NAMES}:
            score += 40
            reasons.append(f"filename:{filename}")

        # Partial filename match
        for name in self.INTERESTING_NAMES:
            if name.lower() in filename and filename not in {n.lower() for n in self.INTERESTING_NAMES}:
                score += 15
                reasons.append(f"partial:{name}")
                break

        # Directory path keywords
        path_parts = set(path_lower.replace('\\', '/').split('/'))
        for dir_name in self.INTERESTING_DIRS:
            if dir_name.lower() in path_parts:
                score += 15
                reasons.append(f"dir:{dir_name}")
                break

        # Size heuristics (config files are usually small)
        if 0 < file.size < 100_000:  # < 100KB
            score += 10
            reasons.append("small_size")
        elif file.size > 10_000_000:  # > 10MB probably not config
            score -= 10
            reasons.append("large_size")

        # Cap at 100
        score = min(100, max(0, score))

        file.interesting_score = score
        file.score_reasons = reasons
        return score

    def get_discovery_summary(self, files: List[DiscoveredFile]) -> Dict:
        """
        Generate summary of discovered files.

        Returns:
            Dict with counts by extension, top scored files, etc.
        """
        by_extension: Dict[str, int] = {}
        by_score: Dict[str, List[DiscoveredFile]] = {
            'high': [],    # 60+
            'medium': [],  # 30-59
            'low': [],     # 0-29
        }

        for f in files:
            ext = f.extension or 'no_ext'
            by_extension[ext] = by_extension.get(ext, 0) + 1

            if f.interesting_score >= 60:
                by_score['high'].append(f)
            elif f.interesting_score >= 30:
                by_score['medium'].append(f)
            else:
                by_score['low'].append(f)

        return {
            'total_files': len(files),
            'by_extension': by_extension,
            'high_priority': len(by_score['high']),
            'medium_priority': len(by_score['medium']),
            'low_priority': len(by_score['low']),
            'top_files': sorted(files, key=lambda f: -f.interesting_score)[:10],
        }

    def get_next_steps(self, files: List[DiscoveredFile], context: Dict[str, str]) -> List[Dict]:
        """
        Suggest next steps after file discovery.

        Args:
            files: Discovered files
            context: Additional context (target_ip, domain, etc.)

        Returns:
            List of next step recommendations
        """
        from ..parsers.config_parser import NextStep

        steps = []
        high_priority = [f for f in files if f.interesting_score >= 60]

        if high_priority:
            steps.append(NextStep(
                action="Download and parse high-priority files",
                command=f"# {len(high_priority)} high-priority files found",
                explanation="Files with score >= 60 are most likely to contain credentials",
                priority=1,
            ))

        # Check for specific file types
        gpp_files = [f for f in files if 'groups.xml' in f.filename.lower()]
        if gpp_files:
            steps.append(NextStep(
                action="Parse GPP files for cpassword",
                command="gpp-decrypt <cpassword>",
                explanation="GPP passwords use a publicly known AES key (MS14-025)",
                priority=1,
            ))

        unattend = [f for f in files if 'unattend' in f.filename.lower()]
        if unattend:
            steps.append(NextStep(
                action="Check Unattend.xml for deployment credentials",
                command="# Look for <Password><Value> elements",
                explanation="Windows deployment files often contain admin passwords",
                priority=1,
            ))

        return steps


class LocalFileDiscovery(FileDiscoveryBase):
    """
    File discovery for local filesystem.

    Useful for testing and parsing already-downloaded files.
    """

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)

    def list_sources(self) -> List[str]:
        """Return the base path as the only source."""
        return [str(self.base_path)]

    def crawl(
        self,
        source: str,
        max_depth: int = 3,
        max_files: int = 1000
    ) -> Iterator[DiscoveredFile]:
        """Crawl local directory for interesting files."""
        source_path = Path(source)
        file_count = 0

        def _crawl_dir(dir_path: Path, depth: int):
            nonlocal file_count
            if depth > max_depth or file_count >= max_files:
                return

            try:
                for entry in dir_path.iterdir():
                    if file_count >= max_files:
                        break

                    if entry.is_file():
                        if self.should_skip(entry.name):
                            continue

                        rel_path = str(entry.relative_to(source_path))
                        stat = entry.stat()

                        discovered = DiscoveredFile(
                            path=rel_path,
                            source=str(source_path),
                            size=stat.st_size,
                            modified_time=datetime.fromtimestamp(stat.st_mtime),
                        )

                        self.score_file(discovered)

                        if discovered.interesting_score > 0:
                            file_count += 1
                            yield discovered

                    elif entry.is_dir() and not entry.name.startswith('.'):
                        yield from _crawl_dir(entry, depth + 1)

            except PermissionError:
                pass

        yield from _crawl_dir(source_path, 0)

    def read_file(self, file: DiscoveredFile, max_size: int = 10_000_000) -> bytes:
        """Read local file content."""
        full_path = Path(file.source) / file.path
        content = full_path.read_bytes()
        if len(content) > max_size:
            content = content[:max_size]
        file.content = content
        return content
