"""
.NET Secrets Hunter - Extract secrets from .NET assemblies.

Patterns searched for:
- Hardcoded strings (base64, hex, passwords)
- Encryption key assignments (AesManaged, RijndaelManaged)
- Connection strings
- API keys and tokens

For full decompilation, use:
- dnSpy (Windows): https://github.com/dnSpy/dnSpy
- ILSpy (Cross-platform): https://github.com/icsharpcode/ILSpy
- dotPeek (Windows): JetBrains dotPeek
"""

import re
import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum


class SecretType(Enum):
    """Type of secret found in assembly."""
    AES_KEY = "aes_key"
    AES_IV = "aes_iv"
    DES_KEY = "des_key"
    PASSWORD = "password"
    CONNECTION_STRING = "connection_string"
    API_KEY = "api_key"
    BASE64_BLOB = "base64_blob"
    HEX_BLOB = "hex_blob"
    CREDENTIAL = "credential"
    UNKNOWN = "unknown"


@dataclass
class ExtractedSecret:
    """A secret extracted from a .NET assembly."""
    secret_type: SecretType
    value: str
    context: str  # Surrounding text/code context
    confidence: float  # 0.0 - 1.0
    offset: int  # Byte offset in file
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self):
        preview = self.value[:30] + "..." if len(self.value) > 30 else self.value
        return f"ExtractedSecret({self.secret_type.value}, {preview}, conf={self.confidence:.2f})"


@dataclass
class DotNetHuntResult:
    """Results from hunting a .NET assembly."""
    file_path: str
    success: bool
    is_dotnet: bool = False
    assembly_name: Optional[str] = None
    runtime_version: Optional[str] = None
    secrets: List[ExtractedSecret] = field(default_factory=list)
    encryption_patterns: List[str] = field(default_factory=list)
    strings_of_interest: List[str] = field(default_factory=list)
    decompile_hints: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def found_secrets(self) -> bool:
        return len(self.secrets) > 0

    @property
    def has_encryption(self) -> bool:
        return len(self.encryption_patterns) > 0


# .NET PE magic bytes
DOS_MAGIC = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'

# Patterns for encryption-related strings
ENCRYPTION_PATTERNS = [
    # AES
    (r'AesManaged', 'AES encryption (System.Security.Cryptography.AesManaged)'),
    (r'RijndaelManaged', 'Rijndael/AES encryption (System.Security.Cryptography.RijndaelManaged)'),
    (r'Aes\.Create', 'AES factory method'),
    (r'AesCryptoServiceProvider', 'AES CSP'),
    (r'CipherMode\.CBC', 'CBC mode encryption'),
    (r'CipherMode\.ECB', 'ECB mode encryption (weak!)'),
    (r'PaddingMode\.', 'Encryption padding mode'),

    # DES
    (r'DESCryptoServiceProvider', 'DES encryption (weak!)'),
    (r'TripleDESCryptoServiceProvider', '3DES encryption'),

    # Key derivation
    (r'Rfc2898DeriveBytes', 'PBKDF2 key derivation'),
    (r'PasswordDeriveBytes', 'Password-based key derivation'),

    # Encoding
    (r'Convert\.FromBase64String', 'Base64 decode'),
    (r'Convert\.ToBase64String', 'Base64 encode'),
    (r'Encoding\.(UTF8|ASCII|Unicode)', 'String encoding'),

    # Hashing
    (r'SHA256Managed', 'SHA256 hashing'),
    (r'MD5CryptoServiceProvider', 'MD5 hashing'),
]

# Patterns for secrets in strings
SECRET_STRING_PATTERNS = [
    # Base64-encoded data (24+ chars, ends with = padding)
    (r'[A-Za-z0-9+/]{24,}={0,2}', SecretType.BASE64_BLOB),

    # Hex strings (32+ chars)
    (r'[0-9a-fA-F]{32,}', SecretType.HEX_BLOB),

    # Connection strings
    (r'(Data Source|Server)=[^;]+;', SecretType.CONNECTION_STRING),
    (r'(User ID|uid)=[^;]+;', SecretType.CONNECTION_STRING),
    (r'(Password|pwd)=[^;]+;', SecretType.CONNECTION_STRING),

    # Common password variable patterns
    (r'password\s*[:=]\s*["\']?[\w@#$%^&*]+', SecretType.PASSWORD),
    (r'secret\s*[:=]\s*["\']?[\w@#$%^&*]+', SecretType.PASSWORD),

    # API keys
    (r'api[_-]?key\s*[:=]\s*["\']?[\w-]+', SecretType.API_KEY),
    (r'apikey\s*[:=]\s*["\']?[\w-]+', SecretType.API_KEY),
]


class DotNetHunter:
    """
    Hunt for secrets in .NET assemblies.

    This hunter performs string extraction and pattern matching.
    For full decompilation, use dnSpy, ILSpy, or dotPeek.

    Usage:
        hunter = DotNetHunter()
        result = hunter.hunt("/path/to/CascAudit.exe")

        if result.has_encryption:
            print("Encryption detected!")
            for pattern in result.encryption_patterns:
                print(f"  {pattern}")
    """

    def __init__(self, min_string_length: int = 8):
        """
        Initialize hunter.

        Args:
            min_string_length: Minimum length for extracted strings
        """
        self.min_string_length = min_string_length

    def hunt(self, file_path: str) -> DotNetHuntResult:
        """
        Hunt for secrets in a .NET assembly.

        Args:
            file_path: Path to .NET executable or DLL

        Returns:
            DotNetHuntResult with extracted secrets and patterns
        """
        result = DotNetHuntResult(file_path=file_path, success=False)

        path = Path(file_path)
        if not path.exists():
            result.errors.append(f"File not found: {file_path}")
            return result

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Check if it's a .NET assembly
            if not self._is_dotnet_assembly(data):
                result.errors.append("Not a .NET assembly (no CLI header)")
                return result

            result.is_dotnet = True

            # Extract assembly info
            result.assembly_name = self._extract_assembly_name(data)
            result.runtime_version = self._extract_runtime_version(data)

            # Extract strings
            strings = self._extract_strings(data)
            result.strings_of_interest = self._filter_interesting_strings(strings)

            # Find encryption patterns
            result.encryption_patterns = self._find_encryption_patterns(data, strings)

            # Extract potential secrets
            result.secrets = self._extract_secrets(strings, data)

            # Generate decompile hints
            result.decompile_hints = self._generate_decompile_hints(result)

            result.success = True

        except Exception as e:
            result.errors.append(f"Error: {e}")

        return result

    def _is_dotnet_assembly(self, data: bytes) -> bool:
        """Check if file is a .NET assembly."""
        if len(data) < 64:
            return False

        # Check DOS header
        if data[:2] != DOS_MAGIC:
            return False

        # Get PE offset
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_offset + 4 > len(data):
            return False

        # Check PE signature
        if data[pe_offset:pe_offset+4] != PE_SIGNATURE:
            return False

        # Check for CLI header (indicates .NET)
        # This is a simplified check - proper parsing would need full PE parsing
        if b'.text\x00' in data and (b'mscoree.dll' in data.lower() or b'_CorExeMain' in data):
            return True

        return b'mscorlib' in data.lower() or b'.NET' in data

    def _extract_assembly_name(self, data: bytes) -> Optional[str]:
        """Extract assembly name from metadata."""
        # Look for assembly name in string table
        patterns = [
            rb'(?:,\s*Version=)',  # After assembly name in fully qualified name
            rb'Assembly:\s*([^\x00]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, data)
            if match:
                # Get string before the pattern
                start = max(0, match.start() - 100)
                context = data[start:match.start()]
                # Find last null or non-printable before
                for i in range(len(context) - 1, -1, -1):
                    if context[i] < 32 or context[i] > 126:
                        name = context[i+1:].decode('utf-8', errors='ignore').strip()
                        if name and len(name) < 100:
                            return name

        return None

    def _extract_runtime_version(self, data: bytes) -> Optional[str]:
        """Extract .NET runtime version."""
        # Look for version string
        match = re.search(rb'v\d+\.\d+(?:\.\d+)?', data)
        if match:
            return match.group().decode('utf-8', errors='ignore')
        return None

    def _extract_strings(self, data: bytes) -> List[Tuple[str, int]]:
        """
        Extract printable strings from binary.

        Returns:
            List of (string, offset) tuples
        """
        strings = []

        # Extract ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{' + str(self.min_string_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, data):
            s = match.group().decode('ascii', errors='ignore')
            strings.append((s, match.start()))

        # Extract Unicode strings (UTF-16LE, common in .NET)
        i = 0
        while i < len(data) - 1:
            if data[i] >= 0x20 and data[i] <= 0x7e and data[i+1] == 0:
                start = i
                chars = []
                while i < len(data) - 1:
                    if data[i] >= 0x20 and data[i] <= 0x7e and data[i+1] == 0:
                        chars.append(chr(data[i]))
                        i += 2
                    else:
                        break
                if len(chars) >= self.min_string_length:
                    strings.append((''.join(chars), start))
            else:
                i += 1

        return strings

    def _filter_interesting_strings(self, strings: List[Tuple[str, int]]) -> List[str]:
        """Filter strings for interesting ones."""
        interesting = []

        keywords = [
            'password', 'secret', 'key', 'crypt', 'aes', 'des',
            'iv', 'salt', 'token', 'api', 'auth', 'credential',
            'connect', 'database', 'server', 'user',
        ]

        for s, _ in strings:
            s_lower = s.lower()
            if any(kw in s_lower for kw in keywords):
                if len(s) < 500:  # Avoid huge strings
                    interesting.append(s)

        return interesting[:100]  # Limit to top 100

    def _find_encryption_patterns(
        self,
        data: bytes,
        strings: List[Tuple[str, int]],
    ) -> List[str]:
        """Find encryption-related patterns in assembly."""
        found = []

        # Check in binary data
        data_str = data.decode('utf-8', errors='ignore')

        for pattern, description in ENCRYPTION_PATTERNS:
            if re.search(pattern, data_str, re.IGNORECASE):
                found.append(description)

        # Check in extracted strings
        for s, _ in strings:
            for pattern, description in ENCRYPTION_PATTERNS:
                if re.search(pattern, s, re.IGNORECASE):
                    if description not in found:
                        found.append(description)

        return found

    def _extract_secrets(
        self,
        strings: List[Tuple[str, int]],
        data: bytes,
    ) -> List[ExtractedSecret]:
        """Extract potential secrets from strings."""
        secrets = []

        for s, offset in strings:
            for pattern, secret_type in SECRET_STRING_PATTERNS:
                matches = re.finditer(pattern, s, re.IGNORECASE)
                for match in matches:
                    value = match.group()

                    # Calculate confidence based on context
                    confidence = self._calculate_confidence(s, value, secret_type)

                    if confidence > 0.3:  # Minimum threshold
                        secret = ExtractedSecret(
                            secret_type=secret_type,
                            value=value,
                            context=s[:100],
                            confidence=confidence,
                            offset=offset,
                        )
                        secrets.append(secret)

        # Deduplicate
        seen = set()
        unique_secrets = []
        for s in secrets:
            key = (s.secret_type, s.value)
            if key not in seen:
                seen.add(key)
                unique_secrets.append(s)

        # Sort by confidence
        unique_secrets.sort(key=lambda x: -x.confidence)

        return unique_secrets[:50]  # Top 50 secrets

    def _calculate_confidence(
        self,
        context: str,
        value: str,
        secret_type: SecretType,
    ) -> float:
        """Calculate confidence score for a potential secret."""
        confidence = 0.5  # Base confidence

        context_lower = context.lower()

        # Boost based on context keywords
        if 'password' in context_lower:
            confidence += 0.2
        if 'key' in context_lower:
            confidence += 0.2
        if 'secret' in context_lower:
            confidence += 0.2
        if 'encrypt' in context_lower or 'decrypt' in context_lower:
            confidence += 0.3
        if 'aes' in context_lower or 'rijndael' in context_lower:
            confidence += 0.3

        # Boost based on value characteristics
        if secret_type == SecretType.BASE64_BLOB:
            # Prefer lengths that are AES key sizes
            try:
                import base64
                decoded_len = len(base64.b64decode(value + '=='))
                if decoded_len in (16, 24, 32):  # AES key sizes
                    confidence += 0.3
            except:
                pass

        if secret_type == SecretType.HEX_BLOB:
            # Prefer lengths that are key sizes
            if len(value) in (32, 48, 64):  # 16, 24, 32 bytes in hex
                confidence += 0.3

        # Penalize if looks like a path or common string
        if '/' in value or '\\' in value:
            confidence -= 0.3
        if value.startswith('http'):
            confidence -= 0.2

        return min(1.0, max(0.0, confidence))

    def _generate_decompile_hints(self, result: DotNetHuntResult) -> List[str]:
        """Generate hints for manual decompilation."""
        hints = []

        if result.has_encryption:
            hints.append(
                "Encryption detected. Use dnSpy/ILSpy to search for encryption class usage."
            )

            if 'AES encryption' in str(result.encryption_patterns) or 'Rijndael' in str(result.encryption_patterns):
                hints.append(
                    "Look for: CreateEncryptor(), CreateDecryptor(), Key property assignments"
                )
                hints.append(
                    "Search pattern in dnSpy: 'new AesManaged' or 'new RijndaelManaged'"
                )

            if 'PBKDF2' in str(result.encryption_patterns):
                hints.append(
                    "PBKDF2 found. Look for salt and iteration count in Rfc2898DeriveBytes constructor."
                )

        if result.secrets:
            for secret in result.secrets[:3]:
                if secret.secret_type == SecretType.BASE64_BLOB and secret.confidence > 0.6:
                    hints.append(
                        f"Potential key at offset 0x{secret.offset:X}: {secret.value[:30]}..."
                    )

        if not hints:
            hints.append(
                "No obvious patterns found. Manual review with dnSpy recommended."
            )

        return hints


def format_hunt_result(result: DotNetHuntResult, verbose: bool = True) -> str:
    """Format hunt results for terminal display."""
    C = "\033[96m"
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    B = "\033[1m"
    D = "\033[2m"
    X = "\033[0m"

    lines = []
    lines.append(f"\n{C}{B}{'=' * 74}{X}")
    lines.append(f"{C}{B}  .NET ASSEMBLY HUNT: {result.file_path}{X}")
    lines.append(f"{C}{B}{'=' * 74}{X}\n")

    if not result.success:
        lines.append(f"  {R}Hunt failed:{X}")
        for err in result.errors:
            lines.append(f"    {err}")
        return '\n'.join(lines)

    # Assembly info
    if result.assembly_name:
        lines.append(f"  {D}Assembly:{X}    {result.assembly_name}")
    if result.runtime_version:
        lines.append(f"  {D}Runtime:{X}     {result.runtime_version}")
    lines.append(f"  {D}Secrets:{X}     {len(result.secrets)}")
    lines.append(f"  {D}Encryption:{X}  {'Yes' if result.has_encryption else 'No'}")
    lines.append("")

    # Encryption patterns
    if result.encryption_patterns:
        lines.append(f"  {Y}{B}ENCRYPTION PATTERNS{X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for pattern in result.encryption_patterns:
            lines.append(f"    {Y}!{X} {pattern}")
        lines.append("")

    # Secrets
    if result.secrets:
        lines.append(f"  {R}{B}EXTRACTED SECRETS ({len(result.secrets)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for secret in result.secrets[:10]:
            conf_color = G if secret.confidence > 0.7 else Y if secret.confidence > 0.5 else D
            value_display = secret.value[:50]
            if len(secret.value) > 50:
                value_display += "..."
            lines.append(f"    {B}[{secret.secret_type.value}]{X} {conf_color}({secret.confidence:.0%}){X}")
            lines.append(f"      {value_display}")
            if verbose:
                lines.append(f"      {D}Context: {secret.context[:60]}...{X}")
        lines.append("")

    # Decompile hints
    if result.decompile_hints:
        lines.append(f"  {G}{B}DECOMPILATION HINTS{X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for hint in result.decompile_hints:
            lines.append(f"    {hint}")
        lines.append("")

    # Interesting strings if verbose
    if verbose and result.strings_of_interest:
        lines.append(f"  {D}STRINGS OF INTEREST ({len(result.strings_of_interest)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for s in result.strings_of_interest[:10]:
            lines.append(f"    {D}{s[:70]}{X}")
        if len(result.strings_of_interest) > 10:
            lines.append(f"    {D}... and {len(result.strings_of_interest) - 10} more{X}")

    return '\n'.join(lines)
