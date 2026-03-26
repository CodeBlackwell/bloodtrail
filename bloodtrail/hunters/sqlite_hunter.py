"""
SQLite Credential Hunter - Extract credentials from SQLite databases.

Commonly found in:
- Application databases (Audit.db, app.db)
- Browser profiles
- Configuration stores
- Custom management tools

Patterns it looks for:
- Tables: users, accounts, credentials, passwords, auth, logins
- Columns: username, password, pwd, pass, secret, hash, key
"""

import sqlite3
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum


class PasswordType(Enum):
    """Classification of password/secret storage."""
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    HEX = "hex"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_BCRYPT = "hash_bcrypt"
    HASH_NTLM = "hash_ntlm"
    ENCRYPTED_AES = "encrypted_aes"
    ENCRYPTED_UNKNOWN = "encrypted_unknown"
    UNKNOWN = "unknown"


@dataclass
class ExtractedCredential:
    """A credential extracted from a SQLite database."""
    username: str
    secret: str  # Password, hash, or encrypted blob
    secret_type: PasswordType
    table_name: str
    additional_fields: Dict[str, Any] = field(default_factory=dict)

    # For encrypted secrets
    encryption_hint: Optional[str] = None  # e.g., "AES-CBC", "DES"
    iv: Optional[str] = None  # If IV is stored separately

    def __repr__(self):
        secret_preview = self.secret[:20] + "..." if len(self.secret) > 20 else self.secret
        return f"ExtractedCredential({self.username}, {self.secret_type.value}, {secret_preview})"


@dataclass
class SqliteHuntResult:
    """Results from hunting a SQLite database."""
    db_path: str
    success: bool
    tables_found: List[str] = field(default_factory=list)
    credential_tables: List[str] = field(default_factory=list)
    credentials: List[ExtractedCredential] = field(default_factory=list)
    interesting_tables: Dict[str, List[str]] = field(default_factory=dict)  # table -> columns
    errors: List[str] = field(default_factory=list)
    raw_schema: Optional[str] = None

    @property
    def found_credentials(self) -> bool:
        return len(self.credentials) > 0

    @property
    def has_encrypted(self) -> bool:
        return any(
            c.secret_type in (PasswordType.ENCRYPTED_AES, PasswordType.ENCRYPTED_UNKNOWN)
            for c in self.credentials
        )


class SqliteHunter:
    """
    Hunt for credentials in SQLite databases.

    Usage:
        hunter = SqliteHunter()
        result = hunter.hunt("/path/to/Audit.db")

        for cred in result.credentials:
            print(f"{cred.username}: {cred.secret_type.value}")
    """

    # Tables likely to contain credentials
    CREDENTIAL_TABLE_PATTERNS = [
        "user", "users", "account", "accounts",
        "credential", "credentials", "cred", "creds",
        "login", "logins", "auth", "authentication",
        "password", "passwords", "pwd", "secret", "secrets",
        "admin", "admins", "ldap", "deletedobject",
    ]

    # Columns likely to contain usernames
    USERNAME_COLUMN_PATTERNS = [
        "username", "user", "name", "login", "loginname",
        "email", "mail", "account", "accountname",
        "samaccountname", "upn", "principal", "uid",
        "distinguishedname", "dn",
    ]

    # Columns likely to contain secrets
    SECRET_COLUMN_PATTERNS = [
        "password", "pwd", "pass", "passwd", "secret",
        "hash", "pwdhash", "passwordhash", "ntlm", "nthash",
        "key", "token", "credential", "cred", "encrypted",
        "cipher", "aes", "blob",
    ]

    def __init__(self):
        pass

    def hunt(self, db_path: str) -> SqliteHuntResult:
        """
        Hunt for credentials in a SQLite database.

        Args:
            db_path: Path to the SQLite database file

        Returns:
            SqliteHuntResult with extracted credentials and metadata
        """
        result = SqliteHuntResult(db_path=db_path, success=False)

        path = Path(db_path)
        if not path.exists():
            result.errors.append(f"Database file not found: {db_path}")
            return result

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            result.tables_found = [row[0] for row in cursor.fetchall()]

            # Get full schema
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
            schemas = [row[0] for row in cursor.fetchall() if row[0]]
            result.raw_schema = "\n\n".join(schemas)

            # Find credential-like tables
            for table in result.tables_found:
                if self._is_credential_table(table):
                    result.credential_tables.append(table)

                    # Get columns for this table
                    columns = self._get_table_columns(cursor, table)
                    result.interesting_tables[table] = columns

                    # Extract credentials
                    creds = self._extract_from_table(cursor, table, columns)
                    result.credentials.extend(creds)

            # Also check non-credential tables for interesting columns
            # (skip tables already processed as credential tables)
            for table in result.tables_found:
                if table not in result.credential_tables:
                    columns = self._get_table_columns(cursor, table)
                    if self._has_interesting_columns(columns):
                        result.interesting_tables[table] = columns
                        creds = self._extract_from_table(cursor, table, columns)
                        result.credentials.extend(creds)

            conn.close()
            result.success = True

        except sqlite3.Error as e:
            result.errors.append(f"SQLite error: {e}")
        except Exception as e:
            result.errors.append(f"Error: {e}")

        return result

    def _is_credential_table(self, table_name: str) -> bool:
        """Check if table name suggests it contains credentials."""
        table_lower = table_name.lower()
        return any(pattern in table_lower for pattern in self.CREDENTIAL_TABLE_PATTERNS)

    def _get_table_columns(self, cursor, table: str) -> List[str]:
        """Get column names for a table."""
        cursor.execute(f"PRAGMA table_info({table})")
        return [row[1] for row in cursor.fetchall()]

    def _has_interesting_columns(self, columns: List[str]) -> bool:
        """Check if columns suggest credentials are stored."""
        columns_lower = [c.lower() for c in columns]

        has_user = any(
            any(p in c for p in self.USERNAME_COLUMN_PATTERNS)
            for c in columns_lower
        )
        has_secret = any(
            any(p in c for p in self.SECRET_COLUMN_PATTERNS)
            for c in columns_lower
        )

        return has_user and has_secret

    def _extract_from_table(
        self,
        cursor,
        table: str,
        columns: List[str]
    ) -> List[ExtractedCredential]:
        """Extract credentials from a table."""
        credentials = []

        # Find username and secret columns
        user_col = self._find_column(columns, self.USERNAME_COLUMN_PATTERNS)
        secret_col = self._find_column(columns, self.SECRET_COLUMN_PATTERNS)

        if not user_col or not secret_col:
            return credentials

        # Get all rows
        try:
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()

            user_idx = columns.index(user_col)
            secret_idx = columns.index(secret_col)

            for row in rows:
                if row[user_idx] is None or row[secret_idx] is None:
                    continue

                username = str(row[user_idx])
                secret_raw = row[secret_idx]

                # Handle blob vs string
                if isinstance(secret_raw, bytes):
                    secret = secret_raw.hex()
                    secret_type = self._classify_secret(secret_raw)
                else:
                    secret = str(secret_raw)
                    secret_type = self._classify_secret(secret)

                # Gather additional fields
                additional = {}
                for i, col in enumerate(columns):
                    if i not in (user_idx, secret_idx) and row[i] is not None:
                        val = row[i]
                        if isinstance(val, bytes):
                            additional[col] = val.hex()
                        else:
                            additional[col] = val

                cred = ExtractedCredential(
                    username=username,
                    secret=secret,
                    secret_type=secret_type,
                    table_name=table,
                    additional_fields=additional,
                )

                # Check for IV column (common in encrypted stores)
                iv_col = self._find_column(columns, ["iv", "nonce", "salt"])
                if iv_col and iv_col in additional:
                    cred.iv = additional[iv_col]
                    if secret_type == PasswordType.ENCRYPTED_UNKNOWN:
                        cred.secret_type = PasswordType.ENCRYPTED_AES
                        cred.encryption_hint = "AES-CBC (IV present)"

                credentials.append(cred)

        except sqlite3.Error as e:
            pass  # Table may have issues

        return credentials

    def _find_column(self, columns: List[str], patterns: List[str]) -> Optional[str]:
        """Find a column matching any of the patterns."""
        for col in columns:
            col_lower = col.lower()
            for pattern in patterns:
                if pattern in col_lower:
                    return col
        return None

    def _classify_secret(self, secret) -> PasswordType:
        """Classify what type of secret this appears to be."""
        if isinstance(secret, bytes):
            # Binary data - likely encrypted or raw hash
            length = len(secret)

            # Check for common encrypted block sizes
            if length == 16:
                return PasswordType.ENCRYPTED_AES  # Single AES block
            elif length == 32:
                return PasswordType.ENCRYPTED_AES  # Two AES blocks
            elif length % 16 == 0 and length > 0:
                return PasswordType.ENCRYPTED_AES  # Multiple AES blocks
            elif length == 8:
                return PasswordType.ENCRYPTED_UNKNOWN  # Possibly DES
            else:
                return PasswordType.ENCRYPTED_UNKNOWN

        # String data
        secret_str = str(secret)

        # Check for common hash formats
        if len(secret_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in secret_str):
            # Could be MD5 or NTLM
            return PasswordType.HASH_MD5  # or NTLM - same length

        if len(secret_str) == 40 and all(c in '0123456789abcdefABCDEF' for c in secret_str):
            return PasswordType.HASH_SHA1

        if len(secret_str) == 64 and all(c in '0123456789abcdefABCDEF' for c in secret_str):
            return PasswordType.HASH_SHA256

        if secret_str.startswith('$2') and len(secret_str) >= 59:
            return PasswordType.HASH_BCRYPT

        # Check for base64 (must have base64 characters, proper padding, and decode to something meaningful)
        # Avoid false positives on plaintext passwords like "plaintext123"
        if len(secret_str) >= 8 and len(secret_str) % 4 == 0:
            import base64
            # Base64 alphabet check (strict - requires at least some uppercase)
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            has_uppercase = any(c.isupper() for c in secret_str.rstrip('='))
            has_mixed = has_uppercase and any(c.islower() for c in secret_str)

            if all(c in base64_chars for c in secret_str) and (has_mixed or secret_str.endswith('=')):
                try:
                    decoded = base64.b64decode(secret_str)
                    if len(decoded) > 0:
                        # Check if decoded is printable text
                        try:
                            decoded_text = decoded.decode('utf-8')
                            if all(32 <= ord(c) < 127 or c in '\t\n\r' for c in decoded_text):
                                return PasswordType.BASE64
                        except UnicodeDecodeError:
                            # Binary data - check for encryption indicators
                            # 16 or 32 bytes = AES block size (likely encrypted)
                            if len(decoded) == 16 or len(decoded) == 32:
                                return PasswordType.ENCRYPTED_AES
                            # Other multiple of 8 with padding = likely encrypted
                            if len(decoded) % 8 == 0 and secret_str.endswith('='):
                                return PasswordType.ENCRYPTED_UNKNOWN
                            # Non-block-aligned binary with padding could still be encoded
                            if secret_str.endswith('='):
                                return PasswordType.BASE64
                except:
                    pass

        # Check for hex string
        if all(c in '0123456789abcdefABCDEF' for c in secret_str) and len(secret_str) > 16:
            return PasswordType.HEX

        # Likely plaintext if it contains normal characters
        if any(c.isalpha() for c in secret_str):
            return PasswordType.PLAINTEXT

        return PasswordType.UNKNOWN

    def get_decryption_hints(self, result: SqliteHuntResult) -> List[str]:
        """
        Generate hints for decrypting encrypted credentials.

        Based on common patterns like Cascade's Audit.db.
        """
        hints = []

        for cred in result.credentials:
            if cred.secret_type == PasswordType.ENCRYPTED_AES:
                hints.append(
                    f"AES-encrypted credential for '{cred.username}' in {cred.table_name}. "
                    f"Look for .NET assemblies, config files, or registry for decryption key."
                )
                if cred.iv:
                    hints.append(f"  IV found: {cred.iv[:32]}...")
                    hints.append("  Likely AES-CBC mode. Search for 'AesManaged' or 'RijndaelManaged' in .NET code.")

        return hints


def format_hunt_result(result: SqliteHuntResult, verbose: bool = True) -> str:
    """Format hunt results for terminal display."""
    # Colors
    C = "\033[96m"
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    B = "\033[1m"
    D = "\033[2m"
    X = "\033[0m"

    lines = []
    lines.append(f"\n{C}{B}{'=' * 74}{X}")
    lines.append(f"{C}{B}  SQLITE CREDENTIAL HUNT: {result.db_path}{X}")
    lines.append(f"{C}{B}{'=' * 74}{X}\n")

    if not result.success:
        lines.append(f"  {R}Hunt failed:{X}")
        for err in result.errors:
            lines.append(f"    {err}")
        return '\n'.join(lines)

    # Summary
    lines.append(f"  {D}Tables found:{X}      {len(result.tables_found)}")
    lines.append(f"  {D}Credential tables:{X} {len(result.credential_tables)}")
    lines.append(f"  {D}Credentials:{X}       {len(result.credentials)}")
    lines.append("")

    # Tables
    if result.credential_tables:
        lines.append(f"  {Y}{B}CREDENTIAL TABLES{X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for table in result.credential_tables:
            cols = result.interesting_tables.get(table, [])
            lines.append(f"    {B}{table}{X}: {D}{', '.join(cols)}{X}")
        lines.append("")

    # Credentials
    if result.credentials:
        lines.append(f"  {R}{B}EXTRACTED CREDENTIALS ({len(result.credentials)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")

        for cred in result.credentials:
            type_color = R if "encrypted" in cred.secret_type.value else G

            lines.append(f"    {B}{cred.username}{X}")
            lines.append(f"      {D}Table:{X} {cred.table_name}")
            lines.append(f"      {D}Type:{X}  {type_color}{cred.secret_type.value}{X}")

            # Show secret (truncated)
            secret_display = cred.secret[:50]
            if len(cred.secret) > 50:
                secret_display += "..."
            lines.append(f"      {D}Value:{X} {secret_display}")

            if cred.iv:
                lines.append(f"      {D}IV:{X}    {cred.iv[:32]}...")

            if cred.encryption_hint:
                lines.append(f"      {Y}Hint:{X}  {cred.encryption_hint}")

            lines.append("")

    # Decryption hints
    if result.has_encrypted:
        hunter = SqliteHunter()
        hints = hunter.get_decryption_hints(result)
        if hints:
            lines.append(f"  {Y}{B}DECRYPTION HINTS{X}")
            lines.append(f"  {D}{'─' * 60}{X}")
            for hint in hints:
                lines.append(f"    {hint}")
            lines.append("")

    # Schema dump if verbose
    if verbose and result.raw_schema:
        lines.append(f"  {D}RAW SCHEMA{X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for line in result.raw_schema.split('\n'):
            lines.append(f"    {D}{line}{X}")

    return '\n'.join(lines)
