"""
AD Recycle Bin / Deleted Objects Parser

Parses ldapsearch output for deleted objects that may contain legacy passwords.

Common attack scenario (Cascade):
1. User is member of "AD Recycle Bin" group
2. Query deleted objects from CN=Deleted Objects,DC=domain,DC=local
3. Find cascadeLegacyPwd attribute on deleted user
4. Decode (base64) and test as credential

Usage:
    parser = DeletedObjectsParser()
    result = parser.parse_ldif("/path/to/deleted_objects.ldif")

    for obj in result.objects:
        if obj.legacy_password:
            print(f"{obj.samaccountname}: {obj.legacy_password}")
"""

import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class ObjectType(Enum):
    """Type of deleted AD object."""
    USER = "user"
    COMPUTER = "computer"
    GROUP = "group"
    CONTAINER = "container"
    UNKNOWN = "unknown"


@dataclass
class DeletedObject:
    """A deleted AD object from the Recycle Bin."""
    dn: str
    original_dn: Optional[str] = None  # DN before deletion
    samaccountname: Optional[str] = None
    object_type: ObjectType = ObjectType.UNKNOWN
    display_name: Optional[str] = None
    description: Optional[str] = None

    # Legacy password attributes
    legacy_password: Optional[str] = None  # Decoded if possible
    legacy_password_raw: Optional[str] = None  # Raw attribute value
    legacy_password_attr: Optional[str] = None  # Attribute name

    # Other potentially useful attributes
    upn: Optional[str] = None  # userPrincipalName
    member_of: List[str] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)

    # Metadata
    deleted_when: Optional[str] = None
    last_known_parent: Optional[str] = None

    @property
    def name(self) -> str:
        """Best available name for display."""
        return self.samaccountname or self.display_name or self.dn.split(',')[0]


@dataclass
class DeletedObjectsResult:
    """Results from parsing deleted objects."""
    source: str
    success: bool
    total_objects: int = 0
    users: List[DeletedObject] = field(default_factory=list)
    computers: List[DeletedObject] = field(default_factory=list)
    groups: List[DeletedObject] = field(default_factory=list)
    objects_with_passwords: List[DeletedObject] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def found_passwords(self) -> bool:
        return len(self.objects_with_passwords) > 0


# Legacy password attribute names to search for
LEGACY_PWD_ATTRS = [
    'cascadelegacypwd',
    'legacypwd',
    'legacypassword',
    'oldpassword',
    'previouspassword',
    'userpassword',
    'unicodepwd',
    'unixuserpassword',
    'sambalmpassword',
    'sambantpassword',
    'mssfu30password',
]


class DeletedObjectsParser:
    """
    Parse ldapsearch LDIF output for deleted AD objects.

    Specifically looks for:
    - Deleted user accounts
    - Legacy password attributes (cascadeLegacyPwd, etc.)
    - Original location before deletion
    """

    def __init__(self):
        self.legacy_attrs = set(attr.lower() for attr in LEGACY_PWD_ATTRS)

    def parse_ldif(self, file_path: str) -> DeletedObjectsResult:
        """
        Parse LDIF file from ldapsearch output.

        Args:
            file_path: Path to LDIF file

        Returns:
            DeletedObjectsResult with parsed objects
        """
        result = DeletedObjectsResult(source=file_path, success=False)

        path = Path(file_path)
        if not path.exists():
            result.errors.append(f"File not found: {file_path}")
            return result

        try:
            content = path.read_text(errors='ignore')
            objects = self._parse_ldif_content(content)

            for obj in objects:
                result.total_objects += 1

                # Categorize by type
                if obj.object_type == ObjectType.USER:
                    result.users.append(obj)
                elif obj.object_type == ObjectType.COMPUTER:
                    result.computers.append(obj)
                elif obj.object_type == ObjectType.GROUP:
                    result.groups.append(obj)

                # Track objects with passwords
                if obj.legacy_password or obj.legacy_password_raw:
                    result.objects_with_passwords.append(obj)

            result.success = True

        except Exception as e:
            result.errors.append(f"Parse error: {e}")

        return result

    def parse_text(self, content: str) -> DeletedObjectsResult:
        """
        Parse LDIF content directly from string.

        Args:
            content: LDIF formatted text

        Returns:
            DeletedObjectsResult with parsed objects
        """
        result = DeletedObjectsResult(source="<text>", success=False)

        try:
            objects = self._parse_ldif_content(content)

            for obj in objects:
                result.total_objects += 1

                if obj.object_type == ObjectType.USER:
                    result.users.append(obj)
                elif obj.object_type == ObjectType.COMPUTER:
                    result.computers.append(obj)
                elif obj.object_type == ObjectType.GROUP:
                    result.groups.append(obj)

                if obj.legacy_password or obj.legacy_password_raw:
                    result.objects_with_passwords.append(obj)

            result.success = True

        except Exception as e:
            result.errors.append(f"Parse error: {e}")

        return result

    def _parse_ldif_content(self, content: str) -> List[DeletedObject]:
        """Parse LDIF content into DeletedObject list."""
        objects = []

        # Split into entries (separated by blank lines)
        entries = re.split(r'\n\s*\n', content)

        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue

            obj = self._parse_entry(entry)
            if obj:
                objects.append(obj)

        return objects

    def _parse_entry(self, entry: str) -> Optional[DeletedObject]:
        """Parse a single LDIF entry."""
        lines = entry.split('\n')
        attributes: Dict[str, List[str]] = {}

        current_attr = None
        current_value = None

        for line in lines:
            line = line.rstrip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Continuation line (starts with space)
            if line.startswith(' ') and current_attr:
                current_value += line[1:]
                continue

            # Save previous attribute if any
            if current_attr and current_value:
                if current_attr not in attributes:
                    attributes[current_attr] = []
                attributes[current_attr].append(current_value)

            # Parse new attribute
            if ':' in line:
                # Handle base64 encoded values (attr:: value)
                if '::' in line:
                    parts = line.split('::', 1)
                    if len(parts) == 2:
                        current_attr = parts[0].strip().lower()
                        encoded_value = parts[1].strip()
                        try:
                            import base64
                            current_value = base64.b64decode(encoded_value).decode('utf-8', errors='ignore')
                        except:
                            current_value = encoded_value
                else:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        current_attr = parts[0].strip().lower()
                        current_value = parts[1].strip()
            else:
                current_attr = None
                current_value = None

        # Don't forget last attribute
        if current_attr and current_value:
            if current_attr not in attributes:
                attributes[current_attr] = []
            attributes[current_attr].append(current_value)

        # Skip if no DN
        if 'dn' not in attributes:
            return None

        # Create object
        obj = DeletedObject(dn=attributes['dn'][0])

        # Extract common attributes
        obj.samaccountname = self._get_first(attributes, 'samaccountname')
        obj.display_name = self._get_first(attributes, 'displayname')
        obj.description = self._get_first(attributes, 'description')
        obj.upn = self._get_first(attributes, 'userprincipalname')
        obj.last_known_parent = self._get_first(attributes, 'lastknownparent')
        obj.deleted_when = self._get_first(attributes, 'whencreated')  # or whenchanged

        # Determine object type
        objectclass = [v.lower() for v in attributes.get('objectclass', [])]
        if 'user' in objectclass or 'person' in objectclass:
            obj.object_type = ObjectType.USER
        elif 'computer' in objectclass:
            obj.object_type = ObjectType.COMPUTER
        elif 'group' in objectclass:
            obj.object_type = ObjectType.GROUP
        elif 'container' in objectclass or 'organizationalunit' in objectclass:
            obj.object_type = ObjectType.CONTAINER

        # Extract group memberships
        obj.member_of = attributes.get('memberof', [])

        # Look for legacy password attributes
        for attr_name in self.legacy_attrs:
            if attr_name in attributes:
                raw_value = attributes[attr_name][0]
                obj.legacy_password_raw = raw_value
                obj.legacy_password_attr = attr_name

                # Try to decode
                obj.legacy_password = self._decode_password(raw_value)
                break

        # Also check for any password-like attributes we might have missed
        for attr_name, values in attributes.items():
            if any(pwd in attr_name for pwd in ['pwd', 'pass', 'secret']):
                if attr_name not in self.legacy_attrs:
                    # Store as additional attribute
                    obj.attributes[attr_name] = values[0]

        return obj

    def _get_first(self, attrs: Dict[str, List[str]], key: str) -> Optional[str]:
        """Get first value for attribute, or None."""
        values = attrs.get(key, [])
        return values[0] if values else None

    def _decode_password(self, value: str) -> Optional[str]:
        """Try to decode a password value."""
        if not value:
            return None

        # Try base64
        try:
            import base64
            decoded = base64.b64decode(value)

            # Try UTF-8
            try:
                text = decoded.decode('utf-8')
                if all(32 <= ord(c) < 127 or c in '\t\n\r' for c in text):
                    return text
            except:
                pass

            # Try UTF-16LE (common for Windows)
            try:
                text = decoded.decode('utf-16-le')
                if all(32 <= ord(c) < 127 or c in '\t\n\r' for c in text):
                    return text
            except:
                pass

            # Return hex if binary
            return decoded.hex()

        except:
            pass

        # Maybe it's already plaintext?
        if all(32 <= ord(c) < 127 for c in value):
            return value

        return None


def format_deleted_objects_result(result: DeletedObjectsResult, verbose: bool = True) -> str:
    """Format deleted objects result for terminal display."""
    C = "\033[96m"
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    B = "\033[1m"
    D = "\033[2m"
    X = "\033[0m"

    lines = []
    lines.append(f"\n{C}{B}{'=' * 74}{X}")
    lines.append(f"{C}{B}  AD RECYCLE BIN PARSER{X}")
    lines.append(f"{C}{B}{'=' * 74}{X}\n")

    if not result.success:
        lines.append(f"  {R}Parse failed:{X}")
        for err in result.errors:
            lines.append(f"    {err}")
        return '\n'.join(lines)

    # Summary
    lines.append(f"  {D}Source:{X}         {result.source}")
    lines.append(f"  {D}Total objects:{X}  {result.total_objects}")
    lines.append(f"  {D}Users:{X}          {len(result.users)}")
    lines.append(f"  {D}Computers:{X}      {len(result.computers)}")
    lines.append(f"  {D}Groups:{X}         {len(result.groups)}")
    lines.append(f"  {D}With passwords:{X} {len(result.objects_with_passwords)}")
    lines.append("")

    # Objects with passwords (most important)
    if result.objects_with_passwords:
        lines.append(f"  {R}{B}LEGACY PASSWORDS FOUND{X}")
        lines.append(f"  {D}{'─' * 60}{X}")

        for obj in result.objects_with_passwords:
            lines.append(f"    {B}{obj.name}{X} ({obj.object_type.value})")
            lines.append(f"      {D}Attribute:{X} {obj.legacy_password_attr}")

            if obj.legacy_password:
                lines.append(f"      {G}Decoded:{X}   {B}{obj.legacy_password}{X}")
            else:
                lines.append(f"      {Y}Raw:{X}       {obj.legacy_password_raw[:50]}...")

            if obj.upn:
                lines.append(f"      {D}UPN:{X}       {obj.upn}")
            lines.append("")

    # Deleted users (for context)
    if verbose and result.users and len(result.users) <= 20:
        lines.append(f"  {D}DELETED USERS ({len(result.users)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for user in result.users[:10]:
            pwd_indicator = f" {G}[PWD]{X}" if user in result.objects_with_passwords else ""
            lines.append(f"    {user.samaccountname or user.dn[:50]}{pwd_indicator}")
        if len(result.users) > 10:
            lines.append(f"    {D}... and {len(result.users) - 10} more{X}")
        lines.append("")

    return '\n'.join(lines)
