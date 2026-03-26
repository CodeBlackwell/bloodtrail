"""
Convert enumeration results to Findings for the recommendation engine.

Bridges between the raw enumeration output and the typed Finding objects
that the recommendation engine expects.
"""

from typing import List, Dict, Any, Optional

from .models import Finding, FindingType


def findings_from_enumeration(
    aggregated,
    source: str = "enumeration",
) -> List[Finding]:
    """
    Convert aggregated enumeration results to Finding objects.

    Extracts findings for:
    - Users with dangerous flags (ASREP, PWNOTREQ, etc.)
    - Users with SPNs (kerberoastable)
    - Users with password-in-description
    - Custom LDAP attributes
    - Group memberships

    Args:
        aggregated: AggregatedResult from enumerators/aggregator
        source: Source identifier for the findings

    Returns:
        List of Finding objects
    """
    findings = []

    # Process users
    for username, user_data in aggregated.users.items():
        findings.extend(_findings_from_user(user_data, source))

    # Process custom attributes (if present)
    if hasattr(aggregated, 'custom_attributes'):
        for attr_data in aggregated.custom_attributes:
            finding = _finding_from_custom_attribute(attr_data, source)
            if finding:
                findings.append(finding)

    return findings


def _findings_from_user(
    user_data: Dict[str, Any],
    source: str,
) -> List[Finding]:
    """Extract findings from a user record."""
    findings = []
    username = user_data.get('name', 'unknown')

    # AS-REP Roastable
    if user_data.get('asrep'):
        finding = Finding(
            id=f"asrep_{username}",
            finding_type=FindingType.USER_FLAG,
            source=source,
            target=username,
            raw_value="DONT_REQ_PREAUTH",
            tags=["DONT_REQ_PREAUTH"],
            metadata={
                "username": username,
                "flag": "DONT_REQ_PREAUTH",
                "asrep_hash": user_data.get('asrep_hash'),
            },
        )
        findings.append(finding)

    # Password not required
    if user_data.get('pwnotreq'):
        finding = Finding(
            id=f"pwnotreq_{username}",
            finding_type=FindingType.USER_FLAG,
            source=source,
            target=username,
            raw_value="PASSWD_NOTREQD",
            tags=["PASSWD_NOTREQD"],
            metadata={
                "username": username,
                "flag": "PASSWD_NOTREQD",
            },
        )
        findings.append(finding)

    # Kerberoastable (has SPN)
    if user_data.get('spn') or user_data.get('spns'):
        spns = user_data.get('spns', [])
        finding = Finding(
            id=f"spn_{username}",
            finding_type=FindingType.USER_FLAG,
            source=source,
            target=username,
            raw_value=spns[0] if spns else "HAS_SPN",
            tags=["HAS_SPN"],
            metadata={
                "username": username,
                "spn_user": username,
                "spns": spns,
            },
        )
        findings.append(finding)

    # Password in description
    desc = user_data.get('description', '').lower()
    if desc and any(hint in desc for hint in ['pass', 'pwd', 'cred', 'secret', 'key']):
        finding = Finding(
            id=f"pwd_in_desc_{username}",
            finding_type=FindingType.LDAP_ATTRIBUTE,
            source=source,
            target="description",
            raw_value=user_data.get('description', ''),
            tags=["suspicious_description", "possible_password"],
            metadata={
                "username": username,
                "attribute_name": "description",
            },
        )
        findings.append(finding)

    # Custom attributes (like cascadeLegacyPwd)
    custom_attrs = user_data.get('custom_attributes', {})
    for attr_name, attr_value in custom_attrs.items():
        finding = Finding(
            id=f"custom_attr_{username}_{attr_name}",
            finding_type=FindingType.LDAP_ATTRIBUTE,
            source=source,
            target=attr_name,
            raw_value=attr_value,
            tags=["custom_attribute"],
            metadata={
                "username": username,
                "attribute_name": attr_name,
            },
        )
        findings.append(finding)

    # Group memberships (member_of) - detect privileged groups
    member_of = user_data.get('member_of', [])
    if not member_of:
        member_of = user_data.get('memberOf', [])

    for group_dn in member_of:
        group_lower = group_dn.lower()

        # Detect AD Recycle Bin membership
        if 'recycle' in group_lower and 'bin' in group_lower:
            import re
            match = re.match(r'CN=([^,]+)', group_dn, re.IGNORECASE)
            group_name = match.group(1) if match else group_dn

            finding = Finding(
                id=f"group_{username}_{group_name.replace(' ', '_').replace(',', '_')}",
                finding_type=FindingType.GROUP_MEMBERSHIP,
                source=source,
                target=group_name,
                raw_value=group_dn,
                tags=["group_membership", "ad_recycle_bin"],
                metadata={
                    "username": username,
                    "group_name": group_name,
                    "group_dn": group_dn,
                },
            )
            findings.append(finding)

        # Detect other privileged groups
        elif any(priv in group_lower for priv in [
            'domain admin', 'enterprise admin', 'administrator',
            'backup operator', 'server operator', 'account operator',
            'dnsadmin', 'schema admin', 'key admin',
        ]):
            import re
            match = re.match(r'CN=([^,]+)', group_dn, re.IGNORECASE)
            group_name = match.group(1) if match else group_dn

            finding = Finding(
                id=f"group_{username}_{group_name.replace(' ', '_').replace(',', '_')}",
                finding_type=FindingType.GROUP_MEMBERSHIP,
                source=source,
                target=group_name,
                raw_value=group_dn,
                tags=["group_membership", "privileged_group"],
                metadata={
                    "username": username,
                    "group_name": group_name,
                    "group_dn": group_dn,
                },
            )
            findings.append(finding)

    return findings


def _finding_from_custom_attribute(
    attr_data: Dict[str, Any],
    source: str,
) -> Optional[Finding]:
    """Create finding from a custom attribute record."""
    username = attr_data.get('username', 'unknown')
    attr_name = attr_data.get('attribute_name', 'unknown')
    attr_value = attr_data.get('value', '')

    if not attr_value:
        return None

    return Finding(
        id=f"custom_attr_{username}_{attr_name}",
        finding_type=FindingType.LDAP_ATTRIBUTE,
        source=source,
        target=attr_name,
        raw_value=attr_value,
        tags=["custom_attribute"],
        metadata={
            "username": username,
            "attribute_name": attr_name,
        },
    )


def findings_from_smb_crawl(
    crawl_result,
    source: str = "smb_crawl",
) -> List[Finding]:
    """
    Convert SMB crawl results to Finding objects.

    Args:
        crawl_result: CrawlResult from SMBCrawler
        source: Source identifier

    Returns:
        List of Finding objects for interesting files
    """
    findings = []

    if not crawl_result:
        return findings

    # Handle CrawlResult object (from SMBCrawler)
    files = getattr(crawl_result, 'files', [])

    for file_info in files:
        # Handle DiscoveredFile objects
        if hasattr(file_info, 'path'):
            file_path = file_info.path
            file_name = file_info.filename if hasattr(file_info, 'filename') else file_path.split('/')[-1]
            file_content = file_info.content if hasattr(file_info, 'content') else None
            file_size = file_info.size if hasattr(file_info, 'size') else None
            file_source = file_info.source if hasattr(file_info, 'source') else source
            file_score = file_info.interesting_score if hasattr(file_info, 'interesting_score') else 0
        # Handle dict-style file info
        elif isinstance(file_info, dict):
            file_path = file_info.get('path', '')
            file_name = file_info.get('name', file_path.split('/')[-1])
            file_content = file_info.get('content')
            file_size = file_info.get('size')
            file_source = file_info.get('source', source)
            file_score = file_info.get('score', 0)
        else:
            continue

        # Check for interesting file types
        tags = []
        lower_name = file_name.lower()
        lower_path = file_path.lower()

        # VNC registry files - HIGH PRIORITY
        if 'vnc' in lower_path and lower_name.endswith('.reg'):
            tags.extend(['vnc', 'registry', 'high_priority'])

        # Database files - HIGH PRIORITY
        elif any(lower_name.endswith(ext) for ext in ['.db', '.sqlite', '.sqlite3']):
            tags.extend(['database', 'high_priority'])

        # Config files
        elif any(lower_name.endswith(ext) for ext in ['.ini', '.conf', '.config', '.cfg']):
            tags.append('config')

        # XML files (often contain creds)
        elif lower_name.endswith('.xml'):
            tags.extend(['config', 'xml'])

        # Executable/DLL - check for .NET
        elif any(lower_name.endswith(ext) for ext in ['.exe', '.dll']):
            tags.append('executable')

        # Scripts
        elif any(lower_name.endswith(ext) for ext in ['.ps1', '.bat', '.cmd', '.vbs']):
            tags.append('script')

        # Text files with suspicious names
        elif any(hint in lower_name for hint in ['pass', 'cred', 'secret', 'login', 'auth']):
            tags.append('suspicious_name')

        # Skip uninteresting files (unless high score)
        if not tags and file_score < 30:
            continue

        # Infer username from path (e.g., /Users/s.smith/ or /IT/Temp/s.smith/)
        inferred_user = _infer_username_from_path(file_path)

        # Extract share name from source URL
        share_name = file_source.split('/')[-1] if '/' in str(file_source) else ''

        finding = Finding(
            id=f"file_{hash(file_path) & 0xFFFFFFFF:08x}",
            finding_type=FindingType.FILE,
            source=source,
            target=file_path,
            raw_value=file_content,
            tags=tags,
            confidence=0.8 if 'high_priority' in tags else 0.5,
            metadata={
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "share": share_name,
                "full_source": file_source,
                "score": file_score,
                "inferred_user": inferred_user,
            },
        )
        findings.append(finding)

    return findings


def _infer_username_from_path(path: str) -> Optional[str]:
    """
    Infer username from file path.

    Looks for patterns like:
    - /Users/username/
    - /home/username/
    - /IT/Temp/s.smith/
    - \\share\\username\\

    Returns username or None.
    """
    import re

    # Normalize path separators
    normalized = path.replace('\\', '/')

    # Common patterns for user directories
    patterns = [
        r'/users?/([^/]+)/',           # /Users/username/ or /User/username/
        r'/home/([^/]+)/',             # /home/username/
        r'/profiles?/([^/]+)/',        # /Profiles/username/
        r'/([a-z]\.[a-z]+)/',          # /s.smith/ (first.last format)
        r'/temp/([^/]+)/',             # /Temp/username/
    ]

    for pattern in patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            username = match.group(1)
            # Validate it looks like a username (not a generic folder)
            generic_folders = {'temp', 'tmp', 'data', 'files', 'documents', 'it', 'admin'}
            if username.lower() not in generic_folders:
                return username

    return None


def findings_from_extracted_credentials(
    credentials,
    source: str = "smb_crawl",
    target: Optional[str] = None,
) -> List[Finding]:
    """
    Convert extracted credentials from SMB crawl or config files to Finding objects.

    These findings are tagged appropriately to trigger password spray recommendations
    when default/shared passwords are discovered.

    Args:
        credentials: List of DiscoveredCredential objects from parsers
        source: Source identifier
        target: Target IP for spray command user_file path

    Returns:
        List of Finding objects for credentials
    """
    # Calculate user_file path if target provided
    user_file = None
    if target:
        target_sanitized = target.replace('.', '_')
        user_file = f"./enum_{target_sanitized}/users_real.txt"
    findings = []

    for cred in credentials:
        # Handle DiscoveredCredential objects
        if hasattr(cred, 'username'):
            username = cred.username
            password = cred.secret
            cred_source = cred.source if hasattr(cred, 'source') else source
            notes = cred.notes if hasattr(cred, 'notes') else ""
            confidence = getattr(cred, 'confidence', None)
        elif isinstance(cred, dict):
            username = cred.get('username', 'unknown')
            password = cred.get('password') or cred.get('secret', '')
            cred_source = cred.get('source', source)
            notes = cred.get('notes', '')
            confidence = cred.get('confidence')
        else:
            continue

        if not password:
            continue

        # Determine tags based on source and characteristics
        tags = ["from_file", "plaintext"]

        # Check for default/shared password indicators
        is_default = False
        notes_lower = notes.lower() if notes else ""
        if any(hint in notes_lower for hint in ['default', 'initial', 'shared', 'common']):
            is_default = True
            tags.append("default_password")

        # High confidence from text file extraction often indicates explicit password mention
        if confidence and hasattr(confidence, 'name') and confidence.name == 'CONFIRMED':
            tags.append("default_password")
            is_default = True

        # Source indicators for default passwords
        source_lower = str(cred_source).lower()
        if any(hint in source_lower for hint in ['hr', 'notice', 'readme', 'welcome', 'onboard', 'setup']):
            tags.append("default_password")
            is_default = True

        # Build metadata dict
        cred_metadata = {
            "username": username,
            "password": password,
            "cred_source": cred_source,
            "notes": notes,
            "source_description": notes,
            "is_default_password": is_default,
        }
        # Add user_file if we have a target
        if user_file:
            cred_metadata["user_file"] = user_file

        finding = Finding(
            id=f"cred_{hash(f'{username}:{password}') & 0xFFFFFFFF:08x}",
            finding_type=FindingType.CREDENTIAL,
            source=source,
            target=cred_source,
            raw_value=password,
            decoded_value=password,  # Already plaintext
            tags=tags,
            confidence=0.9 if is_default else 0.7,
            metadata=cred_metadata,
        )
        findings.append(finding)

    return findings


def findings_from_group_memberships(
    user_groups: Dict[str, List[str]],
    source: str = "ldap_enum",
) -> List[Finding]:
    """
    Convert group membership data to Finding objects.

    Args:
        user_groups: Dict mapping username to list of group names
        source: Source identifier

    Returns:
        List of Finding objects for interesting group memberships
    """
    findings = []

    # Groups that grant special privileges
    interesting_groups = [
        "domain admins",
        "enterprise admins",
        "administrators",
        "account operators",
        "backup operators",
        "server operators",
        "dnsadmins",
        "recycle bin",  # AD Recycle Bin
        "gpo creator",
        "schema admins",
        "key admins",
        "enterprise key admins",
    ]

    for username, groups in user_groups.items():
        for group_name in groups:
            group_lower = group_name.lower()

            # Check if this is an interesting group
            is_interesting = any(ig in group_lower for ig in interesting_groups)
            if not is_interesting:
                continue

            tags = ["group_membership"]
            if "recycle" in group_lower and "bin" in group_lower:
                tags.append("ad_recycle_bin")
            if "admin" in group_lower:
                tags.append("privileged_group")
            if "backup" in group_lower or "server op" in group_lower:
                tags.append("privileged_group")

            finding = Finding(
                id=f"group_{username}_{group_name.replace(' ', '_')}",
                finding_type=FindingType.GROUP_MEMBERSHIP,
                source=source,
                target=group_name,
                raw_value=group_name,
                tags=tags,
                metadata={
                    "username": username,
                    "group_name": group_name,
                },
            )
            findings.append(finding)

    return findings
