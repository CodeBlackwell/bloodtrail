"""
SMB Crawler Integration for Recommendation Engine.

Bridges the SMB crawler with the recommendation engine:
1. Crawls shares with validated credentials
2. Converts discovered files to Findings
3. Processes VNC files, SQLite DBs, etc.
4. Generates prioritized recommendations
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from .models import Finding, FindingType, Recommendation
from .findings_converter import (
    findings_from_smb_crawl,
    findings_from_extracted_credentials,
    _infer_username_from_path,
)
from .decoders import decrypt_vnc_password, extract_vnc_password_from_reg
from .triggers import (
    create_test_vnc_credential_recommendation,
    create_sqlite_hunt_recommendation,
    create_password_spray_recommendation,
)


@dataclass
class SMBCrawlSummary:
    """Summary of SMB crawl results for display."""
    shares_accessed: List[str]
    total_files: int
    high_priority_files: int
    credentials_extracted: int
    findings: List[Finding]
    recommendations: List[Recommendation]
    vnc_files: List[Dict[str, Any]]
    sqlite_files: List[Dict[str, Any]]
    errors: List[str]


def process_smb_crawl(
    crawl_result,
    target: str,
    domain: Optional[str] = None,
    download_and_parse: bool = True,
) -> SMBCrawlSummary:
    """
    Process SMB crawl results and generate findings/recommendations.

    Args:
        crawl_result: CrawlResult from SMBCrawler.crawl_and_extract()
        target: Target IP/hostname
        domain: Domain name
        download_and_parse: If True, parse file contents for secrets

    Returns:
        SMBCrawlSummary with findings and recommendations
    """
    summary = SMBCrawlSummary(
        shares_accessed=getattr(crawl_result, 'shares_accessed', []),
        total_files=len(getattr(crawl_result, 'files', [])),
        high_priority_files=0,
        credentials_extracted=len(getattr(crawl_result, 'credentials', [])),
        findings=[],
        recommendations=[],
        vnc_files=[],
        sqlite_files=[],
        errors=getattr(crawl_result, 'errors', []),
    )

    # Convert crawl results to findings
    findings = findings_from_smb_crawl(crawl_result)

    # Process extracted credentials and create findings with proper tags
    # Pass target so user_file path is set in finding metadata for trigger rules
    extracted_creds = getattr(crawl_result, 'credentials', [])
    if extracted_creds:
        cred_findings = findings_from_extracted_credentials(extracted_creds, target=target)
        findings.extend(cred_findings)

    summary.findings = findings

    # Process each finding for recommendations
    for finding in findings:
        if 'high_priority' in finding.tags:
            summary.high_priority_files += 1

        # VNC registry files
        if 'vnc' in finding.tags and 'registry' in finding.tags:
            vnc_info = _process_vnc_file(finding, target, domain)
            if vnc_info:
                summary.vnc_files.append(vnc_info)
                if vnc_info.get('recommendation'):
                    summary.recommendations.append(vnc_info['recommendation'])

        # SQLite database files
        elif 'database' in finding.tags:
            sqlite_info = _process_sqlite_file(finding, target)
            summary.sqlite_files.append(sqlite_info)
            if sqlite_info.get('recommendation'):
                summary.recommendations.append(sqlite_info['recommendation'])

    # Sort recommendations by priority
    summary.recommendations.sort(key=lambda r: r.priority.value)

    return summary


def _process_vnc_file(
    finding: Finding,
    target: str,
    domain: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Process a VNC registry file finding."""
    result = {
        "file_path": finding.target,
        "inferred_user": finding.metadata.get("inferred_user"),
        "encrypted_hex": None,
        "decrypted_password": None,
        "recommendation": None,
    }

    # Try to extract password from file content if available
    content = finding.raw_value
    if content:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')

        encrypted_hex = extract_vnc_password_from_reg(content)
        if encrypted_hex:
            result["encrypted_hex"] = encrypted_hex

            # Try to decrypt
            decrypt_result = decrypt_vnc_password(encrypted_hex)
            if decrypt_result.success:
                result["decrypted_password"] = decrypt_result.decoded

                # If we have an inferred user, create credential test recommendation
                inferred_user = finding.metadata.get("inferred_user")
                if inferred_user:
                    result["recommendation"] = create_test_vnc_credential_recommendation(
                        finding=finding,
                        decrypted_password=decrypt_result.decoded,
                        inferred_user=inferred_user,
                        target=target,
                        domain=domain,
                    )

    return result


def _process_sqlite_file(
    finding: Finding,
    target: str,
) -> Dict[str, Any]:
    """Process a SQLite database file finding."""
    result = {
        "file_path": finding.target,
        "file_name": finding.metadata.get("file_name"),
        "share": finding.metadata.get("share"),
        "recommendation": create_sqlite_hunt_recommendation(
            finding=finding,
            file_path=finding.target,
            target=target,
        ),
    }
    return result


def generate_smb_crawl_command(
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
    share: Optional[str] = None,
) -> str:
    """Generate smbmap command for share enumeration."""
    domain_flag = f"-d {domain}" if domain else ""
    share_flag = f"-r {share}" if share else ""
    return f"smbmap -H {target} -u '{username}' -p '{password}' {domain_flag} {share_flag}".strip()


def generate_file_retrieval_commands(
    files: List[Finding],
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
) -> List[str]:
    """Generate smbclient commands to retrieve discovered files."""
    commands = []

    for finding in files:
        if finding.finding_type != FindingType.FILE:
            continue

        share = finding.metadata.get("share", "")
        file_path = finding.metadata.get("file_path", finding.target)

        if not share:
            continue

        if domain:
            cred = f"'{domain}\\{username}%{password}'"
        else:
            cred = f"'{username}%{password}'"

        cmd = f"smbclient //{target}/{share} -U {cred} -c 'get {file_path}'"
        commands.append(cmd)

    return commands


def display_smb_summary(summary: SMBCrawlSummary, verbose: bool = True, target: str = "<TARGET>") -> str:
    """Format SMB crawl summary for terminal display."""
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
    lines.append(f"{C}{B}  SMB CRAWL RESULTS{X}")
    lines.append(f"{C}{B}{'=' * 74}{X}\n")

    # Summary stats
    lines.append(f"  {D}Shares accessed:{X}  {', '.join(summary.shares_accessed)}")
    lines.append(f"  {D}Files found:{X}      {summary.total_files}")
    lines.append(f"  {D}High priority:{X}    {summary.high_priority_files}")
    lines.append(f"  {D}Creds extracted:{X}  {summary.credentials_extracted}")
    lines.append("")

    # VNC files
    if summary.vnc_files:
        lines.append(f"  {R}{B}VNC REGISTRY FILES ({len(summary.vnc_files)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for vnc in summary.vnc_files:
            lines.append(f"    {C}{vnc['file_path']}{X}")
            if vnc.get('inferred_user'):
                lines.append(f"      {D}Inferred user:{X} {B}{vnc['inferred_user']}{X}")
            if vnc.get('encrypted_hex'):
                lines.append(f"      {D}Encrypted:{X} {vnc['encrypted_hex'][:30]}...")
            if vnc.get('decrypted_password'):
                lines.append(f"      {G}Decrypted:{X} {B}{vnc['decrypted_password']}{X}")
        lines.append("")

        # TEST CREDENTIALS section for decrypted VNC passwords
        has_decrypted = any(v.get('decrypted_password') and v.get('inferred_user') for v in summary.vnc_files)
        if has_decrypted:
            lines.append(f"  {G}{B}TEST THESE CREDENTIALS{X}")
            lines.append(f"  {D}{'─' * 60}{X}")
            for vnc in summary.vnc_files:
                if vnc.get('decrypted_password') and vnc.get('inferred_user'):
                    user = vnc['inferred_user']
                    pwd = vnc['decrypted_password']
                    lines.append(f"    {B}{user}:{pwd}{X}")
                    lines.append(f"    {G}$ crackmapexec smb {target} -u {user} -p '{pwd}'{X}")
                    lines.append("")

    # SQLite files
    if summary.sqlite_files:
        lines.append(f"  {Y}{B}SQLITE DATABASES ({len(summary.sqlite_files)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for db in summary.sqlite_files:
            lines.append(f"    {C}{db['file_path']}{X}")
            if db.get('share'):
                lines.append(f"      {D}Share:{X} {db['share']}")
        lines.append("")

    # Recommendations
    if summary.recommendations:
        lines.append(f"  {B}RECOMMENDATIONS ({len(summary.recommendations)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for rec in summary.recommendations[:5]:
            priority_color = R if rec.priority.value <= 1 else Y if rec.priority.value <= 2 else D
            lines.append(f"    {priority_color}●{X} {rec.description}")
            if rec.command:
                lines.append(f"      {G}$ {rec.command}{X}")
        if len(summary.recommendations) > 5:
            lines.append(f"    {D}... and {len(summary.recommendations) - 5} more{X}")
        lines.append("")

    # Errors
    if summary.errors and verbose:
        lines.append(f"  {R}Errors:{X}")
        for err in summary.errors[:3]:
            lines.append(f"    {D}{err}{X}")

    return '\n'.join(lines)
