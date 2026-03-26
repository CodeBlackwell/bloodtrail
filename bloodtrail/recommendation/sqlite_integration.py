"""
SQLite Hunter Integration for Recommendation Engine.

Bridges the SQLite hunter with the recommendation engine:
1. Hunts SQLite databases for credentials
2. Converts extracted credentials to Findings
3. Generates prioritized recommendations based on credential type
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from .models import Finding, FindingType, Recommendation, RecommendationPriority
from .triggers import (
    create_decrypt_sqlite_credential_recommendation,
    create_test_sqlite_credential_recommendation,
)

# Import from hunters module
from ..hunters.sqlite_hunter import (
    SqliteHunter,
    SqliteHuntResult,
    ExtractedCredential,
    PasswordType,
    format_hunt_result,
)


@dataclass
class SqliteHuntSummary:
    """Summary of SQLite hunt results for display."""
    db_path: str
    success: bool
    tables_searched: int
    credentials_found: int
    plaintext_creds: int
    encrypted_creds: int
    hashed_creds: int
    findings: List[Finding]
    recommendations: List[Recommendation]
    extracted: List[ExtractedCredential]
    errors: List[str]


def process_sqlite_hunt(
    db_path: str,
    target: str,
    domain: Optional[str] = None,
) -> SqliteHuntSummary:
    """
    Hunt a SQLite database and generate findings/recommendations.

    Args:
        db_path: Path to the SQLite database file
        target: Target IP/hostname for credential testing
        domain: Domain name

    Returns:
        SqliteHuntSummary with findings and recommendations
    """
    hunter = SqliteHunter()
    result = hunter.hunt(db_path)

    summary = SqliteHuntSummary(
        db_path=db_path,
        success=result.success,
        tables_searched=len(result.credential_tables),
        credentials_found=len(result.credentials),
        plaintext_creds=0,
        encrypted_creds=0,
        hashed_creds=0,
        findings=[],
        recommendations=[],
        extracted=result.credentials,
        errors=result.errors,
    )

    if not result.success:
        return summary

    # Process each extracted credential
    for i, cred in enumerate(result.credentials):
        finding = _credential_to_finding(cred, db_path, i)
        summary.findings.append(finding)

        # Categorize by type
        if cred.secret_type == PasswordType.PLAINTEXT:
            summary.plaintext_creds += 1
            # Plaintext = test immediately
            rec = create_test_sqlite_credential_recommendation(
                finding=finding,
                target=target,
                username=cred.username,
                password=cred.secret,
                domain=domain,
                source_table=cred.table_name,
            )
            summary.recommendations.append(rec)

        elif cred.secret_type in (PasswordType.ENCRYPTED_AES, PasswordType.ENCRYPTED_UNKNOWN):
            summary.encrypted_creds += 1
            # Encrypted = need decryption key
            encryption_type = "AES" if cred.secret_type == PasswordType.ENCRYPTED_AES else "unknown"
            rec = create_decrypt_sqlite_credential_recommendation(
                finding=finding,
                target=target,
                username=cred.username,
                encrypted_value=cred.secret,
                encryption_type=encryption_type,
                table_name=cred.table_name,
            )
            summary.recommendations.append(rec)

        elif cred.secret_type in (
            PasswordType.HASH_MD5, PasswordType.HASH_SHA1,
            PasswordType.HASH_SHA256, PasswordType.HASH_BCRYPT,
            PasswordType.HASH_NTLM,
        ):
            summary.hashed_creds += 1
            # Hash = try to crack
            rec = _create_crack_hash_recommendation(finding, cred, target, domain)
            summary.recommendations.append(rec)

        elif cred.secret_type == PasswordType.BASE64:
            # Base64 = decode and test
            import base64
            try:
                decoded = base64.b64decode(cred.secret).decode('utf-8', errors='ignore')
                rec = create_test_sqlite_credential_recommendation(
                    finding=finding,
                    target=target,
                    username=cred.username,
                    password=decoded,
                    domain=domain,
                    source_table=cred.table_name,
                )
                rec.description = f"Test base64-decoded SQLite credential for {cred.username}"
                summary.recommendations.append(rec)
                summary.plaintext_creds += 1  # Effectively plaintext after decode
            except:
                pass

    # Sort recommendations by priority
    summary.recommendations.sort(key=lambda r: r.priority.value)

    return summary


def _credential_to_finding(
    cred: ExtractedCredential,
    db_path: str,
    index: int,
) -> Finding:
    """Convert an extracted credential to a Finding."""
    finding_id = f"sqlite_cred_{index}_{cred.username}"

    tags = ["sqlite", "credential"]
    if cred.secret_type == PasswordType.ENCRYPTED_AES:
        tags.append("encrypted")
        tags.append("aes")
    elif cred.secret_type == PasswordType.ENCRYPTED_UNKNOWN:
        tags.append("encrypted")
    elif "hash" in cred.secret_type.value.lower():
        tags.append("hash")

    return Finding(
        id=finding_id,
        finding_type=FindingType.CREDENTIAL,
        target=cred.username,
        raw_value=cred.secret,
        decoded_value=None,
        source=f"{db_path}:{cred.table_name}",
        tags=tags,
        metadata={
            "username": cred.username,
            "secret_type": cred.secret_type.value,
            "table_name": cred.table_name,
            "db_path": db_path,
            "additional_fields": cred.additional_fields,
            "iv": cred.iv,
            "encryption_hint": cred.encryption_hint,
        },
    )


def _create_crack_hash_recommendation(
    finding: Finding,
    cred: ExtractedCredential,
    target: str,
    domain: Optional[str],
) -> Recommendation:
    """Create recommendation to crack a password hash."""
    hash_type_map = {
        PasswordType.HASH_MD5: ("0", "MD5"),
        PasswordType.HASH_SHA1: ("100", "SHA1"),
        PasswordType.HASH_SHA256: ("1400", "SHA256"),
        PasswordType.HASH_BCRYPT: ("3200", "bcrypt"),
        PasswordType.HASH_NTLM: ("1000", "NTLM"),
    }

    mode, name = hash_type_map.get(cred.secret_type, ("0", "unknown"))

    return Recommendation(
        id=f"crack_sqlite_hash_{finding.id}",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Crack {name} hash for {cred.username}",
        why=f"SQLite database contains {name} hash for '{cred.username}' - attempt offline cracking",
        command=f"hashcat -m {mode} -a 0 hash.txt /usr/share/wordlists/rockyou.txt",
        metadata={
            "username": cred.username,
            "hash": cred.secret,
            "hash_type": name,
            "hashcat_mode": mode,
        },
    )


def display_sqlite_summary(summary: SqliteHuntSummary, verbose: bool = True) -> str:
    """Format SQLite hunt summary for terminal display."""
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
    lines.append(f"{C}{B}  SQLITE CREDENTIAL HUNT: {summary.db_path}{X}")
    lines.append(f"{C}{B}{'=' * 74}{X}\n")

    if not summary.success:
        lines.append(f"  {R}Hunt failed:{X}")
        for err in summary.errors:
            lines.append(f"    {err}")
        return '\n'.join(lines)

    # Summary stats
    lines.append(f"  {D}Tables searched:{X}  {summary.tables_searched}")
    lines.append(f"  {D}Credentials:{X}      {summary.credentials_found}")
    lines.append(f"    {G}Plaintext:{X}      {summary.plaintext_creds}")
    lines.append(f"    {Y}Encrypted:{X}      {summary.encrypted_creds}")
    lines.append(f"    {C}Hashed:{X}         {summary.hashed_creds}")
    lines.append("")

    # Extracted credentials
    if summary.extracted:
        lines.append(f"  {R}{B}EXTRACTED CREDENTIALS ({len(summary.extracted)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")

        for cred in summary.extracted:
            type_color = (
                G if cred.secret_type == PasswordType.PLAINTEXT
                else R if "encrypted" in cred.secret_type.value
                else Y
            )

            lines.append(f"    {B}{cred.username}{X}")
            lines.append(f"      {D}Table:{X} {cred.table_name}")
            lines.append(f"      {D}Type:{X}  {type_color}{cred.secret_type.value}{X}")

            # Show secret (truncated for encrypted/hash)
            secret_display = cred.secret[:40]
            if len(cred.secret) > 40:
                secret_display += "..."
            lines.append(f"      {D}Value:{X} {secret_display}")

            if cred.iv:
                lines.append(f"      {D}IV:{X}    {cred.iv[:32]}...")

            if cred.encryption_hint:
                lines.append(f"      {Y}Hint:{X}  {cred.encryption_hint}")

            lines.append("")

    # Recommendations
    if summary.recommendations:
        lines.append(f"  {B}RECOMMENDATIONS ({len(summary.recommendations)}){X}")
        lines.append(f"  {D}{'─' * 60}{X}")
        for rec in summary.recommendations[:5]:
            priority_color = R if rec.priority.value <= 1 else Y if rec.priority.value <= 2 else D
            lines.append(f"    {priority_color}[{rec.priority.name}]{X} {rec.description}")
            lines.append(f"      {D}Why:{X} {rec.why[:60]}...")
            if rec.command:
                lines.append(f"      {G}$ {rec.command}{X}")
            lines.append("")

        if len(summary.recommendations) > 5:
            lines.append(f"    {D}... and {len(summary.recommendations) - 5} more{X}")

    return '\n'.join(lines)


def hunt_and_display(
    db_path: str,
    target: str,
    domain: Optional[str] = None,
    verbose: bool = True,
) -> SqliteHuntSummary:
    """
    Convenience function to hunt a database and display results.

    Args:
        db_path: Path to SQLite database
        target: Target IP for credential testing
        domain: Domain name
        verbose: Show detailed output

    Returns:
        SqliteHuntSummary with all findings and recommendations
    """
    summary = process_sqlite_hunt(db_path, target, domain)
    print(display_sqlite_summary(summary, verbose))
    return summary
