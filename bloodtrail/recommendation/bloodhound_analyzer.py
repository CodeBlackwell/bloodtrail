"""
BloodHound Analyzer - Run privilege escalation queries after BloodHound collection.

This module bridges BloodHound data (in Neo4j) with the recommendation engine.
After SharpHound collection and import, it runs Cypher queries to detect:
- Account Operators membership (can create users)
- Exchange Windows Permissions with WriteDACL (can grant DCSync)
- Other privilege escalation paths

Detected paths are converted to Finding objects that trigger recommendations.
"""

from typing import List, Optional, Dict, Any
import re

from ..core.neo4j_connection import get_neo4j_session, Neo4jConnection
from ..config import Neo4jConfig
from .models import Finding, FindingType


class BloodHoundAnalyzer:
    """
    Analyze BloodHound data for privilege escalation paths.

    Runs targeted Cypher queries and converts results to findings
    that the recommendation engine can process.
    """

    def __init__(self, config: Optional[Neo4jConfig] = None, verbose: bool = False):
        """
        Initialize analyzer.

        Args:
            config: Neo4j connection config (uses defaults if not provided)
            verbose: Enable verbose output for debugging
        """
        self.config = config
        self.verbose = verbose

    def _log(self, message: str) -> None:
        """Print debug message if verbose enabled."""
        if self.verbose:
            print(f"[BloodHound] {message}")

    def analyze_attack_paths(
        self,
        username: str,
        domain: str,
    ) -> List[Finding]:
        """
        Run all privilege escalation queries for the given user.

        This is the main entry point called after BloodHound collection.

        Args:
            username: Current user (sAMAccountName format, e.g., 'svc-alfresco')
            domain: Domain name (e.g., 'HTB.LOCAL')

        Returns:
            List of Finding objects representing discovered attack paths
        """
        findings: List[Finding] = []

        # Format username as UPN for BloodHound queries
        upn = f"{username.upper()}@{domain.upper()}"
        self._log(f"Analyzing attack paths for: {upn}")

        try:
            with get_neo4j_session(self.config) as session:
                # Check Account Operators membership
                ao_findings = self._check_account_operators(session, upn, domain)
                findings.extend(ao_findings)

                # Check Exchange WriteDACL on domain
                exchange_findings = self._check_exchange_writedacl(session, domain)
                findings.extend(exchange_findings)

                # Check direct WriteDACL paths to domain
                writedacl_findings = self._check_writedacl_paths(session, upn, domain)
                findings.extend(writedacl_findings)

                # Check existing DCSync rights (non-admin)
                dcsync_findings = self._check_dcsync_rights(session)
                findings.extend(dcsync_findings)

                # Check GenericAll on high-value targets
                genericall_findings = self._check_genericall_paths(session, upn)
                findings.extend(genericall_findings)

                # Check ForceChangePassword rights
                fcp_findings = self._check_force_change_password(session, upn)
                findings.extend(fcp_findings)

        except ConnectionError as e:
            self._log(f"Neo4j connection failed: {e}")
            return []
        except Exception as e:
            self._log(f"Analysis error: {e}")
            return []

        self._log(f"Found {len(findings)} attack path(s)")
        return findings

    def _check_account_operators(
        self,
        session,
        upn: str,
        domain: str,
    ) -> List[Finding]:
        """
        Check if user is member of Account Operators (directly or nested).

        Account Operators can:
        - Create new domain users
        - Add users to non-protected groups
        - Modify non-protected accounts

        This is critical for Forest HTB: svc-alfresco is nested member.
        """
        findings = []

        query = """
        MATCH (u:User {name: $upn})-[:MemberOf*1..]->(g:Group)
        WHERE g.name =~ '(?i)ACCOUNT OPERATORS@.*'
        RETURN u.name AS User, g.name AS Group
        """

        try:
            result = session.run(query, upn=upn)
            records = list(result)

            for record in records:
                self._log(f"Account Operators: {record['User']} -> {record['Group']}")

                finding = Finding(
                    id=f"finding_account_operators_{upn.replace('@', '_')}",
                    finding_type=FindingType.GROUP_MEMBERSHIP,
                    source="bloodhound",
                    target=upn,
                    raw_value={
                        "user": record["User"],
                        "group": record["Group"],
                    },
                    tags=["ACCOUNT_OPERATORS", "PRIVILEGED_GROUP", "CAN_CREATE_USERS"],
                    metadata={
                        "group_name": "Account Operators",
                        "can_create_users": True,
                        "can_add_to_groups": True,
                        "domain": domain,
                    },
                )
                finding.decoded_value = f"{record['User']} is member of Account Operators"
                findings.append(finding)

        except Exception as e:
            self._log(f"Account Operators query failed: {e}")

        return findings

    def _check_exchange_writedacl(
        self,
        session,
        domain: str,
    ) -> List[Finding]:
        """
        Check if Exchange Windows Permissions has WriteDACL on the domain.

        This is the key Forest HTB vector:
        Exchange Windows Permissions -[WriteDacl]-> Domain
        Allows granting DCSync rights via Add-ObjectACL.
        """
        findings = []

        query = """
        MATCH (g:Group)-[:WriteDacl]->(d:Domain)
        WHERE g.name =~ '(?i)EXCHANGE WINDOWS PERMISSIONS@.*'
        RETURN g.name AS ExchangeGroup, d.name AS Domain
        """

        try:
            result = session.run(query)
            records = list(result)

            for record in records:
                self._log(f"Exchange WriteDACL: {record['ExchangeGroup']} -> {record['Domain']}")

                finding = Finding(
                    id=f"finding_exchange_writedacl_{domain.replace('.', '_')}",
                    finding_type=FindingType.GROUP_MEMBERSHIP,
                    source="bloodhound",
                    target=record["ExchangeGroup"],
                    raw_value={
                        "group": record["ExchangeGroup"],
                        "domain": record["Domain"],
                        "right": "WriteDacl",
                    },
                    tags=["EXCHANGE_WINDOWS_PERMISSIONS", "WRITEDACL", "DCSYNC_PATH"],
                    metadata={
                        "group_name": "Exchange Windows Permissions",
                        "has_writedacl": True,
                        "target_domain": record["Domain"],
                        "enables_dcsync": True,
                    },
                )
                finding.decoded_value = f"Exchange Windows Permissions has WriteDACL on {record['Domain']}"
                findings.append(finding)

        except Exception as e:
            self._log(f"Exchange WriteDACL query failed: {e}")

        return findings

    def _check_writedacl_paths(
        self,
        session,
        upn: str,
        domain: str,
    ) -> List[Finding]:
        """
        Check if user has direct or indirect WriteDACL on high-value targets.

        WriteDACL allows modifying permissions - can grant self GenericAll
        or add DCSync rights directly.
        """
        findings = []

        query = """
        MATCH path = (u:User {name: $upn})-[:WriteDacl|MemberOf*1..5]->(target)
        WHERE (target:Domain OR target:Group OR target:User)
          AND target.name =~ '(?i).*(ADMIN|DOMAIN).*'
        WITH u, target, length(path) as pathLength
        ORDER BY pathLength
        LIMIT 10
        RETURN DISTINCT u.name AS Attacker,
               target.name AS Target,
               labels(target) AS TargetType
        """

        try:
            result = session.run(query, upn=upn)
            records = list(result)

            for record in records:
                target_name = record["Target"]
                target_type = record["TargetType"][0] if record["TargetType"] else "Unknown"

                self._log(f"WriteDACL path: {record['Attacker']} -> {target_name}")

                finding = Finding(
                    id=f"finding_writedacl_{upn.replace('@', '_')}_{target_name.replace('@', '_')}",
                    finding_type=FindingType.GROUP_MEMBERSHIP,
                    source="bloodhound",
                    target=target_name,
                    raw_value={
                        "attacker": record["Attacker"],
                        "target": target_name,
                        "target_type": target_type,
                    },
                    tags=["WRITEDACL", "ACL_ABUSE"],
                    metadata={
                        "attack_type": "writedacl",
                        "target_type": target_type,
                    },
                )
                finding.decoded_value = f"{record['Attacker']} has WriteDACL path to {target_name}"
                findings.append(finding)

        except Exception as e:
            self._log(f"WriteDACL paths query failed: {e}")

        return findings

    def _check_dcsync_rights(self, session) -> List[Finding]:
        """
        Check for non-admin principals with DCSync rights.

        These can immediately dump all domain hashes without further escalation.
        """
        findings = []

        query = """
        MATCH (n)-[:GetChanges]->(d:Domain)
        MATCH (n)-[:GetChangesAll]->(d)
        WHERE NOT n.admincount = true
        RETURN n.name AS Principal, labels(n) AS Type, d.name AS Domain
        """

        try:
            result = session.run(query)
            records = list(result)

            for record in records:
                principal = record["Principal"]
                principal_type = record["Type"][0] if record["Type"] else "Unknown"

                self._log(f"DCSync rights: {principal} -> {record['Domain']}")

                finding = Finding(
                    id=f"finding_dcsync_{principal.replace('@', '_')}",
                    finding_type=FindingType.GROUP_MEMBERSHIP,
                    source="bloodhound",
                    target=principal,
                    raw_value={
                        "principal": principal,
                        "type": principal_type,
                        "domain": record["Domain"],
                    },
                    tags=["DCSYNC", "CRITICAL", "DOMAIN_COMPROMISE"],
                    metadata={
                        "has_dcsync": True,
                        "principal_type": principal_type,
                        "domain": record["Domain"],
                    },
                )
                finding.decoded_value = f"{principal} has DCSync rights on {record['Domain']}"
                findings.append(finding)

        except Exception as e:
            self._log(f"DCSync rights query failed: {e}")

        return findings

    def _check_genericall_paths(self, session, upn: str) -> List[Finding]:
        """
        Check for GenericAll on high-value targets.

        GenericAll = full control. Can reset passwords, modify attributes, etc.
        """
        findings = []

        query = """
        MATCH (u:User {name: $upn})-[:GenericAll|MemberOf*1..3]->(target)
        WHERE (target.admincount = true OR target.name =~ '(?i).*(ADMIN|DOMAIN).*')
          AND u <> target
        RETURN DISTINCT u.name AS Attacker,
               target.name AS Target,
               labels(target) AS TargetType
        LIMIT 10
        """

        try:
            result = session.run(query, upn=upn)
            records = list(result)

            for record in records:
                target_name = record["Target"]
                target_type = record["TargetType"][0] if record["TargetType"] else "Unknown"

                self._log(f"GenericAll: {record['Attacker']} -> {target_name}")

                finding = Finding(
                    id=f"finding_genericall_{upn.replace('@', '_')}_{target_name.replace('@', '_')}",
                    finding_type=FindingType.GROUP_MEMBERSHIP,
                    source="bloodhound",
                    target=target_name,
                    raw_value={
                        "attacker": record["Attacker"],
                        "target": target_name,
                        "target_type": target_type,
                    },
                    tags=["GENERICALL", "ACL_ABUSE", "HIGH_VALUE"],
                    metadata={
                        "attack_type": "genericall",
                        "target_type": target_type,
                    },
                )
                finding.decoded_value = f"{record['Attacker']} has GenericAll on {target_name}"
                findings.append(finding)

        except Exception as e:
            self._log(f"GenericAll query failed: {e}")

        return findings

    def _check_force_change_password(self, session, upn: str) -> List[Finding]:
        """
        Check for ForceChangePassword rights.

        Can reset another user's password without knowing current password.
        """
        findings = []

        query = """
        MATCH (u:User {name: $upn})-[:ForceChangePassword|MemberOf*1..3]->(target:User)
        WHERE target.enabled = true
          AND u <> target
        RETURN DISTINCT u.name AS Attacker,
               target.name AS Target,
               target.admincount AS TargetIsPrivileged
        ORDER BY target.admincount DESC
        LIMIT 10
        """

        try:
            result = session.run(query, upn=upn)
            records = list(result)

            for record in records:
                target_name = record["Target"]
                is_privileged = record["TargetIsPrivileged"] or False

                self._log(f"ForceChangePassword: {record['Attacker']} -> {target_name}")

                tags = ["FORCECHANGEPASSWORD", "PASSWORD_RESET"]
                if is_privileged:
                    tags.append("PRIVILEGED_TARGET")

                finding = Finding(
                    id=f"finding_fcp_{upn.replace('@', '_')}_{target_name.replace('@', '_')}",
                    finding_type=FindingType.GROUP_MEMBERSHIP,
                    source="bloodhound",
                    target=target_name,
                    raw_value={
                        "attacker": record["Attacker"],
                        "target": target_name,
                        "is_privileged": is_privileged,
                    },
                    tags=tags,
                    metadata={
                        "attack_type": "force_change_password",
                        "target_is_privileged": is_privileged,
                    },
                )
                finding.decoded_value = f"{record['Attacker']} can reset password for {target_name}"
                findings.append(finding)

        except Exception as e:
            self._log(f"ForceChangePassword query failed: {e}")

        return findings

    def is_neo4j_available(self) -> bool:
        """
        Check if Neo4j is available and contains BloodHound data.

        Returns:
            True if Neo4j is connected and has BloodHound data
        """
        try:
            conn = Neo4jConnection(self.config)
            if not conn.connect():
                return False

            # Check if there's BloodHound data
            with conn.driver.session() as session:
                result = session.run("MATCH (n:Domain) RETURN count(n) as count")
                record = result.single()
                has_data = record and record["count"] > 0

            conn.close()
            return has_data
        except Exception:
            return False


def analyze_for_user(
    username: str,
    domain: str,
    verbose: bool = False,
) -> List[Finding]:
    """
    Convenience function to run BloodHound analysis for a user.

    Args:
        username: sAMAccountName (e.g., 'svc-alfresco')
        domain: Domain name (e.g., 'HTB.LOCAL')
        verbose: Enable debug output

    Returns:
        List of discovered attack path findings
    """
    analyzer = BloodHoundAnalyzer(verbose=verbose)
    return analyzer.analyze_attack_paths(username, domain)
