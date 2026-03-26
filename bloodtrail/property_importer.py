"""
Node Property Importer for BloodHound Data

Imports security-relevant properties from User/Computer nodes to enable
quick-wins queries (Kerberoasting, AS-REP, delegation detection).

The BloodTrail edge extractor only imports relationships (AdminTo, GenericAll, etc.)
but not node properties. This module fills that gap by importing properties
needed for vulnerability detection queries like:
- Kerberoasting (hasspn, serviceprincipalnames)
- AS-REP roasting (dontreqpreauth)
- Delegation abuse (unconstraineddelegation, trustedtoauth)
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

from .data_source import DataSource
from .config import Neo4jConfig, DEFAULT_BATCH_SIZE


class Colors:
    """ANSI color codes for terminal output"""
    BOLD = '\033[1m'
    DIM = '\033[2m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'


@dataclass
class PropertyImportStats:
    """Statistics from property import"""
    users_imported: int = 0
    computers_imported: int = 0
    groups_imported: int = 0
    domains_imported: int = 0

    # Security-relevant counts
    kerberoastable: int = 0
    asrep_roastable: int = 0
    unconstrained_delegation: int = 0
    constrained_delegation: int = 0
    privileged_users: int = 0
    no_laps: int = 0

    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def print_summary(self):
        """Print colorized summary"""
        C = Colors
        print()
        print(f"{C.BOLD}{C.CYAN}{'=' * 60}{C.RESET}")
        print(f"{C.BOLD}Node Properties Imported{C.RESET}")
        print(f"{C.CYAN}{'=' * 60}{C.RESET}")
        print()

        # Node counts
        print(f"  {C.BOLD}Nodes:{C.RESET}")
        print(f"    Users:     {C.GREEN}{self.users_imported:>5}{C.RESET}")
        print(f"    Computers: {C.GREEN}{self.computers_imported:>5}{C.RESET}")
        print(f"    Groups:    {C.GREEN}{self.groups_imported:>5}{C.RESET}")
        print(f"    Domains:   {C.GREEN}{self.domains_imported:>5}{C.RESET}")
        print()

        # Quick wins detected
        print(f"  {C.BOLD}Quick Wins Detected:{C.RESET}")
        self._print_quickwin("Kerberoastable", self.kerberoastable, C.RED)
        self._print_quickwin("AS-REP Roastable", self.asrep_roastable, C.RED)
        self._print_quickwin("Unconstrained Delegation", self.unconstrained_delegation, C.YELLOW)
        self._print_quickwin("Constrained Delegation", self.constrained_delegation, C.YELLOW)
        self._print_quickwin("Privileged Users (admincount)", self.privileged_users, C.BLUE)
        self._print_quickwin("Computers Without LAPS", self.no_laps, C.YELLOW)
        print()

        print(f"  {C.DIM}Duration: {self.duration_seconds:.2f}s{C.RESET}")
        print()

    def _print_quickwin(self, name: str, count: int, color: str):
        C = Colors
        if count > 0:
            print(f"    {color}{name}:{C.RESET} {C.BOLD}{count:>5}{C.RESET}")
        else:
            print(f"    {C.DIM}{name}:{C.RESET} {C.DIM}{count:>5}{C.RESET}")


class PropertyImporter:
    """
    Imports node properties from BloodHound JSON to Neo4j.

    Properties imported:
    - User: hasspn, serviceprincipalnames, dontreqpreauth, admincount, enabled, pwdneverexpires
    - Computer: unconstraineddelegation, trustedtoauth, haslaps, operatingsystem
    - Group/Domain: Basic properties for reference
    """

    # User properties needed for security queries
    USER_PROPERTIES = [
        'name', 'enabled', 'hasspn', 'serviceprincipalnames',
        'dontreqpreauth', 'admincount', 'pwdneverexpires', 'description',
        'lastlogon', 'lastlogontimestamp', 'pwdlastset', 'sensitive',
        'unconstraineddelegation', 'trustedtoauth', 'passwordnotreqd',
        'sidhistory', 'displayname', 'whencreated', 'samaccountname'
    ]

    # Computer properties for delegation and LAPS queries
    COMPUTER_PROPERTIES = [
        'name', 'enabled', 'unconstraineddelegation', 'trustedtoauth',
        'haslaps', 'operatingsystem', 'description', 'lastlogontimestamp',
        'pwdlastset', 'serviceprincipalnames', 'allowedtodelegate'
    ]

    # Group properties
    GROUP_PROPERTIES = [
        'name', 'description', 'admincount', 'highvalue'
    ]

    # Domain properties
    DOMAIN_PROPERTIES = [
        'name', 'domain', 'functionallevel', 'highvalue'
    ]

    def __init__(self, driver, batch_size: int = DEFAULT_BATCH_SIZE):
        self.driver = driver
        self.batch_size = batch_size
        self.stats = PropertyImportStats()

    def import_from_source(
        self,
        data_source: DataSource,
        verbose: bool = False
    ) -> PropertyImportStats:
        """
        Import properties from BloodHound JSON data source.

        Args:
            data_source: Directory or ZIP containing BloodHound JSON
            verbose: Print detailed progress

        Returns:
            PropertyImportStats with results
        """
        start_time = time.time()
        self.stats = PropertyImportStats()
        C = Colors

        for filename, data in data_source.iter_json_files():
            filename_lower = filename.lower()

            if 'users' in filename_lower:
                if verbose:
                    print(f"{C.CYAN}[*]{C.RESET} Importing user properties from {filename}...")
                self._import_users(data, verbose)

            elif 'computers' in filename_lower:
                if verbose:
                    print(f"{C.CYAN}[*]{C.RESET} Importing computer properties from {filename}...")
                self._import_computers(data, verbose)

            elif 'groups' in filename_lower:
                if verbose:
                    print(f"{C.CYAN}[*]{C.RESET} Importing group properties from {filename}...")
                self._import_groups(data, verbose)

            elif 'domains' in filename_lower:
                if verbose:
                    print(f"{C.CYAN}[*]{C.RESET} Importing domain properties from {filename}...")
                self._import_domains(data, verbose)

        self.stats.duration_seconds = time.time() - start_time
        return self.stats

    def _import_users(self, data: dict, verbose: bool):
        """Import User node properties"""
        users = data.get('data', [])
        if not users:
            return

        # Prepare batch data
        user_batch = []
        for user in users:
            props = user.get('Properties', {})
            name = props.get('name')
            if not name:
                continue

            # Track security-relevant properties
            if props.get('hasspn') and props.get('enabled', False):
                # Skip KRBTGT
                if not name.upper().startswith('KRBTGT'):
                    self.stats.kerberoastable += 1

            if props.get('dontreqpreauth') and props.get('enabled', False):
                self.stats.asrep_roastable += 1

            if props.get('admincount'):
                self.stats.privileged_users += 1

            # Build property dict for import
            user_data = {
                'name': name,
                'enabled': props.get('enabled', False),
                'hasspn': props.get('hasspn', False),
                'serviceprincipalnames': props.get('serviceprincipalnames', []),
                'dontreqpreauth': props.get('dontreqpreauth', False),
                'admincount': props.get('admincount', False),
                'pwdneverexpires': props.get('pwdneverexpires', False),
                'description': props.get('description'),
                'lastlogon': props.get('lastlogon'),
                'pwdlastset': props.get('pwdlastset'),
                'sensitive': props.get('sensitive', False),
                'unconstraineddelegation': props.get('unconstraineddelegation', False),
                'trustedtoauth': props.get('trustedtoauth', False),
                'displayname': props.get('displayname'),
                'samaccountname': props.get('samaccountname'),
            }
            user_batch.append(user_data)

        # Batch import to Neo4j
        if user_batch:
            self._batch_import_users(user_batch, verbose)

    def _batch_import_users(self, users: List[dict], verbose: bool):
        """Batch import users using UNWIND"""
        C = Colors
        query = """
        UNWIND $users AS u
        MERGE (n:User {name: u.name})
        SET n.enabled = u.enabled,
            n.hasspn = u.hasspn,
            n.serviceprincipalnames = u.serviceprincipalnames,
            n.dontreqpreauth = u.dontreqpreauth,
            n.admincount = u.admincount,
            n.pwdneverexpires = u.pwdneverexpires,
            n.description = u.description,
            n.lastlogon = u.lastlogon,
            n.pwdlastset = u.pwdlastset,
            n.sensitive = u.sensitive,
            n.unconstraineddelegation = u.unconstraineddelegation,
            n.trustedtoauth = u.trustedtoauth,
            n.displayname = u.displayname,
            n.samaccountname = u.samaccountname
        RETURN count(n) AS imported
        """

        try:
            for i in range(0, len(users), self.batch_size):
                batch = users[i:i + self.batch_size]
                with self.driver.session() as session:
                    result = session.run(query, users=batch)
                    record = result.single()
                    if record:
                        self.stats.users_imported += record["imported"]

            if verbose:
                print(f"  {C.GREEN}[+]{C.RESET} Imported {self.stats.users_imported} users")

        except Exception as e:
            self.stats.errors.append(f"User import error: {e}")
            if verbose:
                print(f"  {C.RED}[!]{C.RESET} Error importing users: {e}")

    def _import_computers(self, data: dict, verbose: bool):
        """Import Computer node properties"""
        computers = data.get('data', [])
        if not computers:
            return

        computer_batch = []
        for computer in computers:
            props = computer.get('Properties', {})
            name = props.get('name')
            if not name:
                continue

            # Track security-relevant properties
            if props.get('unconstraineddelegation') and props.get('enabled', False):
                self.stats.unconstrained_delegation += 1

            if props.get('trustedtoauth') and props.get('enabled', False):
                self.stats.constrained_delegation += 1

            if props.get('haslaps') is False and props.get('enabled', False):
                # Skip DCs (they don't need LAPS)
                if not name.upper().startswith('DC'):
                    self.stats.no_laps += 1

            computer_data = {
                'name': name,
                'enabled': props.get('enabled', False),
                'unconstraineddelegation': props.get('unconstraineddelegation', False),
                'trustedtoauth': props.get('trustedtoauth', False),
                'haslaps': props.get('haslaps', False),
                'operatingsystem': props.get('operatingsystem'),
                'description': props.get('description'),
                'serviceprincipalnames': props.get('serviceprincipalnames', []),
                'allowedtodelegate': computer.get('AllowedToDelegate', []),
            }
            computer_batch.append(computer_data)

        if computer_batch:
            self._batch_import_computers(computer_batch, verbose)

    def _batch_import_computers(self, computers: List[dict], verbose: bool):
        """Batch import computers using UNWIND"""
        C = Colors
        query = """
        UNWIND $computers AS c
        MERGE (n:Computer {name: c.name})
        SET n.enabled = c.enabled,
            n.unconstraineddelegation = c.unconstraineddelegation,
            n.trustedtoauth = c.trustedtoauth,
            n.haslaps = c.haslaps,
            n.operatingsystem = c.operatingsystem,
            n.description = c.description,
            n.serviceprincipalnames = c.serviceprincipalnames,
            n.allowedtodelegate = c.allowedtodelegate
        RETURN count(n) AS imported
        """

        try:
            for i in range(0, len(computers), self.batch_size):
                batch = computers[i:i + self.batch_size]
                with self.driver.session() as session:
                    result = session.run(query, computers=batch)
                    record = result.single()
                    if record:
                        self.stats.computers_imported += record["imported"]

            if verbose:
                print(f"  {C.GREEN}[+]{C.RESET} Imported {self.stats.computers_imported} computers")

        except Exception as e:
            self.stats.errors.append(f"Computer import error: {e}")
            if verbose:
                print(f"  {C.RED}[!]{C.RESET} Error importing computers: {e}")

    def _import_groups(self, data: dict, verbose: bool):
        """Import Group node properties"""
        groups = data.get('data', [])
        if not groups:
            return

        group_batch = []
        for group in groups:
            props = group.get('Properties', {})
            name = props.get('name')
            if not name:
                continue

            group_data = {
                'name': name,
                'description': props.get('description'),
                'admincount': props.get('admincount', False),
                'highvalue': props.get('highvalue', False),
            }
            group_batch.append(group_data)

        if group_batch:
            self._batch_import_groups(group_batch, verbose)

    def _batch_import_groups(self, groups: List[dict], verbose: bool):
        """Batch import groups using UNWIND"""
        C = Colors
        query = """
        UNWIND $groups AS g
        MERGE (n:Group {name: g.name})
        SET n.description = g.description,
            n.admincount = g.admincount,
            n.highvalue = g.highvalue
        RETURN count(n) AS imported
        """

        try:
            for i in range(0, len(groups), self.batch_size):
                batch = groups[i:i + self.batch_size]
                with self.driver.session() as session:
                    result = session.run(query, groups=batch)
                    record = result.single()
                    if record:
                        self.stats.groups_imported += record["imported"]

            if verbose:
                print(f"  {C.GREEN}[+]{C.RESET} Imported {self.stats.groups_imported} groups")

        except Exception as e:
            self.stats.errors.append(f"Group import error: {e}")
            if verbose:
                print(f"  {C.RED}[!]{C.RESET} Error importing groups: {e}")

    def _import_domains(self, data: dict, verbose: bool):
        """Import Domain node properties"""
        domains = data.get('data', [])
        if not domains:
            return

        domain_batch = []
        for domain in domains:
            props = domain.get('Properties', {})
            name = props.get('name')
            if not name:
                continue

            domain_data = {
                'name': name,
                'functionallevel': props.get('functionallevel'),
                'highvalue': props.get('highvalue', True),  # Domains are high value by default
            }
            domain_batch.append(domain_data)

        if domain_batch:
            self._batch_import_domains(domain_batch, verbose)

    def _batch_import_domains(self, domains: List[dict], verbose: bool):
        """Batch import domains using UNWIND"""
        C = Colors
        query = """
        UNWIND $domains AS d
        MERGE (n:Domain {name: d.name})
        SET n.functionallevel = d.functionallevel,
            n.highvalue = d.highvalue
        RETURN count(n) AS imported
        """

        try:
            for i in range(0, len(domains), self.batch_size):
                batch = domains[i:i + self.batch_size]
                with self.driver.session() as session:
                    result = session.run(query, domains=batch)
                    record = result.single()
                    if record:
                        self.stats.domains_imported += record["imported"]

            if verbose:
                print(f"  {C.GREEN}[+]{C.RESET} Imported {self.stats.domains_imported} domains")

        except Exception as e:
            self.stats.errors.append(f"Domain import error: {e}")
            if verbose:
                print(f"  {C.RED}[!]{C.RESET} Error importing domains: {e}")
