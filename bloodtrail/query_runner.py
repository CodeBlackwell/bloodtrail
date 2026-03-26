"""
BloodHound Cypher Query Runner

Loads and executes queries from the cypher_queries/*.json library.
Supports variable substitution, result formatting, and query search.

Note: Formatting utilities, models, and report generation have been
extracted to core/ and report_generator.py for modularity.
"""

from typing import Dict, List, Optional, Any

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from .config import Neo4jConfig
from .logger import DebugLogger, Component, StepType

# Module-level debug logger
_logger = DebugLogger(component=Component.BT_QUERY)
from .core.models import Query, QueryResult
from .core.formatters import (
    Colors,
    format_field_value,
    has_path_results,
    print_attack_paths,
)
from .core.query_loader import load_all_queries


class QueryRunner:
    """
    Runs Cypher queries from the BloodHound Trail query library.

    Example:
        runner = QueryRunner()
        runner.connect()

        # List queries
        queries = runner.list_queries(category="lateral_movement")

        # Run query with variables
        result = runner.run_query(
            "owned-what-can-access",
            {"USER": "PETE@CORP.COM"}
        )

        # Export query for BloodHound paste
        cypher = runner.export_query("lateral-adminto-nonpriv")
    """

    def __init__(self, neo4j_config: Optional[Neo4jConfig] = None):
        self.config = neo4j_config or Neo4jConfig()
        self.driver = None
        self._queries: Dict[str, Query] = {}
        self._categories: Dict[str, List[str]] = {}
        self._pwned_users_cache: Optional[set] = None
        self._load_queries()

    def _load_queries(self):
        """Load all queries from JSON files."""
        self._queries, self._categories = load_all_queries()

    def connect(self) -> bool:
        """Establish Neo4j connection."""
        _logger.verbose("Attempting Neo4j connection", StepType.CONNECTION,
                        uri=self.config.uri, user=self.config.user)
        try:
            self.driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            _logger.info("Neo4j connection established", StepType.CONNECTION,
                         uri=self.config.uri)
            return True
        except AuthError:
            _logger.error("Neo4j authentication failed", StepType.CONNECTION,
                          user=self.config.user)
            print(f"[!] Neo4j authentication failed (user: {self.config.user})")
            return False
        except ServiceUnavailable:
            _logger.error("Neo4j not available", StepType.CONNECTION,
                          uri=self.config.uri)
            print(f"[!] Neo4j not available at {self.config.uri}")
            return False
        except Exception as e:
            _logger.error("Neo4j connection error", StepType.CONNECTION,
                          error=str(e))
            print(f"[!] Neo4j connection error: {e}")
            return False

    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()

    def get_pwned_users(self, force_refresh: bool = False) -> set:
        """
        Get set of pwned user names for highlighting.

        Returns:
            Set of user principal names that are marked as pwned
        """
        if self._pwned_users_cache is not None and not force_refresh:
            return self._pwned_users_cache

        if not self.driver:
            return set()

        try:
            with self.driver.session() as session:
                result = session.run(
                    "MATCH (u:User) WHERE u.pwned = true RETURN u.name AS name"
                )
                self._pwned_users_cache = {r["name"] for r in result if r["name"]}
        except Exception:
            self._pwned_users_cache = set()

        return self._pwned_users_cache

    def get_inventory(self) -> Dict[str, Any]:
        """
        Get BloodHound data inventory summary.

        Returns dict with counts and samples of:
        - domains, users, computers, groups
        - key relationships (AdminTo, CanRDP, etc.)
        """
        if not self.driver:
            return {}

        inventory = {
            "domains": [],
            "users": {"count": 0, "enabled": 0, "samples": []},
            "computers": {"count": 0, "samples": []},
            "groups": {"count": 0, "samples": []},
            "relationships": {},
        }

        try:
            with self.driver.session() as session:
                # Domains
                result = session.run(
                    "MATCH (d:Domain) RETURN d.name as name ORDER BY d.name"
                )
                inventory["domains"] = [r["name"] for r in result]

                # Users
                result = session.run("""
                    MATCH (u:User)
                    RETURN count(u) as total,
                           sum(CASE WHEN u.enabled = true THEN 1 ELSE 0 END) as enabled
                """)
                row = result.single()
                if row:
                    inventory["users"]["count"] = row["total"]
                    inventory["users"]["enabled"] = row["enabled"]

                # User samples (enabled, high value first)
                result = session.run("""
                    MATCH (u:User)
                    WHERE u.enabled = true
                    RETURN u.name as name, u.admincount as admincount
                    ORDER BY u.admincount DESC, u.name
                    LIMIT 10
                """)
                inventory["users"]["samples"] = [r["name"] for r in result]

                # Computers
                result = session.run("MATCH (c:Computer) RETURN count(c) as total")
                row = result.single()
                if row:
                    inventory["computers"]["count"] = row["total"]

                result = session.run("""
                    MATCH (c:Computer)
                    RETURN c.name as name
                    ORDER BY c.name
                    LIMIT 10
                """)
                inventory["computers"]["samples"] = [r["name"] for r in result]

                # Groups
                result = session.run("MATCH (g:Group) RETURN count(g) as total")
                row = result.single()
                if row:
                    inventory["groups"]["count"] = row["total"]

                result = session.run("""
                    MATCH (g:Group)
                    WHERE g.highvalue = true OR g.name CONTAINS 'ADMIN'
                    RETURN g.name as name
                    ORDER BY g.name
                    LIMIT 10
                """)
                inventory["groups"]["samples"] = [r["name"] for r in result]

                # Key relationships
                rel_queries = {
                    "AdminTo": "MATCH ()-[r:AdminTo]->() RETURN count(r) as c",
                    "CanRDP": "MATCH ()-[r:CanRDP]->() RETURN count(r) as c",
                    "CanPSRemote": "MATCH ()-[r:CanPSRemote]->() RETURN count(r) as c",
                    "HasSession": "MATCH ()-[r:HasSession]->() RETURN count(r) as c",
                    "MemberOf": "MATCH ()-[r:MemberOf]->() RETURN count(r) as c",
                    "GenericAll": "MATCH ()-[r:GenericAll]->() RETURN count(r) as c",
                    "WriteDacl": "MATCH ()-[r:WriteDacl]->() RETURN count(r) as c",
                    "DCSync": "MATCH (n)-[:GetChanges|GetChangesAll]->() RETURN count(DISTINCT n) as c",
                }
                for rel_type, query in rel_queries.items():
                    try:
                        result = session.run(query)
                        row = result.single()
                        if row and row["c"] > 0:
                            inventory["relationships"][rel_type] = row["c"]
                    except:
                        pass

        except Exception as e:
            inventory["error"] = str(e)

        return inventory

    def list_queries(
        self,
        category: Optional[str] = None,
        oscp_relevance: Optional[str] = None,
        tag: Optional[str] = None
    ) -> List[Query]:
        """
        List available queries with optional filtering.

        Args:
            category: Filter by category (e.g., "lateral_movement")
            oscp_relevance: Filter by relevance ("high", "medium", "low")
            tag: Filter by tag (e.g., "OSCP:HIGH")

        Returns:
            List of matching Query objects
        """
        queries = list(self._queries.values())

        if category:
            queries = [q for q in queries if q.category == category]

        if oscp_relevance:
            queries = [q for q in queries if q.oscp_relevance == oscp_relevance]

        if tag:
            tag_lower = tag.lower()
            queries = [
                q for q in queries
                if any(tag_lower in t.lower() for t in q.tags)
            ]

        return queries

    def get_categories(self) -> List[str]:
        """Get list of all query categories."""
        return list(self._categories.keys())

    def get_query(self, query_id: str) -> Optional[Query]:
        """Get a specific query by ID."""
        return self._queries.get(query_id)

    def search_queries(self, keyword: str) -> List[Query]:
        """
        Search queries by keyword in name, description, or tags.

        Args:
            keyword: Search term

        Returns:
            List of matching Query objects
        """
        keyword_lower = keyword.lower()
        matches = []

        for query in self._queries.values():
            if (
                keyword_lower in query.name.lower()
                or keyword_lower in query.description.lower()
                or keyword_lower in query.id.lower()
                or any(keyword_lower in tag.lower() for tag in query.tags)
            ):
                matches.append(query)

        return matches

    def run_query(
        self,
        query_id: str,
        variables: Optional[Dict[str, str]] = None,
        limit: int = 100
    ) -> QueryResult:
        """
        Execute a query from the library.

        Args:
            query_id: Query ID (e.g., "lateral-adminto-nonpriv")
            variables: Dict of variable substitutions (e.g., {"USER": "PETE@CORP.COM"})
            limit: Maximum records to return

        Returns:
            QueryResult with records or error
        """
        _logger.verbose("Running query", StepType.QUERYING,
                        query_id=query_id, variables=variables, limit=limit)

        query = self.get_query(query_id)
        if not query:
            _logger.warning("Query not found", StepType.QUERYING, query_id=query_id)
            return QueryResult(
                query_id=query_id,
                success=False,
                error=f"Query not found: {query_id}"
            )

        # Check required variables
        if query.has_variables():
            variables = variables or {}
            missing = [
                v for v in query.get_required_variables()
                if v not in variables
            ]
            if missing:
                return QueryResult(
                    query_id=query_id,
                    success=False,
                    error=f"Missing required variables: {', '.join(missing)}"
                )

        # Substitute variables
        cypher = query.cypher
        if variables:
            cypher = query.substitute_variables(variables)

        # Add LIMIT if not present
        if "LIMIT" not in cypher.upper():
            cypher = f"{cypher}\nLIMIT {limit}"

        # Connect if needed
        if not self.driver:
            if not self.connect():
                return QueryResult(
                    query_id=query_id,
                    success=False,
                    error="Failed to connect to Neo4j"
                )

        # Execute query
        try:
            with self.driver.session() as session:
                result = session.run(cypher)
                records = [dict(record) for record in result]

                _logger.info("Query completed", StepType.QUERYING,
                             query_id=query_id, records=len(records))
                return QueryResult(
                    query_id=query_id,
                    success=True,
                    records=records,
                    record_count=len(records),
                    cypher_executed=cypher
                )

        except Exception as e:
            _logger.error("Query failed", StepType.QUERYING,
                          query_id=query_id, error=str(e))
            return QueryResult(
                query_id=query_id,
                success=False,
                error=str(e),
                cypher_executed=cypher
            )

    def run_category(
        self,
        category: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Dict[str, QueryResult]:
        """
        Run all queries in a category.

        Args:
            category: Category name (e.g., "quick_wins")
            variables: Shared variables for queries that need them

        Returns:
            Dict mapping query IDs to their results
        """
        results = {}
        query_ids = self._categories.get(category, [])

        for query_id in query_ids:
            query = self.get_query(query_id)
            if query and not query.has_variables():
                # Only run queries that don't need variables
                results[query_id] = self.run_query(query_id, variables)
            elif query and variables:
                # Run if variables provided
                results[query_id] = self.run_query(query_id, variables)

        return results

    def export_query(
        self,
        query_id: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Optional[str]:
        """
        Export a query as raw Cypher for copy-paste into BloodHound.

        Args:
            query_id: Query ID
            variables: Optional variable substitutions

        Returns:
            Cypher query string or None if not found
        """
        query = self.get_query(query_id)
        if not query:
            return None

        cypher = query.cypher
        if variables:
            cypher = query.substitute_variables(variables)

        return cypher

    def format_results_table(
        self,
        result: QueryResult,
        max_width: int = 50,
        highlight_pwned: bool = True
    ) -> str:
        """
        Format query results as an ASCII table with optional pwned user highlighting.

        Args:
            result: QueryResult to format
            max_width: Maximum column width
            highlight_pwned: If True, highlight pwned users in green

        Returns:
            Formatted table string
        """
        if not result.success:
            return f"Error: {result.error}"

        if not result.records:
            return "No results found"

        # Get pwned users for highlighting
        pwned_users = self.get_pwned_users() if highlight_pwned else set()

        # ANSI codes for highlighting
        GREEN = '\033[92m'
        BOLD = '\033[1m'
        RESET = '\033[0m'

        # User-related column names (case-insensitive match)
        USER_COLUMNS = {
            'user', 'users', 'attacker', 'victim', 'target', 'principal',
            'pwneduser', 'pwnedwithaccess', 'newtargetusers', 'victimsession',
            'highvaluetarget', 'serviceaccount', 'member', 'gmsaaccount'
        }

        # Get column headers from first record
        headers = list(result.records[0].keys())

        # Identify user columns
        user_header_indices = {
            h for h in headers if h.lower() in USER_COLUMNS
        }

        # Pre-format all values (applies timestamp formatting)
        formatted_records = []
        for record in result.records:
            formatted = {}
            for h in headers:
                val = format_field_value(h, record.get(h, ""))
                formatted[h] = val
            formatted_records.append(formatted)

        # Calculate column widths using formatted values (without ANSI codes)
        widths = {}
        for h in headers:
            max_val_len = max(
                len(formatted[h][:max_width]) for formatted in formatted_records
            )
            widths[h] = min(
                max(len(str(h)), max_val_len),
                max_width
            )

        # Build table
        lines = []

        # Header
        header_line = " | ".join(h.ljust(widths[h])[:widths[h]] for h in headers)
        lines.append(header_line)
        lines.append("-" * len(header_line))

        # Rows with pwned highlighting
        pwned_count = 0
        for formatted in formatted_records:
            row = []
            for h in headers:
                val = formatted[h][:max_width]
                display_val = val.ljust(widths[h])[:widths[h]]

                # Highlight if this is a user column and user is pwned
                if h in user_header_indices and val in pwned_users:
                    display_val = f"{GREEN}{display_val}{RESET}"
                    pwned_count += 1

                row.append(display_val)
            lines.append(" | ".join(row))

        # Footer with pwned indicator if any found
        footer = f"\n({result.record_count} records)"
        if pwned_count > 0:
            footer += f" | {GREEN}{BOLD}{pwned_count} pwned user(s) highlighted{RESET}"
        lines.append(footer)

        return "\n".join(lines)


# =============================================================================
# BACKWARD COMPATIBILITY EXPORTS
# =============================================================================
# These re-exports maintain backward compatibility for code that imports
# directly from query_runner. New code should import from core/ or report_generator.

from .core.formatters import (  # noqa: E402, F401
    TIMESTAMP_FIELDS,
    format_timestamp_ago,
    is_timestamp_field,
    is_neo4j_path,
    get_node_name,
    format_neo4j_path,
    format_path_oneline,
)

from .report_generator import (  # noqa: E402, F401
    run_all_queries,
    print_query_info,
    export_to_bloodhound_customqueries,
    export_to_bloodhound_ce,
)
