"""
BloodHound Trail - Main Orchestration

Coordinates edge extraction from BloodHound JSON and batch import to Neo4j.
Supports both directory and ZIP file data sources.
"""

import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Union
from dataclasses import dataclass, field

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from .config import Neo4jConfig, DEFAULT_BATCH_SIZE, ATTACK_PATH_EDGES
from .logger import DebugLogger, Component, StepType

# Module-level debug logger
_logger = DebugLogger(component=Component.BT_IMPORT)
from .sid_resolver import SIDResolver
from .extractors import (
    EdgeExtractorRegistry,
    ExtractionResult,
    Edge,
    deduplicate_edges,
)
from .data_source import DataSource, create_data_source
from .ip_resolver import IPResolver
from .pwned_tracker import PwnedTracker
from .property_importer import PropertyImporter, PropertyImportStats


class Colors:
    """ANSI color codes for terminal output"""
    BOLD = '\033[1m'
    DIM = '\033[2m'
    HEADER = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'


@dataclass
class ImportStats:
    """Statistics from edge import"""
    edges_extracted: int = 0
    edges_deduplicated: int = 0
    edges_imported: int = 0
    edges_skipped: int = 0
    edges_failed: int = 0
    edges_already_existed: int = 0  # Edges that were merged (already existed)
    batches_processed: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)
    failed_samples: List[Dict] = field(default_factory=list)  # Sample of failed edges

    def summary(self) -> str:
        """Plain text summary"""
        return (
            f"Extracted: {self.edges_extracted}, "
            f"Deduplicated: {self.edges_deduplicated}, "
            f"Imported: {self.edges_imported}, "
            f"Failed: {max(0, self.edges_failed)}, "
            f"Time: {self.duration_seconds:.2f}s"
        )

    def print_colored_summary(self):
        """Print colorized detailed summary"""
        C = Colors
        unique = self.edges_extracted - self.edges_deduplicated
        failed = max(0, self.edges_failed)  # Ensure non-negative
        total_processed = self.edges_imported + self.edges_already_existed

        print()
        print(f"{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════════════╗{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}║{C.RESET}              {C.BOLD}BloodHound Trail - Import Summary{C.RESET}                      {C.BOLD}{C.CYAN}║{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════════════════════╝{C.RESET}")
        print()

        # Extraction stats
        print(f"  {C.BOLD}Extraction:{C.RESET}")
        print(f"  {C.DIM}{'─' * 50}{C.RESET}")
        print(f"    {C.CYAN}Extracted from JSON:{C.RESET}     {C.BOLD}{self.edges_extracted:>6}{C.RESET}")
        print(f"    {C.YELLOW}Duplicates removed:{C.RESET}      {C.DIM}{self.edges_deduplicated:>6}{C.RESET}")
        print(f"    {C.CYAN}Unique edges to process:{C.RESET} {C.BOLD}{unique:>6}{C.RESET}")
        print()

        # Import results
        print(f"  {C.BOLD}Neo4j Import Results:{C.RESET}")
        print(f"  {C.DIM}{'─' * 50}{C.RESET}")

        # Processed (matched nodes)
        if total_processed > 0:
            print(f"    {C.GREEN}✓ Edges processed:{C.RESET}       {C.BOLD}{C.GREEN}{total_processed:>6}{C.RESET}")
        else:
            print(f"    {C.RED}✗ Edges processed:{C.RESET}       {C.BOLD}{C.RED}{total_processed:>6}{C.RESET}")

        # Breakdown: newly created vs already existed
        if self.edges_imported > 0:
            print(f"      {C.GREEN}↳ Newly created:{C.RESET}      {C.GREEN}{self.edges_imported:>6}{C.RESET}")
        else:
            print(f"      {C.DIM}↳ Newly created:{C.RESET}      {C.DIM}{self.edges_imported:>6}{C.RESET}")

        if self.edges_already_existed > 0:
            print(f"      {C.BLUE}↳ Already existed:{C.RESET}    {C.BLUE}{self.edges_already_existed:>6}{C.RESET}")
        else:
            print(f"      {C.DIM}↳ Already existed:{C.RESET}    {C.DIM}{self.edges_already_existed:>6}{C.RESET}")

        # Failed (nodes not found)
        if failed > 0:
            print(f"    {C.RED}✗ Failed (nodes missing):{C.RESET}{C.RED}{failed:>6}{C.RESET}")
        else:
            print(f"    {C.DIM}  Failed (nodes missing):{C.RESET}{C.DIM}{failed:>6}{C.RESET}")

        print(f"  {C.DIM}{'─' * 50}{C.RESET}")
        print(f"    {C.DIM}Batches processed:{C.RESET}        {self.batches_processed:>6}")
        print(f"    {C.DIM}Duration:{C.RESET}                 {self.duration_seconds:>5.2f}s")
        print()

        # Success/failure indicator
        if total_processed > 0 and failed == 0:
            if self.edges_imported > 0 and self.edges_already_existed > 0:
                print(f"  {C.GREEN}{C.BOLD}✓ All edges processed!{C.RESET} ({C.GREEN}{self.edges_imported} new{C.RESET}, {C.BLUE}{self.edges_already_existed} existed{C.RESET})")
            elif self.edges_imported > 0:
                print(f"  {C.GREEN}{C.BOLD}✓ All {self.edges_imported} edges newly created!{C.RESET}")
            else:
                print(f"  {C.BLUE}{C.BOLD}✓ All {self.edges_already_existed} edges already existed in Neo4j{C.RESET}")
        elif total_processed > 0:
            pct = (total_processed / unique * 100) if unique > 0 else 0
            print(f"  {C.YELLOW}⚠ Partial success: {pct:.1f}% of edges processed{C.RESET}")
        else:
            print(f"  {C.RED}{C.BOLD}✗ No edges processed - see diagnostics below{C.RESET}")
        print()


@dataclass
class Neo4jDiagnostics:
    """Diagnostic info about Neo4j database state"""
    connected: bool = False
    total_nodes: int = 0
    users: int = 0
    computers: int = 0
    groups: int = 0
    domains: int = 0
    existing_edges: Dict[str, int] = field(default_factory=dict)
    all_labels: Dict[str, int] = field(default_factory=dict)  # All node labels
    sample_user: Optional[str] = None
    sample_computer: Optional[str] = None
    is_bloodhound_ce: bool = False  # CE uses different schema
    error: Optional[str] = None


class BatchExecutor:
    """
    Executes batched Neo4j edge creation.

    Uses UNWIND for efficient bulk imports with proper error handling.
    """

    def __init__(self, driver, batch_size: int = DEFAULT_BATCH_SIZE):
        self.driver = driver
        self.batch_size = batch_size
        self.stats = ImportStats()

    def create_edges(self, edges: List[Edge], verbose: bool = False) -> ImportStats:
        """
        Bulk create edges in Neo4j using batched UNWIND queries.

        Args:
            edges: List of Edge objects to create
            verbose: Print progress messages

        Returns:
            ImportStats with results
        """
        start_time = time.time()
        self.stats = ImportStats()
        self.stats.edges_extracted = len(edges)

        # Deduplicate
        unique_edges = deduplicate_edges(edges)
        self.stats.edges_deduplicated = len(edges) - len(unique_edges)

        # Group edges by type for efficient batch processing
        edges_by_type: Dict[str, List[Edge]] = {}
        for edge in unique_edges:
            if edge.edge_type not in edges_by_type:
                edges_by_type[edge.edge_type] = []
            edges_by_type[edge.edge_type].append(edge)

        # Process each edge type
        for edge_type, type_edges in edges_by_type.items():
            if verbose:
                print(f"  Importing {len(type_edges)} {edge_type} edges...")

            self._import_edge_batch(edge_type, type_edges, verbose)

        self.stats.duration_seconds = time.time() - start_time
        return self.stats

    def _import_edge_batch(
        self,
        edge_type: str,
        edges: List[Edge],
        verbose: bool
    ):
        """Import a batch of edges of the same type"""
        # Process in batches
        for i in range(0, len(edges), self.batch_size):
            batch = edges[i:i + self.batch_size]
            self.stats.batches_processed += 1

            # Convert to dict format for Neo4j parameters
            edge_data = [
                {"source": e.source, "target": e.target, "props": e.properties}
                for e in batch
            ]

            # Dynamic query based on edge type
            # First check which edges already exist, then merge
            # Two-step approach for accurate counting
            query = f"""
            UNWIND $edges AS edge
            MATCH (source {{name: edge.source}})
            MATCH (target {{name: edge.target}})
            OPTIONAL MATCH (source)-[existing:{edge_type}]->(target)
            WITH source, target, edge, existing IS NOT NULL AS already_exists
            MERGE (source)-[r:{edge_type}]->(target)
            ON CREATE SET r += edge.props
            RETURN
                count(r) AS processed,
                sum(CASE WHEN already_exists THEN 0 ELSE 1 END) AS newly_created,
                sum(CASE WHEN already_exists THEN 1 ELSE 0 END) AS already_existed
            """

            try:
                with self.driver.session() as session:
                    result = session.run(query, edges=edge_data)
                    record = result.single()

                    if record is None:
                        # No matches at all - all edges failed
                        self.stats.edges_failed += len(batch)
                        if verbose:
                            print(f"    {Colors.RED}⚠{Colors.RESET} {edge_type}: 0/{len(batch)} (no matching nodes)")
                    else:
                        processed = int(record["processed"] or 0)
                        newly_created = int(record["newly_created"] or 0)
                        already_existed = int(record["already_existed"] or 0)

                        self.stats.edges_imported += newly_created
                        self.stats.edges_already_existed += already_existed
                        # Edges that didn't match nodes (source or target not found)
                        # Use min(processed, len(batch)) to avoid negative failed counts
                        failed = max(0, len(batch) - min(processed, len(batch)))
                        self.stats.edges_failed += failed

                        if verbose:
                            status = f"{Colors.GREEN}✓{Colors.RESET}" if processed > 0 else f"{Colors.RED}✗{Colors.RESET}"
                            print(f"    {status} {edge_type}: {processed}/{len(batch)} ({newly_created} new, {already_existed} existed)")

            except Exception as e:
                self.stats.errors.append(f"{edge_type} batch {i//self.batch_size}: {e}")
                self.stats.edges_failed += len(batch)
                if verbose:
                    print(f"    {Colors.RED}✗{Colors.RESET} {edge_type}: error - {str(e)[:50]}")


class BHEnhancer:
    """
    Main orchestrator for BloodHound edge enhancement.

    Supports both directory and ZIP file data sources.

    Example:
        enhancer = BHEnhancer(
            bh_data_dir=Path("/path/to/bh/json"),
            neo4j_config=Neo4jConfig()
        )
        stats = enhancer.run(preset="attack-paths", verbose=True)

        # Or with ZIP file:
        enhancer = BHEnhancer(
            bh_data_dir=Path("/path/to/sharphound_output.zip"),
            neo4j_config=Neo4jConfig()
        )
    """

    def __init__(
        self,
        bh_data_dir: Union[Path, DataSource],
        neo4j_config: Optional[Neo4jConfig] = None
    ):
        # Store original path for display
        if isinstance(bh_data_dir, DataSource):
            self.data_source = bh_data_dir
            self.bh_data_dir = bh_data_dir.source_path
        else:
            self.bh_data_dir = Path(bh_data_dir)
            self.data_source = None  # Created lazily in initialize()

        self.config = neo4j_config or Neo4jConfig()
        self.driver = None
        self.resolver = None
        self.registry = None

    def connect(self) -> bool:
        """Establish Neo4j connection"""
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
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()

    def diagnose_neo4j(self) -> Neo4jDiagnostics:
        """
        Check Neo4j database state before import.

        Returns diagnostics about what nodes/edges exist.
        """
        diag = Neo4jDiagnostics()

        if not self.driver:
            if not self.connect():
                diag.error = "Cannot connect to Neo4j"
                return diag

        diag.connected = True

        try:
            with self.driver.session() as session:
                # Count nodes by label
                result = session.run("MATCH (n) RETURN count(n) as total")
                diag.total_nodes = result.single()["total"]

                result = session.run("MATCH (u:User) RETURN count(u) as c")
                diag.users = result.single()["c"]

                result = session.run("MATCH (c:Computer) RETURN count(c) as c")
                diag.computers = result.single()["c"]

                result = session.run("MATCH (g:Group) RETURN count(g) as c")
                diag.groups = result.single()["c"]

                result = session.run("MATCH (d:Domain) RETURN count(d) as c")
                diag.domains = result.single()["c"]

                # Sample user/computer names to check format
                result = session.run("MATCH (u:User) RETURN u.name as name LIMIT 1")
                rec = result.single()
                if rec and rec["name"]:
                    diag.sample_user = rec["name"]

                result = session.run("MATCH (c:Computer) RETURN c.name as name LIMIT 1")
                rec = result.single()
                if rec and rec["name"]:
                    diag.sample_computer = rec["name"]

                # Check if BloodHound CE (uses objectId instead of name)
                result = session.run(
                    "MATCH (n) WHERE n.objectId IS NOT NULL RETURN count(n) as c LIMIT 1"
                )
                ce_count = result.single()["c"]
                if ce_count > 0 and diag.total_nodes > 0:
                    diag.is_bloodhound_ce = True

                # Get all node labels with counts
                result = session.run("""
                    CALL db.labels() YIELD label
                    CALL {
                        WITH label
                        MATCH (n) WHERE label IN labels(n)
                        RETURN count(n) as cnt
                    }
                    RETURN label, cnt ORDER BY cnt DESC LIMIT 10
                """)
                for rec in result:
                    diag.all_labels[rec["label"]] = rec["cnt"]

                # Count existing edge types
                edge_types = ["AdminTo", "MemberOf", "HasSession", "CanRDP",
                             "CanPSRemote", "ExecuteDCOM", "GenericAll", "WriteDacl"]
                for etype in edge_types:
                    result = session.run(f"MATCH ()-[r:{etype}]->() RETURN count(r) as c")
                    count = result.single()["c"]
                    if count > 0:
                        diag.existing_edges[etype] = count

        except Exception as e:
            diag.error = str(e)

        return diag

    def check_node_exists(self, name: str) -> Optional[str]:
        """Check if a node exists and return its labels"""
        if not self.driver:
            return None
        try:
            with self.driver.session() as session:
                result = session.run(
                    "MATCH (n {name: $name}) RETURN labels(n) as labels",
                    name=name
                )
                rec = result.single()
                if rec:
                    return ", ".join(rec["labels"])
        except:
            pass
        return None

    def initialize(self) -> bool:
        """Initialize data source, resolver and registry"""
        C = Colors
        _logger.verbose("Initializing data source", StepType.INIT,
                        path=str(self.bh_data_dir))
        try:
            # Create data source if not already provided
            if self.data_source is None:
                self.data_source = create_data_source(self.bh_data_dir)

            source_type = self.data_source.source_type
            source_label = "ZIP file" if source_type == "zip" else "directory"

            print(f"{C.CYAN}[*]{C.RESET} Loading SIDs from {source_label} {C.BOLD}{self.bh_data_dir}{C.RESET}...")
            self.resolver = SIDResolver(self.data_source)
            _logger.info("SID mappings loaded", StepType.PARSING,
                         sid_count=len(self.resolver), source_type=source_type)
            print(f"{C.GREEN}[+]{C.RESET} Loaded {C.BOLD}{len(self.resolver)}{C.RESET} SID mappings")

            self.registry = EdgeExtractorRegistry(self.resolver)
            _logger.verbose("Initialization complete", StepType.INIT)
            return True
        except FileNotFoundError as e:
            _logger.error("Data source not found", StepType.INIT, error=str(e))
            print(f"{C.RED}[!]{C.RESET} {e}")
            return False
        except Exception as e:
            _logger.error("Initialization error", StepType.INIT, error=str(e))
            print(f"{C.RED}[!]{C.RESET} Initialization error: {e}")
            return False

    def run(
        self,
        preset: Optional[str] = None,
        edge_filter: Optional[Set[str]] = None,
        dry_run: bool = False,
        verbose: bool = False,
        dc_ip: Optional[str] = None,
        clean_ips: bool = True,
        import_properties: bool = True,
        properties_only: bool = False
    ) -> ImportStats:
        """
        Run the edge enhancement pipeline.

        Args:
            preset: "attack-paths" for attack-path focused edges, None for all
            edge_filter: Specific edge types to extract (overrides preset)
            dry_run: Extract but don't import (validation mode)
            verbose: Print detailed progress
            dc_ip: Optional DC IP for DNS resolution and command placeholder population
            clean_ips: If True, clear all IPs before regenerating (default, --clean mode).
                       If False, incremental update (--update mode)
            import_properties: If True, import node properties (hasspn, etc.) before edges
            properties_only: If True, only import properties (skip edge extraction)

        Returns:
            ImportStats with results
        """
        C = Colors
        stats = ImportStats()

        # Initialize
        if not self.initialize():
            return stats

        # Properties-only mode: skip edge extraction
        result = None
        if not properties_only:
            # Determine edge filter
            if edge_filter:
                filter_set = edge_filter
            elif preset == "attack-paths":
                filter_set = ATTACK_PATH_EDGES
                print(f"{C.CYAN}[*]{C.RESET} Using {C.BOLD}attack-paths{C.RESET} preset ({C.CYAN}{len(filter_set)}{C.RESET} edge types)")
            else:
                filter_set = None  # All edges

            # Extract edges
            source_label = "ZIP" if self.data_source.source_type == "zip" else "directory"
            print(f"{C.CYAN}[*]{C.RESET} Extracting edges from {source_label} {C.BOLD}{self.bh_data_dir}{C.RESET}...")
            result = self.registry.extract_from_source(
                self.data_source,
                edge_filter=filter_set
            )

            stats.edges_extracted = result.edge_count
            if result.errors:
                stats.errors.extend(result.errors)

            # Summary by edge type (always show, more verbose)
            edge_counts: Dict[str, int] = {}
            for edge in result.edges:
                edge_counts[edge.edge_type] = edge_counts.get(edge.edge_type, 0) + 1

            print(f"{C.GREEN}[+]{C.RESET} Extracted {C.BOLD}{C.GREEN}{result.edge_count}{C.RESET} edges:")
            for etype, count in sorted(edge_counts.items(), key=lambda x: -x[1]):
                print(f"    {C.CYAN}•{C.RESET} {etype}: {C.BOLD}{count}{C.RESET}")

            if result.skipped:
                print(f"{C.YELLOW}[*]{C.RESET} Skipped {C.YELLOW}{result.skipped}{C.RESET} edges (filtered out)")

            # Dry run - stop here
            if dry_run:
                print(f"{C.GREEN}[*]{C.RESET} Dry run complete. Would import {C.BOLD}{result.edge_count}{C.RESET} edges.")
                return stats

        # Connect to Neo4j
        print(f"{C.CYAN}[*]{C.RESET} Connecting to Neo4j at {C.BOLD}{self.config.uri}{C.RESET}...")
        if not self.connect():
            return stats
        print(f"{C.GREEN}[+]{C.RESET} Connected to Neo4j")

        try:
            # Import node properties (enables quick-wins queries like Kerberoasting)
            if import_properties:
                print(f"\n{C.CYAN}[*]{C.RESET} Importing node properties...")
                prop_importer = PropertyImporter(self.driver, self.config.batch_size)
                prop_stats = prop_importer.import_from_source(self.data_source, verbose=verbose)
                prop_stats.print_summary()

                # If properties_only mode, skip edge import
                if properties_only:
                    print(f"{C.GREEN}[+]{C.RESET} Properties-only mode complete.")
                    return stats

            # Import edges (only if we have edges to import)
            if result is not None and result.edges:
                print(f"{C.CYAN}[*]{C.RESET} Importing edges to Neo4j...")
                executor = BatchExecutor(self.driver, self.config.batch_size)
                import_stats = executor.create_edges(result.edges, verbose=verbose)

                # Merge stats
                stats.edges_imported = import_stats.edges_imported
                stats.edges_already_existed = import_stats.edges_already_existed
                stats.edges_failed = import_stats.edges_failed
                stats.edges_deduplicated = import_stats.edges_deduplicated
                stats.batches_processed = import_stats.batches_processed
                stats.duration_seconds = import_stats.duration_seconds
                stats.errors.extend(import_stats.errors)

                # Use colored summary
                stats.print_colored_summary()

                if import_stats.errors and verbose:
                    print(f"{C.RED}[!]{C.RESET} Errors encountered:")
                    for err in import_stats.errors[:5]:
                        print(f"    {C.RED}•{C.RESET} {err}")

            # NEW: IP Address Enrichment
            # Only if edges were successfully imported
            if result is not None and (stats.edges_imported > 0 or stats.edges_already_existed > 0):
                print()
                print(f"{C.CYAN}[*]{C.RESET} Resolving IP addresses for Computer nodes...")

                # Extract computer names from edges
                computer_names = self._extract_computer_names(result.edges)

                if computer_names:
                    if verbose:
                        print(f"    Found {C.BOLD}{len(computer_names)}{C.RESET} unique computers")

                    # Clear existing IPs if --clean mode AND we have dc_ip to resolve new ones
                    if dc_ip and clean_ips and not dry_run:
                        cleared_count, _ = self._clear_all_ips(verbose=verbose)

                    # Resolve IPs in parallel (only if DC provided as DNS server)
                    if dc_ip:
                        resolver = IPResolver(timeout=2.0, max_workers=20, dc_ip=dc_ip)
                        ip_mappings = resolver.resolve_batch(list(computer_names))

                        # Store IPs in Neo4j
                        enriched_count = self._enrich_ips(ip_mappings, verbose=verbose)

                        # Show stats
                        if enriched_count > 0:
                            res_stats = resolver.get_stats()
                            mode = "clean" if clean_ips else "update"
                            print(f"{C.GREEN}[+]{C.RESET} IP Enrichment complete ({mode} mode):")
                            print(f"    {C.GREEN}Resolved:{C.RESET}  {res_stats['resolved']}")
                            print(f"    {C.DIM}Failed:{C.RESET}     {res_stats['failed']}")
                            print(f"    {C.DIM}Cached:{C.RESET}     {res_stats['cached']}")

                            # Print detailed list of resolved IPs
                            if verbose:
                                resolved_ips = [(fqdn, ip) for fqdn, ip in ip_mappings.items() if ip is not None]
                                if resolved_ips:
                                    print(f"\n{C.CYAN}[*]{C.RESET} Resolved {C.BOLD}{len(resolved_ips)}{C.RESET} Computer IPs:")
                                    for computer, ip in sorted(resolved_ips):
                                        print(f"    {C.DIM}{computer:40}{C.RESET} {C.GREEN}{ip}{C.RESET}")
                else:
                    if verbose:
                        print(f"    {C.YELLOW}No computers found in edges{C.RESET}")

                # Store DC IP in Neo4j if provided (dual-purpose: DNS + command placeholder)
                if dc_ip and not dry_run:
                    try:
                        tracker = PwnedTracker(self.config)
                        if tracker.connect():
                            dc_result = tracker.set_dc_ip(dc_ip=dc_ip)
                            if dc_result.success:
                                if verbose:
                                    print(f"{C.GREEN}[+]{C.RESET} DC IP stored: {dc_ip}")
                            tracker.close()
                    except Exception as e:
                        if verbose:
                            print(f"{C.YELLOW}[!]{C.RESET} Could not store DC IP: {e}")

            # If many failures, run diagnostics and show helpful output
            if import_stats.edges_failed > 0 and import_stats.edges_imported == 0:
                self._print_failure_diagnostics(result.edges)

        finally:
            self.close()

        return stats

    def _extract_computer_names(self, edges: List[Edge]) -> Set[str]:
        """
        Extract unique computer FQDNs from edges.

        Looks for Computer nodes in both source and target of edges.
        Used to build list of computers for IP resolution.

        Args:
            edges: List of Edge objects from BloodHound data

        Returns:
            Set of unique computer FQDNs (e.g., {"FILES04.CORP.COM", "DC1.CORP.COM", ...})
        """
        computers = set()

        for edge in edges:
            # Extract computers from edge endpoints
            # Computer nodes are typically targets of AdminTo, CanRDP, etc.
            # or sources of HasSession
            # We identify them by checking if name looks like FQDN (contains dot)

            # Check source principal
            if edge.source and '.' in edge.source:
                # Likely a computer FQDN (e.g., DC1.CORP.COM)
                # Filter out SIDs and ObjectGUIDs
                if not edge.source.startswith('S-1-') and '@' not in edge.source:
                    computers.add(edge.source)

            # Check target principal
            if edge.target and '.' in edge.target:
                if not edge.target.startswith('S-1-') and '@' not in edge.target:
                    computers.add(edge.target)

        return computers

    def _enrich_ips(self, ip_mappings: Dict[str, Optional[str]], verbose: bool = False):
        """
        Enrich Neo4j Computer nodes with resolved IP addresses.

        Sets custom properties on Computer nodes:
        - bloodtrail_ip: IPv4 address (e.g., "10.0.0.15")
        - bloodtrail_ip_resolved_at: Timestamp of resolution

        Args:
            ip_mappings: Dict mapping computer FQDN -> IP address
            verbose: Print detailed progress

        Returns:
            Number of computers enriched
        """
        C = Colors

        if not ip_mappings:
            if verbose:
                print(f"{C.YELLOW}[*]{C.RESET} No computers to enrich")
            return 0

        # Count successful resolutions
        successful = sum(1 for ip in ip_mappings.values() if ip is not None)
        failed = len(ip_mappings) - successful

        if verbose:
            print(f"{C.CYAN}[*]{C.RESET} Enriching Neo4j with IP addresses...")
            print(f"    Resolved: {C.GREEN}{successful}{C.RESET} computers")
            print(f"    Failed:   {C.DIM}{failed}{C.RESET} computers (will use FQDN)")

        # Batch update Neo4j (only for successfully resolved IPs)
        enriched_count = 0
        try:
            with self.driver.session() as session:
                # Prepare batch data (only include successful resolutions)
                batch_data = [
                    {"fqdn": fqdn, "ip": ip}
                    for fqdn, ip in ip_mappings.items()
                    if ip is not None
                ]

                if not batch_data:
                    if verbose:
                        print(f"{C.YELLOW}[*]{C.RESET} No IPs resolved successfully")
                    return 0

                # Batch Cypher query to set IP properties
                query = """
                UNWIND $computers AS comp
                MATCH (c:Computer {name: comp.fqdn})
                SET c.bloodtrail_ip = comp.ip,
                    c.bloodtrail_ip_resolved_at = timestamp()
                RETURN count(c) AS enriched
                """

                result = session.run(query, computers=batch_data)
                record = result.single()
                if record:
                    enriched_count = record["enriched"]

                if verbose and enriched_count > 0:
                    print(f"{C.GREEN}[+]{C.RESET} Enriched {C.BOLD}{enriched_count}{C.RESET} Computer nodes with IPs")

        except Exception as e:
            if verbose:
                print(f"{C.RED}[!]{C.RESET} IP enrichment error: {e}")
            return 0

        return enriched_count

    def _clear_all_ips(self, verbose: bool = False) -> tuple[int, List[tuple[str, str]]]:
        """
        Clear all bloodtrail_ip properties from Computer nodes.

        Used in --clean mode to ensure fresh slate before IP regeneration.

        Args:
            verbose: Print detailed output

        Returns:
            Tuple of (count of cleared nodes, list of (computer_name, ip) pairs that were cleared)
        """
        C = Colors

        if not self.driver:
            return (0, [])

        try:
            with self.driver.session() as session:
                # Get list of computers with IPs before clearing
                result = session.run("""
                    MATCH (c:Computer)
                    WHERE c.bloodtrail_ip IS NOT NULL
                    RETURN c.name AS name, c.bloodtrail_ip AS ip
                    ORDER BY c.name
                """)

                cleared_ips = [(record["name"], record["ip"]) for record in result]

                if not cleared_ips:
                    return (0, [])

                # Clear all IPs
                result = session.run("""
                    MATCH (c:Computer)
                    WHERE c.bloodtrail_ip IS NOT NULL
                    REMOVE c.bloodtrail_ip, c.bloodtrail_ip_resolved_at
                    RETURN count(c) AS cleared
                """)

                record = result.single()
                cleared = record["cleared"] if record else 0

                if verbose and cleared > 0:
                    print(f"{C.YELLOW}[*]{C.RESET} Cleared {C.BOLD}{cleared}{C.RESET} existing IPs (--clean mode)")
                    for computer, ip in cleared_ips:
                        print(f"    {C.DIM}{computer:40}{C.RESET} {C.YELLOW}{ip}{C.RESET}")

                return (cleared, cleared_ips)

        except Exception as e:
            if verbose:
                print(f"{C.RED}[!]{C.RESET} Failed to clear IPs: {e}")
            return (0, [])

    def _print_failure_diagnostics(self, edges: List[Edge]):
        """Print detailed diagnostics when all imports fail"""
        print()
        print("=" * 70)
        print("[!] DIAGNOSTIC: All edge imports failed")
        print("=" * 70)
        print()

        # Run Neo4j diagnostics
        diag = self.diagnose_neo4j()

        print(f"[*] Neo4j Database State:")
        print(f"    Total nodes:  {diag.total_nodes}")
        print(f"    Users:        {diag.users}")
        print(f"    Computers:    {diag.computers}")
        print(f"    Groups:       {diag.groups}")
        print(f"    Domains:      {diag.domains}")

        if diag.all_labels:
            print(f"    All node labels (top 10):")
            for label, count in diag.all_labels.items():
                marker = "  ← BloodHound" if label in ("User", "Computer", "Group", "Domain") else ""
                print(f"      {label}: {count}{marker}")

        if diag.existing_edges:
            print(f"    Existing edges:")
            for etype, count in sorted(diag.existing_edges.items()):
                print(f"      {etype}: {count}")

        # Check a few sample edges
        print()
        print("[*] Checking sample edges from JSON:")
        samples = edges[:5]
        for edge in samples:
            source_exists = self.check_node_exists(edge.source)
            target_exists = self.check_node_exists(edge.target)

            source_status = f"✓ ({source_exists})" if source_exists else "✗ NOT FOUND"
            target_status = f"✓ ({target_exists})" if target_exists else "✗ NOT FOUND"

            print(f"    {edge.edge_type}: {edge.source[:40]}...")
            print(f"      Source: {source_status}")
            print(f"      Target: {target_exists and f'✓ ({target_exists})' or '✗ NOT FOUND'}")

        # Determine likely cause and show recipe
        print()
        print("=" * 70)
        print("[*] LIKELY CAUSE & SOLUTION:")
        print("=" * 70)

        if diag.total_nodes == 0:
            print("""
    ❌ CAUSE: Neo4j database is EMPTY - no BloodHound data imported

    📋 RECIPE:
    1. Start BloodHound GUI and import your SharpHound/BloodHound data:
       bloodhound

    2. In BloodHound, use File > Upload Data to import your ZIP files

    3. Verify data loaded:
       cypher-shell -u neo4j -p $NEO4J_PASSWORD "MATCH (n) RETURN count(n)"

    4. Re-run bloodtrail:
       crack bloodtrail /path/to/bh/json/ --preset attack-paths
""")
        elif diag.total_nodes > 0 and diag.users == 0 and diag.computers == 0:
            print(f"""
    ❌ CAUSE: Neo4j has {diag.total_nodes} nodes but NO BloodHound data

    The database contains data, but not BloodHound nodes (User, Computer, Group).
    This could be:
    - Data from a different application (crack-electron, custom graph, etc.)
    - BloodHound CE data with different schema
    - Corrupted or incomplete import

    📋 RECIPE:
    1. Clear the database and reimport BloodHound data:
       # In cypher-shell:
       MATCH (n) DETACH DELETE n

    2. Start BloodHound and import your collection:
       bloodhound

    3. Re-run bloodtrail:
       crack bloodtrail /path/to/bh/json/ --preset attack-paths
""")
        elif diag.is_bloodhound_ce:
            print("""
    ❌ CAUSE: BloodHound CE detected (uses different schema)

    BloodHound CE uses 'objectId' property instead of 'name'.
    This tool currently supports BloodHound Legacy only.

    📋 OPTIONS:
    1. Use BloodHound Legacy (4.x) instead of CE
    2. Query directly with CE-compatible Cypher:
       crack bloodtrail --list-queries
       (Then manually adapt queries for CE schema)
""")
        elif diag.sample_user and not diag.sample_user.endswith(("@" + diag.sample_user.split("@")[-1] if "@" in (diag.sample_user or "") else "")):
            print(f"""
    ⚠️  CAUSE: Node name format mismatch

    Sample user in Neo4j: {diag.sample_user}
    Sample computer:      {diag.sample_computer}

    The JSON edges may use different naming (e.g., missing domain suffix).

    📋 RECIPE:
    1. Check your SharpHound collection matches the BloodHound import
    2. Ensure domain suffix consistency (USER@DOMAIN.COM format)
""")
        else:
            print(f"""
    ⚠️  CAUSE: Node names in JSON don't match Neo4j nodes

    Sample user in Neo4j:     {diag.sample_user}
    Sample computer in Neo4j: {diag.sample_computer}

    📋 RECIPE:
    1. Verify BloodHound data was imported from the SAME collection:
       cypher-shell -u neo4j -p $NEO4J_PASSWORD \\
         "MATCH (u:User) RETURN u.name LIMIT 5"

    2. Check if names match your JSON files

    3. If using different collections, re-import matching data to BloodHound

    📋 QUICK TEST:
       crack bloodtrail --validate
       crack bloodtrail /path/to/json --dry-run --verbose
""")

    def validate(self, verbose: bool = False) -> Dict:
        """
        Validate BloodHound data without importing.

        Returns summary of what would be imported.
        """
        if not self.initialize():
            return {"error": "Failed to initialize"}

        result = self.registry.extract_from_source(self.data_source)

        # Count by type
        edge_counts: Dict[str, int] = {}
        for edge in result.edges:
            edge_counts[edge.edge_type] = edge_counts.get(edge.edge_type, 0) + 1

        # Check resolver stats
        resolver_stats = self.resolver.get_stats()

        return {
            "total_edges": result.edge_count,
            "edges_by_type": edge_counts,
            "extraction_errors": result.errors,
            "resolver_stats": resolver_stats,
            "supported_edge_types": list(self.registry.get_all_edge_types()),
        }


def quick_enhance(
    bh_dir: str,
    uri: str = "bolt://localhost:7687",
    user: str = "neo4j",
    password: str = "",
    preset: str = "attack-paths"
) -> ImportStats:
    """
    Quick enhancement function for one-liner usage.

    Example:
        from bloodtrail import quick_enhance
        stats = quick_enhance("/path/to/bh/json")
    """
    config = Neo4jConfig(uri=uri, user=user, password=password)
    enhancer = BHEnhancer(Path(bh_dir), config)
    return enhancer.run(preset=preset, verbose=True)
