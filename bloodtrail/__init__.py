"""
BloodHound Trail - Edge Enhancement & Query Analysis

Dynamically populates missing Neo4j edges from BloodHound JSON exports,
enabling complete attack path discovery via Cypher queries.

Features:
  - Property Import: Import node properties (hasspn, dontreqpreauth, etc.)
    for Kerberoasting, AS-REP roasting, and delegation detection
  - Edge Enhancement: Import missing edges (AdminTo, GenericAll, MemberOf, etc.)
  - Query Library: 63+ pre-built Cypher queries for attack path discovery
  - Query Runner: Execute queries via CLI or programmatically
  - ZIP Support: Process SharpHound ZIP output directly (no extraction needed)

Credentials:
  - Neo4j:      Set via NEO4J_PASSWORD environment variable
  - BloodHound: Set via BloodHound UI

Usage:
    # Full import (properties + edges)
    crack bloodtrail /path/to/bh/json/ --preset attack-paths

    # Properties only (fast Kerberoasting/AS-REP detection)
    crack bloodtrail /path/to/bh/json/ --properties-only

    # Edges only (skip property import)
    crack bloodtrail /path/to/bh/json/ --no-properties

    # Query library
    crack bloodtrail --list-queries
    crack bloodtrail --run-query lateral-adminto-nonpriv
    crack bloodtrail --search-query DCSync
"""

__version__ = "1.3.0"
__author__ = "OSCP Study"

from .sid_resolver import SIDResolver
from .extractors import (
    ComputerEdgeExtractor,
    ACEExtractor,
    GroupMembershipExtractor,
)
from .main import BHEnhancer
from .query_runner import QueryRunner, Query, QueryResult
from .data_source import (
    DataSource,
    DirectoryDataSource,
    ZipDataSource,
    create_data_source,
    is_valid_bloodhound_source,
)
from .property_importer import PropertyImporter, PropertyImportStats

__all__ = [
    "SIDResolver",
    "ComputerEdgeExtractor",
    "ACEExtractor",
    "GroupMembershipExtractor",
    "BHEnhancer",
    "QueryRunner",
    "Query",
    "QueryResult",
    "DataSource",
    "DirectoryDataSource",
    "ZipDataSource",
    "create_data_source",
    "is_valid_bloodhound_source",
    "PropertyImporter",
    "PropertyImportStats",
]
