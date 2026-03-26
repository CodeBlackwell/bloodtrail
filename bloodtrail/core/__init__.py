"""
BloodTrail Core Module

Extracted models, formatters, and utilities from the monolithic query_runner.py.
This module provides clean, reusable components for the CLI commands.
"""

from .models import (
    Query,
    QueryResult,
    DiscoveredCredential,
    SecretType,
    SourceType,
    Confidence,
)
from .formatters import (
    TIMESTAMP_FIELDS,
    format_timestamp_ago,
    is_timestamp_field,
    is_neo4j_path,
    get_node_name,
    format_neo4j_path,
    format_path_oneline,
    print_attack_paths,
    has_path_results,
    format_field_value,
    Colors,
)
from .neo4j_connection import Neo4jConnection, get_neo4j_session
from .query_loader import get_queries_dir, load_all_queries
from .file_discovery import (
    DiscoveredFile,
    FileDiscoveryBase,
    LocalFileDiscovery,
)
from .detection import (
    DetectionConfidence,
    AttackCommand,
    DetectionResult,
    DetectorBase,
    AzureADConnectDetector,
    GPPPasswordDetector,
    LAPSDetector,
    DetectorRegistry,
    get_default_registry,
)
from .password_reuse import (
    ReuseAnalysis,
    SpraySuggestion,
    PasswordReuseTracker,
)
from .service_accounts import (
    AccountPriority,
    AttackVector,
    ServiceAccountInfo,
    AnalysisResult,
    ServiceAccountAnalyzer,
)

__all__ = [
    # Models
    "Query",
    "QueryResult",
    "DiscoveredCredential",
    "SecretType",
    "SourceType",
    "Confidence",
    # Formatters
    "TIMESTAMP_FIELDS",
    "format_timestamp_ago",
    "is_timestamp_field",
    "is_neo4j_path",
    "get_node_name",
    "format_neo4j_path",
    "format_path_oneline",
    "print_attack_paths",
    "has_path_results",
    "format_field_value",
    "Colors",
    # Connection
    "Neo4jConnection",
    "get_neo4j_session",
    # Query Loading
    "get_queries_dir",
    "load_all_queries",
    # File Discovery
    "DiscoveredFile",
    "FileDiscoveryBase",
    "LocalFileDiscovery",
    # Detection
    "DetectionConfidence",
    "AttackCommand",
    "DetectionResult",
    "DetectorBase",
    "AzureADConnectDetector",
    "GPPPasswordDetector",
    "LAPSDetector",
    "DetectorRegistry",
    "get_default_registry",
    # Password Reuse
    "ReuseAnalysis",
    "SpraySuggestion",
    "PasswordReuseTracker",
    # Service Accounts
    "AccountPriority",
    "AttackVector",
    "ServiceAccountInfo",
    "AnalysisResult",
    "ServiceAccountAnalyzer",
]
