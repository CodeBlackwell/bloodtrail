"""
Edge Extractors for BloodHound Data

Extracts relationship data from BloodHound JSON exports and converts
to Neo4j edge format for import.

Supports both directory and ZIP file data sources.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Set, Iterator, Union
from dataclasses import dataclass, field

from .config import ACE_EDGE_MAPPINGS, ATTACK_PATH_EDGES
from .sid_resolver import SIDResolver
from .data_source import DataSource, create_data_source


@dataclass
class Edge:
    """Represents a Neo4j edge to be created"""
    source: str           # Source node name
    target: str           # Target node name
    edge_type: str        # Relationship type (e.g., AdminTo, GenericAll)
    properties: Dict = field(default_factory=dict)  # Edge properties

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type,
            "properties": self.properties,
        }


@dataclass
class ExtractionResult:
    """Result of edge extraction"""
    edges: List[Edge] = field(default_factory=list)
    edge_count: int = 0
    errors: List[str] = field(default_factory=list)
    skipped: int = 0

    def add_edge(self, edge: Edge):
        self.edges.append(edge)
        self.edge_count += 1

    def add_error(self, msg: str):
        self.errors.append(msg)

    def merge(self, other: "ExtractionResult"):
        self.edges.extend(other.edges)
        self.edge_count += other.edge_count
        self.errors.extend(other.errors)
        self.skipped += other.skipped


class BaseExtractor(ABC):
    """
    Base class for BloodHound edge extractors.

    Subclasses implement extract() to process specific JSON file types
    and return edges for Neo4j import.
    """

    # Edge types this extractor produces
    edge_types: Set[str] = set()

    # JSON file types this extractor processes (e.g., "computers", "users")
    source_files: Set[str] = set()

    def __init__(self, resolver: SIDResolver):
        self.resolver = resolver

    @abstractmethod
    def extract(self, data: dict, filename: str) -> ExtractionResult:
        """
        Extract edges from BloodHound JSON data.

        Args:
            data: Parsed JSON data from BloodHound export
            filename: Source filename for error reporting

        Returns:
            ExtractionResult with extracted edges
        """
        pass

    def should_process(self, filename: str) -> bool:
        """Check if this extractor should process the given file"""
        fname_lower = filename.lower()
        return any(src in fname_lower for src in self.source_files)


class ComputerEdgeExtractor(BaseExtractor):
    """
    Extracts edges from computers.json:
    - AdminTo (LocalAdmins)
    - CanPSRemote (PSRemoteUsers)
    - CanRDP (RemoteDesktopUsers)
    - ExecuteDCOM (DcomUsers)
    - HasSession (Sessions)
    - AllowedToAct (Resource-based constrained delegation)
    """

    edge_types = {"AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM", "HasSession", "AllowedToAct"}
    source_files = {"computers"}

    # Mapping of JSON field -> edge type
    FIELD_MAPPINGS = {
        "LocalAdmins": "AdminTo",
        "PSRemoteUsers": "CanPSRemote",
        "RemoteDesktopUsers": "CanRDP",
        "DcomUsers": "ExecuteDCOM",
        "Sessions": "HasSession",
        "AllowedToAct": "AllowedToAct",
    }

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for computer in data.get("data", []):
            target_name = computer.get("Properties", {}).get("name")
            if not target_name:
                result.add_error(f"Computer missing name in {filename}")
                continue

            # Process each relationship type
            for field_name, edge_type in self.FIELD_MAPPINGS.items():
                field_data = computer.get(field_name, {})

                # Handle both direct arrays and nested Results
                if isinstance(field_data, dict):
                    results = field_data.get("Results", [])
                    collected = field_data.get("Collected", True)
                    if not collected:
                        continue  # Skip uncollected data
                elif isinstance(field_data, list):
                    results = field_data
                else:
                    continue

                for item in results:
                    # Get source SID
                    if isinstance(item, dict):
                        source_sid = item.get("ObjectIdentifier") or item.get("UserSID")
                        obj_type = item.get("ObjectType", "Unknown")
                    elif isinstance(item, str):
                        source_sid = item
                        obj_type = "Unknown"
                    else:
                        continue

                    if not source_sid:
                        continue

                    # Resolve SID to name
                    source_name, _ = self.resolver.resolve(source_sid)

                    # Create edge (source -> target for most, reverse for HasSession)
                    if edge_type == "HasSession":
                        # HasSession: Computer -[:HasSession]-> User
                        edge = Edge(
                            source=target_name,
                            target=source_name,
                            edge_type=edge_type,
                            properties={"source_type": "Computer", "target_type": obj_type}
                        )
                    else:
                        # Others: Principal -[:EdgeType]-> Computer
                        edge = Edge(
                            source=source_name,
                            target=target_name,
                            edge_type=edge_type,
                            properties={"source_type": obj_type, "target_type": "Computer"}
                        )

                    result.add_edge(edge)

        return result


class ACEExtractor(BaseExtractor):
    """
    Extracts ACL-based edges from all object types:
    - GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns
    - ForceChangePassword, AddKeyCredentialLink
    - GetChanges, GetChangesAll (DCSync rights on Domain objects)
    - And other ACE-based permissions
    """

    edge_types = set(ACE_EDGE_MAPPINGS.values())
    source_files = {"users", "computers", "groups", "domains", "gpos", "ous", "containers"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for obj in data.get("data", []):
            target_name = obj.get("Properties", {}).get("name")
            if not target_name:
                continue

            # Process ACEs
            for ace in obj.get("Aces", []):
                right_name = ace.get("RightName")
                principal_sid = ace.get("PrincipalSID")
                is_inherited = ace.get("IsInherited", False)
                principal_type = ace.get("PrincipalType", "Unknown")

                if not right_name or not principal_sid:
                    continue

                # Map to Neo4j edge type
                edge_type = ACE_EDGE_MAPPINGS.get(right_name)
                if not edge_type:
                    continue  # Skip unmapped ACE types

                # Resolve principal SID
                source_name, resolved_type = self.resolver.resolve(principal_sid)

                # Create edge: Principal -[:Right]-> Object
                edge = Edge(
                    source=source_name,
                    target=target_name,
                    edge_type=edge_type,
                    properties={
                        "inherited": is_inherited,
                        "source_type": principal_type or resolved_type,
                    }
                )
                result.add_edge(edge)

        return result


class GroupMembershipExtractor(BaseExtractor):
    """
    Extracts group membership edges from groups.json:
    - MemberOf: Member -> Group relationship
    """

    edge_types = {"MemberOf"}
    source_files = {"groups"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for group in data.get("data", []):
            group_name = group.get("Properties", {}).get("name")
            if not group_name:
                continue

            # Process Members array
            members = group.get("Members", [])
            for member in members:
                if isinstance(member, dict):
                    member_sid = member.get("ObjectIdentifier")
                    member_type = member.get("ObjectType", "Unknown")
                elif isinstance(member, str):
                    member_sid = member
                    member_type = "Unknown"
                else:
                    continue

                if not member_sid:
                    continue

                # Resolve member SID
                member_name, resolved_type = self.resolver.resolve(member_sid)

                # Create edge: Member -[:MemberOf]-> Group
                edge = Edge(
                    source=member_name,
                    target=group_name,
                    edge_type="MemberOf",
                    properties={
                        "source_type": member_type or resolved_type,
                        "target_type": "Group"
                    }
                )
                result.add_edge(edge)

        return result


class DelegationExtractor(BaseExtractor):
    """
    Extracts delegation edges from users and computers:
    - AllowedToDelegate: Constrained delegation targets
    """

    edge_types = {"AllowedToDelegate"}
    source_files = {"users", "computers"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for obj in data.get("data", []):
            source_name = obj.get("Properties", {}).get("name")
            if not source_name:
                continue

            # Process AllowedToDelegate array
            delegates = obj.get("AllowedToDelegate", [])
            for delegate_sid in delegates:
                if not delegate_sid:
                    continue

                # Resolve delegate SID
                target_name, target_type = self.resolver.resolve(delegate_sid)

                # Create edge: Source -[:AllowedToDelegate]-> Target
                edge = Edge(
                    source=source_name,
                    target=target_name,
                    edge_type="AllowedToDelegate",
                    properties={"target_type": target_type}
                )
                result.add_edge(edge)

        return result


class TrustExtractor(BaseExtractor):
    """
    Extracts domain trust relationships from domains.json:
    - TrustedBy: Domain trust relationships
    """

    edge_types = {"TrustedBy"}
    source_files = {"domains"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for domain in data.get("data", []):
            source_name = domain.get("Properties", {}).get("name")
            if not source_name:
                continue

            # Process Trusts array
            trusts = domain.get("Trusts", [])
            for trust in trusts:
                if not isinstance(trust, dict):
                    continue

                target_domain = trust.get("TargetDomainName")
                if not target_domain:
                    continue

                trust_direction = trust.get("TrustDirection", 0)
                trust_type = trust.get("TrustType", "Unknown")
                is_transitive = trust.get("IsTransitive", False)
                sid_filtering = trust.get("SidFilteringEnabled", True)

                # TrustDirection: 0=Disabled, 1=Inbound, 2=Outbound, 3=Bidirectional
                # TrustedBy: source trusts target (outbound from source perspective)
                if trust_direction in (2, 3):  # Outbound or Bidirectional
                    edge = Edge(
                        source=source_name,
                        target=target_domain,
                        edge_type="TrustedBy",
                        properties={
                            "trust_type": trust_type,
                            "transitive": is_transitive,
                            "sid_filtering": sid_filtering,
                            "direction": trust_direction,
                        }
                    )
                    result.add_edge(edge)

                # Also add reverse for bidirectional
                if trust_direction == 3:  # Bidirectional
                    edge = Edge(
                        source=target_domain,
                        target=source_name,
                        edge_type="TrustedBy",
                        properties={
                            "trust_type": trust_type,
                            "transitive": is_transitive,
                            "sid_filtering": sid_filtering,
                            "direction": trust_direction,
                        }
                    )
                    result.add_edge(edge)

        return result


class CoercionExtractor(BaseExtractor):
    """
    Extracts coercion-related edges:
    - HasSIDHistory: SID history relationships for token manipulation
    - CoerceToTGT: Computed for unconstrained delegation (requires post-processing)
    """

    edge_types = {"HasSIDHistory"}
    source_files = {"users", "computers"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        result = ExtractionResult()

        for obj in data.get("data", []):
            source_name = obj.get("Properties", {}).get("name")
            if not source_name:
                continue

            # Process SIDHistory array
            sid_history = obj.get("Properties", {}).get("sidhistory", [])
            if not sid_history:
                sid_history = obj.get("SIDHistory", [])

            for hist_sid in sid_history:
                if not hist_sid:
                    continue

                # Resolve historical SID
                target_name, target_type = self.resolver.resolve(hist_sid)

                # Create edge: Source -[:HasSIDHistory]-> Target (historical identity)
                edge = Edge(
                    source=source_name,
                    target=target_name,
                    edge_type="HasSIDHistory",
                    properties={
                        "source_type": obj.get("Properties", {}).get("objecttype", "Unknown"),
                        "target_type": target_type,
                    }
                )
                result.add_edge(edge)

        return result


class ADCSExtractor(BaseExtractor):
    """
    Extracts ADCS-related edges from BloodHound CE data:
    - Processes cas.json (Certificate Authorities)
    - Processes certtemplates.json (Certificate Templates)

    Note: ESC1-13 edges are computed by BloodHound CE and should be
    directly imported if present in the data, not extracted from raw ACLs.
    """

    edge_types = {
        "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5",
        "ADCSESC6a", "ADCSESC6b", "ADCSESC7",
        "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
        "GoldenCert", "EnrollOnBehalfOf",
    }
    source_files = {"cas", "certtemplates", "enterprisecas", "rootcas", "aiacas", "ntauthstores"}

    def extract(self, data: dict, filename: str) -> ExtractionResult:
        """
        Extract ADCS edges from BloodHound CE ADCS JSON exports.

        BloodHound CE computes ESC edges during processing, so we look for
        pre-computed edges in the data rather than calculating them.
        """
        result = ExtractionResult()

        for obj in data.get("data", []):
            target_name = obj.get("Properties", {}).get("name")
            if not target_name:
                continue

            # Process pre-computed ESC edges if present
            # BloodHound CE includes these in specific relationship arrays
            for edge_type in self.edge_types:
                edge_array = obj.get(edge_type, [])
                if not edge_array:
                    continue

                for item in edge_array:
                    if isinstance(item, dict):
                        source_sid = item.get("ObjectIdentifier")
                        source_type = item.get("ObjectType", "Unknown")
                    elif isinstance(item, str):
                        source_sid = item
                        source_type = "Unknown"
                    else:
                        continue

                    if not source_sid:
                        continue

                    source_name, resolved_type = self.resolver.resolve(source_sid)

                    edge = Edge(
                        source=source_name,
                        target=target_name,
                        edge_type=edge_type,
                        properties={
                            "source_type": source_type or resolved_type,
                        }
                    )
                    result.add_edge(edge)

            # Also check for EnrollOnBehalfOf which links templates
            enroll_behalf = obj.get("EnrollOnBehalfOf", [])
            for template in enroll_behalf:
                if isinstance(template, dict):
                    template_name = template.get("Name") or template.get("ObjectIdentifier")
                elif isinstance(template, str):
                    template_name = template
                else:
                    continue

                if template_name:
                    edge = Edge(
                        source=target_name,
                        target=template_name,
                        edge_type="EnrollOnBehalfOf",
                        properties={}
                    )
                    result.add_edge(edge)

        return result


class EdgeExtractorRegistry:
    """
    Registry of all edge extractors.

    Provides a unified interface for extracting edges from BloodHound data.
    """

    def __init__(self, resolver: SIDResolver):
        self.resolver = resolver
        self.extractors: List[BaseExtractor] = [
            # Core extractors
            ComputerEdgeExtractor(resolver),
            ACEExtractor(resolver),
            GroupMembershipExtractor(resolver),
            DelegationExtractor(resolver),
            # Trust and coercion
            TrustExtractor(resolver),
            CoercionExtractor(resolver),
            # ADCS (BloodHound CE)
            ADCSExtractor(resolver),
        ]

    def extract_from_file(self, json_path: Path) -> ExtractionResult:
        """Extract edges from a single JSON file (filesystem path)"""
        result = ExtractionResult()

        try:
            with open(json_path) as f:
                data = json.load(f)
        except Exception as e:
            result.add_error(f"Failed to load {json_path}: {e}")
            return result

        filename = json_path.name
        return self.extract_from_data(data, filename)

    def extract_from_data(self, data: dict, filename: str) -> ExtractionResult:
        """Extract edges from parsed JSON data"""
        result = ExtractionResult()

        for extractor in self.extractors:
            if extractor.should_process(filename):
                extractor_result = extractor.extract(data, filename)
                result.merge(extractor_result)

        return result

    def extract_from_source(
        self,
        data_source: Union[Path, DataSource],
        edge_filter: Optional[Set[str]] = None
    ) -> ExtractionResult:
        """
        Extract edges from a DataSource (directory or ZIP file).

        Args:
            data_source: DataSource object or Path to directory/ZIP
            edge_filter: Optional set of edge types to extract (None = all)

        Returns:
            ExtractionResult with all extracted edges
        """
        result = ExtractionResult()

        # Convert Path to DataSource if needed
        if isinstance(data_source, (str, Path)):
            data_source = create_data_source(Path(data_source))

        # Iterate over all JSON files in the source
        for filename, data in data_source.iter_json_files():
            file_result = self.extract_from_data(data, filename)
            result.merge(file_result)

        # Apply edge type filter
        if edge_filter:
            filtered_edges = [e for e in result.edges if e.edge_type in edge_filter]
            result.skipped = len(result.edges) - len(filtered_edges)
            result.edges = filtered_edges
            result.edge_count = len(filtered_edges)

        return result

    def extract_from_directory(
        self,
        data_dir: Union[Path, DataSource],
        edge_filter: Optional[Set[str]] = None
    ) -> ExtractionResult:
        """
        Extract edges from all JSON files in directory or ZIP.

        This method is maintained for backwards compatibility.
        Use extract_from_source() for new code.

        Args:
            data_dir: Directory/ZIP Path or DataSource containing BloodHound exports
            edge_filter: Optional set of edge types to extract (None = all)

        Returns:
            ExtractionResult with all extracted edges
        """
        return self.extract_from_source(data_dir, edge_filter)

    def get_attack_path_edges(self, data_source: Union[Path, DataSource]) -> ExtractionResult:
        """Extract only attack-path relevant edges"""
        return self.extract_from_source(data_source, edge_filter=ATTACK_PATH_EDGES)

    def get_all_edge_types(self) -> Set[str]:
        """Return all supported edge types"""
        all_types = set()
        for extractor in self.extractors:
            all_types.update(extractor.edge_types)
        return all_types


def deduplicate_edges(edges: List[Edge]) -> List[Edge]:
    """
    Remove duplicate edges (same source, target, edge_type).

    Keeps first occurrence (typically has better properties).
    """
    seen = set()
    unique = []

    for edge in edges:
        key = (edge.source, edge.target, edge.edge_type)
        if key not in seen:
            seen.add(key)
            unique.append(edge)

    return unique
