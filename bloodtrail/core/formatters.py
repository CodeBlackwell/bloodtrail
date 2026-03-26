"""
BloodTrail Formatters

Timestamp formatting, Neo4j path parsing, and display utilities.
Extracted from query_runner.py for reuse across CLI commands.
"""

from typing import Dict, List, Any


# =============================================================================
# ANSI COLORS
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# =============================================================================
# TIMESTAMP FORMATTING HELPERS
# =============================================================================

# Field names that contain timestamps (case-insensitive matching)
TIMESTAMP_FIELDS = {
    'passwordlastset', 'pwdlastset', 'lastlogon', 'lastlogontimestamp',
    'lastlogoff', 'whencreated', 'whenchanged', 'accountexpires',
    'badpasswordtime', 'lastpasswordset', 'pwdlastchange'
}


def format_timestamp_ago(timestamp: Any) -> str:
    """
    Convert a timestamp to human-readable "X time ago" format.

    Args:
        timestamp: Unix epoch in seconds or milliseconds, or None/0

    Returns:
        Human-readable string like "3 months ago" or "Never"
    """
    if timestamp is None or timestamp == 0 or timestamp == -1:
        return "Never"

    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return str(timestamp)

    # BloodHound timestamps can be in milliseconds or seconds
    # If > year 3000 in seconds, it's probably milliseconds
    if ts > 32503680000:  # Year 3000 in seconds
        ts = ts // 1000

    # Handle Windows FILETIME (100-nanosecond intervals since 1601)
    # These are huge numbers > 100000000000000
    if ts > 100000000000000:
        # Convert FILETIME to Unix timestamp
        ts = (ts // 10000000) - 11644473600

    from datetime import datetime
    try:
        dt = datetime.fromtimestamp(ts)
        now = datetime.now()
        delta = now - dt

        seconds = int(delta.total_seconds())
        if seconds < 0:
            return "In the future"
        if seconds < 60:
            return f"{seconds} seconds ago"
        if seconds < 3600:
            mins = seconds // 60
            return f"{mins} minute{'s' if mins != 1 else ''} ago"
        if seconds < 86400:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        if seconds < 2592000:  # 30 days
            days = seconds // 86400
            return f"{days} day{'s' if days != 1 else ''} ago"
        if seconds < 31536000:  # 365 days
            months = seconds // 2592000
            return f"{months} month{'s' if months != 1 else ''} ago"

        years = seconds // 31536000
        return f"{years} year{'s' if years != 1 else ''} ago"
    except (ValueError, OSError, OverflowError):
        return str(timestamp)


def is_timestamp_field(field_name: str) -> bool:
    """Check if a field name represents a timestamp."""
    return field_name.lower().replace('_', '') in TIMESTAMP_FIELDS


# =============================================================================
# NEO4J PATH FORMATTING
# =============================================================================

def is_neo4j_path(value: Any) -> bool:
    """Check if value is a Neo4j Path object."""
    # Check by type name since we may not have the exact import
    type_name = type(value).__name__
    return type_name == 'Path' or 'graph.Path' in str(type(value))


def get_node_name(node: Any) -> str:
    """Extract readable name from Neo4j Node object."""
    # Try common name properties in order of preference
    for prop in ['name', 'samaccountname', 'distinguishedname']:
        try:
            val = node.get(prop) or node.get(prop.upper())
            if val:
                return str(val)
        except (AttributeError, TypeError):
            pass
    # Fallback: try to get labels
    try:
        labels = list(node.labels) if hasattr(node, 'labels') else []
        if labels:
            return f"[{':'.join(labels)}]"
    except:
        pass
    return "<?>"


def format_neo4j_path(path: Any) -> Dict[str, Any]:
    """
    Parse a Neo4j Path object into structured data.

    Returns:
        {
            'start': str,       # Start node name
            'end': str,         # End node name
            'hops': int,        # Number of relationships
            'nodes': [str],     # All node names in order
            'edges': [str],     # All relationship types in order
            'steps': [(node, edge, node), ...]  # Step-by-step breakdown
        }
    """
    try:
        nodes = list(path.nodes)
        rels = list(path.relationships)

        node_names = [get_node_name(n) for n in nodes]
        edge_types = [r.type for r in rels]

        # Build steps: (from_node, edge, to_node)
        steps = []
        for i, rel in enumerate(rels):
            steps.append({
                'from': node_names[i],
                'edge': edge_types[i],
                'to': node_names[i + 1]
            })

        return {
            'start': node_names[0] if node_names else '?',
            'end': node_names[-1] if node_names else '?',
            'hops': len(rels),
            'nodes': node_names,
            'edges': edge_types,
            'steps': steps
        }
    except Exception as e:
        return {
            'start': '?',
            'end': '?',
            'hops': 0,
            'nodes': [],
            'edges': [],
            'steps': [],
            'error': str(e)
        }


def format_path_oneline(path: Any) -> str:
    """Format path as single-line summary for tables."""
    parsed = format_neo4j_path(path)
    if parsed.get('error'):
        return str(path)[:50]

    # Short format: START -[E1,E2,E3]-> END (N hops)
    edges_str = ','.join(parsed['edges'][:5])
    if len(parsed['edges']) > 5:
        edges_str += '...'
    return f"{parsed['start']} -[{edges_str}]-> {parsed['end']} ({parsed['hops']} hops)"


def print_attack_paths(
    records: List[Dict],
    query_name: str = "Attack Paths",
    use_colors: bool = True,
    max_paths: int = 10
) -> None:
    """
    Print attack paths in a visual, digestible format.

    Displays each path as a chain showing:
    - Start and end nodes
    - Each hop with edge type
    - Total hop count

    Args:
        records: Query results containing path objects
        query_name: Display name for the section header
        use_colors: Enable ANSI colors
        max_paths: Maximum number of paths to display
    """
    # Find path column(s)
    if not records:
        return

    path_columns = []
    for key, val in records[0].items():
        if is_neo4j_path(val):
            path_columns.append(key)

    if not path_columns:
        return  # No path objects found

    # Color setup
    if use_colors:
        BOLD = '\033[1m'
        DIM = '\033[2m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        RESET = '\033[0m'
    else:
        BOLD = DIM = CYAN = GREEN = YELLOW = RED = RESET = ''

    # Group paths by destination for deduplication summary
    paths_by_dest = {}
    all_parsed = []

    for record in records:
        for col in path_columns:
            path_obj = record.get(col)
            if path_obj and is_neo4j_path(path_obj):
                parsed = format_neo4j_path(path_obj)
                if not parsed.get('error'):
                    all_parsed.append(parsed)
                    dest = parsed['end']
                    if dest not in paths_by_dest:
                        paths_by_dest[dest] = []
                    paths_by_dest[dest].append(parsed)

    if not all_parsed:
        return

    # Print summary header
    unique_starts = len(set(p['start'] for p in all_parsed))
    unique_ends = len(set(p['end'] for p in all_parsed))
    print(f"\n  {BOLD}Found {len(all_parsed)} path(s){RESET}")
    print(f"  {DIM}From {unique_starts} user(s) to {unique_ends} target(s){RESET}")
    print()

    # Print each path visually
    displayed = 0
    for i, parsed in enumerate(all_parsed[:max_paths], 1):
        hops = parsed['hops']
        start = parsed['start']
        end = parsed['end']

        # Path header
        print(f"  {BOLD}{CYAN}Path {i}{RESET}: {GREEN}{start}{RESET} -> {RED}{end}{RESET} ({hops} hop{'s' if hops != 1 else ''})")

        # Show each step
        for step in parsed['steps']:
            edge = step['edge']
            to_node = step['to']
            # Colorize edge types
            if edge in ('MemberOf',):
                edge_color = DIM
            elif edge in ('AdminTo', 'CanRDP', 'CanPSRemote'):
                edge_color = GREEN
            elif edge in ('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'ForceChangePassword'):
                edge_color = RED
            elif edge in ('HasSession',):
                edge_color = YELLOW
            else:
                edge_color = CYAN

            print(f"      | {edge_color}[{edge}]{RESET}")
            print(f"      {to_node}")

        print()  # Space between paths
        displayed += 1

    # Truncation notice
    if len(all_parsed) > max_paths:
        remaining = len(all_parsed) - max_paths
        print(f"  {DIM}... and {remaining} more path(s){RESET}")
        print()

    # Quick reference: paths grouped by start user
    paths_by_start = {}
    for p in all_parsed:
        start = p['start']
        if start not in paths_by_start:
            paths_by_start[start] = []
        paths_by_start[start].append(p)

    if len(paths_by_start) > 1:
        print(f"  {BOLD}Summary by Starting User:{RESET}")
        for start, paths in sorted(paths_by_start.items(), key=lambda x: -len(x[1])):
            targets = set(p['end'] for p in paths)
            min_hops = min(p['hops'] for p in paths)
            print(f"    {YELLOW}>{RESET} {start}: {len(paths)} path(s), min {min_hops} hops -> {', '.join(list(targets)[:3])}")
        print()


def has_path_results(records: List[Dict]) -> bool:
    """Check if query results contain Neo4j Path objects."""
    if not records:
        return False
    for key, val in records[0].items():
        if is_neo4j_path(val):
            return True
    return False


def format_field_value(field_name: str, value: Any) -> str:
    """Format a field value, applying timestamp/path formatting if appropriate."""
    if value is None:
        return ""
    if is_timestamp_field(field_name):
        return format_timestamp_ago(value)
    if is_neo4j_path(value):
        return format_path_oneline(value)
    return str(value)
