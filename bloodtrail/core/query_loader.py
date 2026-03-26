"""
BloodTrail Query Loader

Loads Cypher queries from JSON files in the cypher_queries/ directory.
Extracted from QueryRunner._load_all_queries() for reuse.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple

from .models import Query


def get_queries_dir() -> Path:
    """
    Get path to cypher_queries directory.

    Returns:
        Path to the cypher_queries/ directory containing JSON query definitions.
    """
    return Path(__file__).parent.parent / "cypher_queries"


def load_all_queries() -> Tuple[Dict[str, Query], Dict[str, List[str]]]:
    """
    Load all queries from JSON files in the cypher_queries directory.

    Scans all *.json files (except schema.json) and parses them into
    Query objects. Queries are indexed by ID and grouped by category.

    Returns:
        Tuple of:
        - queries_by_id: Dict mapping query ID to Query object
        - categories: Dict mapping category name to list of query IDs

    Example:
        queries, categories = load_all_queries()

        # Get a specific query
        query = queries["lateral-adminto-nonpriv"]

        # Get all queries in a category
        lateral_ids = categories["lateral_movement"]
    """
    queries_dir = get_queries_dir()
    queries_by_id: Dict[str, Query] = {}
    categories: Dict[str, List[str]] = {}

    if not queries_dir.exists():
        return queries_by_id, categories

    for json_file in queries_dir.glob("*.json"):
        # Skip schema file
        if json_file.name == "schema.json":
            continue

        try:
            with open(json_file) as f:
                data = json.load(f)

            category = data.get("category", json_file.stem)
            categories[category] = []

            for query_data in data.get("queries", []):
                query = Query(
                    id=query_data["id"],
                    name=query_data["name"],
                    description=query_data["description"],
                    cypher=query_data["cypher"],
                    category=category,
                    variables=query_data.get("variables", {}),
                    edge_types_used=query_data.get("edge_types_used", []),
                    oscp_relevance=query_data.get("oscp_relevance", "medium"),
                    expected_results=query_data.get("expected_results", ""),
                    example_output=query_data.get("example_output", ""),
                    next_steps=query_data.get("next_steps", []),
                    tags=query_data.get("tags", []),
                )
                queries_by_id[query.id] = query
                categories[category].append(query.id)

        except json.JSONDecodeError as e:
            print(f"[!] JSON error in {json_file}: {e}")
        except KeyError as e:
            print(f"[!] Missing required field in {json_file}: {e}")
        except Exception as e:
            print(f"[!] Error loading {json_file}: {e}")

    return queries_by_id, categories


def load_query_by_id(query_id: str) -> Query:
    """
    Load a specific query by ID.

    Convenience function for loading a single query without
    loading the entire library.

    Args:
        query_id: The query ID to load

    Returns:
        Query object

    Raises:
        KeyError: If query not found
    """
    queries, _ = load_all_queries()
    if query_id not in queries:
        raise KeyError(f"Query not found: {query_id}")
    return queries[query_id]


def get_query_categories() -> List[str]:
    """
    Get list of all available query categories.

    Returns:
        List of category names (e.g., ["lateral_movement", "quick_wins", ...])
    """
    _, categories = load_all_queries()
    return list(categories.keys())
