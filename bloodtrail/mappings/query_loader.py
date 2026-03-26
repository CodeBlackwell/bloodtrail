"""
Query mappings loader for bloodtrail.

Loads query-to-command mappings from JSON file.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Any


@lru_cache(maxsize=1)
def _load_query_mappings() -> Dict[str, Any]:
    """Load query command mappings from JSON file."""
    json_path = Path(__file__).parent.parent / "data" / "query_mappings.json"
    with open(json_path, "r") as f:
        return json.load(f)


# Lazy-loaded on first access
QUERY_COMMAND_MAPPINGS: Dict[str, Any] = _load_query_mappings()
