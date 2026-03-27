"""
BloodTrail Web UI Command

Launches the interactive web visualization for BloodHound data.
Requires optional dependencies: pip install bloodtrail[ui]
"""

import json
import webbrowser
from argparse import Namespace
from pathlib import Path

from ..base import BaseCommandGroup


def _load_data(bh_path):
    """Load BloodHound data — handles both raw SharpHound and pre-processed formats."""
    from ...demo.parser import parse_upload
    from ...demo.analyzer import analyze

    path = Path(bh_path)
    parsed = parse_upload(path)

    if not parsed["nodes"] and path.is_dir():
        for f in path.glob("*.json"):
            data = json.loads(f.read_text())
            if "nodes" in data and "edges" in data:
                parsed = data
                break

    if not parsed.get("nodes"):
        return None

    if not parsed.get("chains"):
        result = analyze(parsed["nodes"], parsed["edges"])
        parsed["chains"] = result["chains"]
        parsed["quick_wins"] = result["quick_wins"]
        parsed.setdefault("meta", {})["chain_count"] = len(result["chains"])

    return parsed


class UICommands(BaseCommandGroup):
    """Web UI launcher command handler."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        if not getattr(args, 'ui', False):
            return -1

        try:
            import uvicorn
        except ImportError:
            cls.print_error("Web UI requires extra dependencies.")
            print("  Install with: pip install bloodtrail[ui]")
            return 1

        bh_path = getattr(args, 'bh_data_dir', None)
        if not bh_path or not Path(bh_path).exists():
            cls.print_error("Provide a BloodHound data path: bloodtrail /path/to/data --ui")
            return 1

        cls.print_info(f"Parsing BloodHound data from {bh_path}...")

        parsed = _load_data(bh_path)
        if not parsed:
            cls.print_error("No BloodHound data found. Provide a SharpHound ZIP, JSON dir, or pre-processed file.")
            return 1

        from ...demo.app import app, set_data
        set_data(parsed)

        port = getattr(args, 'port', 8765)
        url = f"http://127.0.0.1:{port}"

        cls.print_success(f"Launching BloodTrail UI at {url}")
        print(f"  {len(parsed['nodes'])} nodes, {len(parsed['edges'])} edges, {len(parsed.get('chains', []))} chains")
        print(f"  Press Ctrl+C to stop\n")

        webbrowser.open(url)
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
        return 0
