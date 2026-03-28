"""
Output pagination for BloodTrail.

Pipes output through system pager when stdout is a TTY and output exceeds terminal height.
"""

import os
import sys
from contextlib import contextmanager


@contextmanager
def paged_output(enabled: bool = True):
    """Context manager that pipes stdout through $PAGER when on a TTY."""
    if not enabled or not sys.stdout.isatty():
        yield
        return

    pager = os.environ.get("PAGER", "less -R")
    try:
        import subprocess
        proc = subprocess.Popen(pager, shell=True, stdin=subprocess.PIPE, text=True)
        old_stdout = sys.stdout
        sys.stdout = proc.stdin
        yield
        proc.stdin.close()
        proc.wait()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    except Exception:
        yield
    finally:
        sys.stdout = old_stdout if 'old_stdout' in dir() else sys.stdout


def truncate_results(records: list, limit: int = 50) -> tuple:
    """Truncate result list, return (truncated_list, total_count, was_truncated)."""
    total = len(records)
    if limit <= 0 or total <= limit:
        return records, total, False
    return records[:limit], total, True
