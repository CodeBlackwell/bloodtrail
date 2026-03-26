"""
Post-success suggestions for bloodtrail display.

Shows "When You Succeed" next steps after successful attacks.
"""

from typing import List, Dict

from .base import Colors, NoColors


def print_post_success(
    post_success: List[Dict],
    domain: str = "",
    dc_ip: str = "<DC_IP>",
    use_colors: bool = True
) -> None:
    """
    Print post-success suggestions after command tables.

    Shows "When You Succeed" next steps for discovery commands
    like Kerberoasting, AS-REP roasting, etc.

    Args:
        post_success: List of {"description": str, "command": str|None}
        domain: Domain for placeholder replacement
        dc_ip: DC IP for placeholder replacement
        use_colors: Enable ANSI colors
    """
    if not post_success:
        return

    c = Colors if use_colors else NoColors

    print(f"\n  {c.DIM}─── When You Succeed ───────────────────────────────{c.RESET}")

    for i, step in enumerate(post_success, 1):
        desc = step.get("description", "")
        cmd = step.get("command")

        print(f"  {c.CYAN}{i}.{c.RESET} {desc}")
        if cmd:
            # Fill domain/DC placeholders
            cmd = cmd.replace("<DOMAIN>", domain.lower() if domain else "<DOMAIN>")
            cmd = cmd.replace("<DC_IP>", dc_ip)
            print(f"     {c.GREEN}{cmd}{c.RESET}")

    print()
