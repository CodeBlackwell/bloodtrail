"""
Pwned user display functions for bloodtrail.

Shows tables of compromised users, machines, and credential harvest targets.
"""

from typing import List, Dict

from .base import Colors, NoColors


def print_pwned_users_table(
    users: List,  # List[PwnedUser]
    use_colors: bool = True
) -> None:
    """
    Print a table of all pwned users with their access summary.

    Args:
        users: List of PwnedUser objects
        use_colors: Enable ANSI colors
    """
    c = Colors if use_colors else NoColors

    if not users:
        print(f"{c.DIM}No pwned users tracked.{c.RESET}")
        print(f"{c.DIM}Mark a user as pwned: bloodtrail --pwn USER@DOMAIN.COM --cred-type password --cred-value 'secret'{c.RESET}")
        return

    # Header
    print()
    print(f"{c.BOLD}{'='*90}{c.RESET}")
    print(f"  {c.CYAN}PWNED USERS{c.RESET} ({len(users)} total)")
    print(f"{'='*90}")
    print()

    # Table header
    print(f"  {'User':<30} {'Cred Type':<15} {'Admin On':<10} {'User On':<10} {'Domain?':<8} {'Pwned At'}")
    print(f"  {'-'*30} {'-'*15} {'-'*10} {'-'*10} {'-'*8} {'-'*20}")

    for user in users:
        # Count access by type (cred-access and rbcd-capable count as admin-equivalent)
        admin_count = sum(1 for a in user.access if a.privilege_level in ("local-admin", "cred-access", "rbcd-capable"))
        user_count = sum(1 for a in user.access if a.privilege_level in ("user-level", "dcom-exec"))
        domain_marker = "YES" if user.domain_level_access == "domain-admin" else "-"

        # Format timestamp
        pwned_at_str = user.pwned_at.strftime("%Y-%m-%d %H:%M")

        # Color based on privilege level
        if user.domain_level_access == "domain-admin":
            name_color = c.RED
        elif admin_count > 0:
            name_color = c.YELLOW
        else:
            name_color = c.RESET

        # Show credential types (comma-separated if multiple)
        cred_display = ",".join(user.cred_types) if user.cred_types else "password"
        if len(cred_display) > 15:
            cred_display = cred_display[:12] + "..."

        print(f"  {name_color}{user.name:<30}{c.RESET} {cred_display:<15} {admin_count:<10} {user_count:<10} {domain_marker:<8} {pwned_at_str}")

    # Credentials section - show actual pwned credentials
    print()
    print(f"{c.BOLD}{'='*90}{c.RESET}")
    print(f"  {c.GREEN}CAPTURED CREDENTIALS{c.RESET}")
    print(f"{'='*90}")
    print()

    for user in users:
        if not user.cred_types or not user.cred_values:
            continue

        # Color based on privilege level (include cred-access and rbcd-capable as admin-equiv)
        if user.domain_level_access == "domain-admin":
            name_color = c.RED
        elif any(a.privilege_level in ("local-admin", "cred-access", "rbcd-capable") for a in user.access):
            name_color = c.YELLOW
        else:
            name_color = c.RESET

        print(f"  {name_color}{c.BOLD}{user.name}{c.RESET}")

        # Print each credential type and value
        for cred_type, cred_value in zip(user.cred_types, user.cred_values):
            # Format credential type for display
            cred_label = cred_type.replace("-", " ").title()
            print(f"    {c.DIM}{cred_label}:{c.RESET} {c.GREEN}{cred_value}{c.RESET}")

        print()

    # gMSA Access section - show service accounts user can read passwords for
    users_with_gmsa = [u for u in users if u.gmsa_access]
    if users_with_gmsa:
        print(f"{c.BOLD}{'='*90}{c.RESET}")
        print(f"  {c.MAGENTA}SERVICE ACCOUNT ACCESS (gMSA){c.RESET}")
        print(f"{'='*90}")
        print()

        for user in users_with_gmsa:
            print(f"  {c.BOLD}{user.name}{c.RESET}")
            print(f"    {c.DIM}Can read:{c.RESET} {c.MAGENTA}{', '.join(user.gmsa_access)}{c.RESET}")
            print()

    print(f"{c.DIM}Run: bloodtrail --pwned-user USER  to see detailed access for a user{c.RESET}")
    print()


def print_machines_ip_table(machines: List[Dict], use_colors: bool = True, dc_ip: str = None) -> None:
    """
    Print table of machines with their resolved IP addresses.

    Args:
        machines: List of dicts with 'name' and 'ip' keys
        use_colors: Enable ANSI colors
        dc_ip: Domain Controller IP to highlight with blood drip emoji
    """
    c = Colors if use_colors else NoColors

    if not machines:
        print(f"{c.DIM}No machines found in BloodHound database.{c.RESET}")
        return

    resolved = sum(1 for m in machines if m["ip"])
    print(f"\n{c.BOLD}{'='*60}{c.RESET}")
    print(f"  {c.CYAN}MACHINES{c.RESET} ({resolved}/{len(machines)} resolved)")
    print(f"{'='*60}\n")

    # Calculate column widths
    max_name = max(len(m["name"]) for m in machines)
    max_ip = max(len(m["ip"] or "---") for m in machines)

    # Header
    print(f"  {c.BOLD}{'Machine':<{max_name}}  {'IP Address':<{max_ip}}{c.RESET}")
    print(f"  {'-' * max_name}  {'-' * max_ip}")

    # Rows
    for m in machines:
        ip_display = m["ip"] if m["ip"] else "---"
        is_dc = dc_ip and m["ip"] == dc_ip
        ip_color = c.RED if is_dc else (c.CYAN if m["ip"] else c.DIM)
        dc_marker = " 🩸" if is_dc else ""
        print(f"  {m['name']:<{max_name}}  {ip_color}{ip_display:<{max_ip}}{c.RESET}{dc_marker}")

    # Legend
    if dc_ip:
        print()
        print(f"  {c.DIM}🩸 = Domain Controller (stored DC IP){c.RESET}")
    print()


def print_cred_harvest_targets(
    targets: List[Dict],
    use_colors: bool = True
) -> None:
    """
    Print high-priority credential harvest targets.

    These are machines where pwned users have admin AND privileged users have sessions.

    Args:
        targets: List of dicts with pwned_user, target, privileged_sessions
        use_colors: Enable ANSI colors
    """
    from ..mappings.edge_mappings import CRED_TYPE_TEMPLATES
    from ..mappings.command_fill import fill_pwned_command

    c = Colors if use_colors else NoColors

    if not targets:
        print(f"{c.DIM}No high-priority credential harvest targets found.{c.RESET}")
        return

    print()
    print(f"{c.RED}{c.BOLD}{'='*70}{c.RESET}")
    print(f"  {c.RED}PRIORITY CREDENTIAL HARVEST TARGETS{c.RESET}")
    print(f"{c.RED}{'='*70}{c.RESET}")
    print()

    for t in targets[:10]:
        user = t["pwned_user"]
        target = t["target"]
        sessions = t["privileged_sessions"]
        cred_type = t.get("cred_type", "password")
        cred_value = t.get("cred_value", "<PASSWORD>")

        # Extract username/domain
        if "@" in user:
            username, domain = user.split("@")
        else:
            username, domain = user, ""

        print(f"  {c.BOLD}{target}{c.RESET}")
        print(f"    {c.DIM}Pwned user:{c.RESET} {user} ({cred_type})")
        print(f"    {c.YELLOW}High-value sessions:{c.RESET} {', '.join(sessions[:5])}")

        # Secretsdump command
        template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("secretsdump")
        if template:
            cmd = fill_pwned_command(
                template,
                username=username,
                domain=domain,
                target=target,
                cred_value=cred_value
            )
            print(f"    {c.GREEN}{cmd}{c.RESET}")
        print()

    if len(targets) > 10:
        print(f"  {c.DIM}... and {len(targets) - 10} more targets{c.RESET}")

    print()
