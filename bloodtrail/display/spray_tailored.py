"""
BloodHound-based tailored spray commands for bloodtrail.

Generates spray commands based on BloodHound access relationships.
"""

from typing import List, Dict

from .base import Colors, NoColors


# Protocol mapping for each access type
ACCESS_TYPE_PROTOCOLS = {
    "AdminTo": {
        "name": "Local Admin",
        "protocols": [
            {"name": "SMB (CrackMapExec)", "cmd": "crackmapexec smb {targets} -u {users} -p '<PASSWORD>'", "single": "crackmapexec smb {target} -u {user} -p '<PASSWORD>'"},
            {"name": "WinRM (evil-winrm)", "cmd": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'", "single": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'"},
            {"name": "PSExec", "cmd": "impacket-psexec '{domain}/{user}:<PASSWORD>'@{target}", "single": "impacket-psexec '{domain}/{user}:<PASSWORD>'@{target}"},
            {"name": "WMIExec", "cmd": "impacket-wmiexec '{domain}/{user}:<PASSWORD>'@{target}", "single": "impacket-wmiexec '{domain}/{user}:<PASSWORD>'@{target}"},
        ],
    },
    "CanRDP": {
        "name": "RDP Access",
        "protocols": [
            {"name": "xfreerdp", "cmd": "xfreerdp /v:{target} /u:{user} /p:'<PASSWORD>' /cert:ignore", "single": "xfreerdp /v:{target} /u:{user} /p:'<PASSWORD>' /cert:ignore"},
            {"name": "rdesktop", "cmd": "rdesktop -u {user} -p '<PASSWORD>' {target}", "single": "rdesktop -u {user} -p '<PASSWORD>' {target}"},
        ],
    },
    "CanPSRemote": {
        "name": "PS Remoting",
        "protocols": [
            {"name": "WinRM (evil-winrm)", "cmd": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'", "single": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'"},
            {"name": "WinRM (CrackMapExec)", "cmd": "crackmapexec winrm {targets} -u {users} -p '<PASSWORD>'", "single": "crackmapexec winrm {target} -u {user} -p '<PASSWORD>'"},
        ],
    },
    "ExecuteDCOM": {
        "name": "DCOM Execution",
        "protocols": [
            {"name": "DCOMExec", "cmd": "impacket-dcomexec '{domain}/{user}:<PASSWORD>'@{target}", "single": "impacket-dcomexec '{domain}/{user}:<PASSWORD>'@{target}"},
        ],
    },
    "ReadLAPSPassword": {
        "name": "LAPS Password",
        "protocols": [
            {"name": "LDAP Query", "cmd": "crackmapexec ldap {target} -u {user} -p '<PASSWORD>' -M laps", "single": "crackmapexec ldap {target} -u {user} -p '<PASSWORD>' -M laps"},
            {"name": "LAPSDumper", "cmd": "python3 laps.py -u {user} -p '<PASSWORD>' -d {domain}", "single": "python3 laps.py -u {user} -p '<PASSWORD>' -d {domain}"},
        ],
    },
}

ACCESS_PRIORITY = ["AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM", "ReadLAPSPassword"]

MONOLITHIC_PROTOCOLS = {
    "AdminTo": ("crackmapexec smb", 'crackmapexec smb {target} -u {user} -p "$PASSWORD"'),
    "CanPSRemote": ("evil-winrm", 'evil-winrm -i {target} -u {user} -p "$PASSWORD"'),
    "CanRDP": ("xfreerdp3", 'xfreerdp3 /v:{target} /u:{user} /p:"$PASSWORD" /cert:ignore'),
    "ExecuteDCOM": ("dcomexec", "impacket-dcomexec '{domain}/{user}:$PASSWORD'@{target}"),
    "ReadLAPSPassword": ("crackmapexec ldap", 'crackmapexec ldap {target} -u {user} -p "$PASSWORD" -M laps'),
}

EDGE_DESCRIPTIONS = {
    "AdminTo": "local admin → SMB auth",
    "CanPSRemote": "WinRM → evil-winrm auth",
    "CanRDP": "RDP → xfreerdp3 auth",
    "ExecuteDCOM": "DCOM → dcomexec auth",
    "ReadLAPSPassword": "LAPS read → ldap query",
}


def _extract_username(upn: str) -> str:
    """Extract username from UPN format (USER@DOMAIN.COM -> user)."""
    if "@" in upn:
        return upn.split("@")[0].lower()
    return upn.lower()


def _extract_domain(upn: str) -> str:
    """Extract domain from UPN format (USER@DOMAIN.COM -> DOMAIN.COM)."""
    if "@" in upn:
        return upn.split("@")[1]
    return ""


def _extract_short_hostname(fqdn: str) -> str:
    """Extract short hostname from FQDN (CLIENT74.CORP.COM -> CLIENT74)."""
    if "." in fqdn:
        return fqdn.split(".")[0]
    return fqdn


def _select_best_target_for_user(user_access: dict) -> dict:
    """
    Select the best target for a user based on access type priority.

    Args:
        user_access: {access_type: [(computer, ip, inherited_from), ...]}

    Returns:
        Dict with access_type, computer, ip, inherited_from, had_rdp_but_skipped
    """
    had_rdp = "CanRDP" in user_access
    non_rdp_types = [t for t in user_access.keys() if t != "CanRDP"]
    had_better_than_rdp = len(non_rdp_types) > 0

    for access_type in ACCESS_PRIORITY:
        if access_type == "CanRDP" and had_better_than_rdp:
            continue

        if access_type in user_access and user_access[access_type]:
            targets = sorted(user_access[access_type], key=lambda x: x[0])
            computer, ip, inherited_from = targets[0]

            return {
                "access_type": access_type,
                "computer": computer,
                "ip": ip,
                "inherited_from": inherited_from,
                "had_rdp_but_skipped": had_rdp and had_better_than_rdp and access_type != "CanRDP",
            }

    return None


def _group_by_common_targets(user_targets: dict, access_type: str) -> list:
    """
    Group users by common target subsets.

    Args:
        user_targets: {username: set(targets)} for a specific access type
        access_type: The access type being processed

    Returns:
        List of groups: [{users: [...], targets: [...], target_ips: {...}}]
    """
    if not user_targets:
        return []

    groups = []
    users = list(user_targets.keys())
    target_sets = {u: set(t for t, ip in targets) for u, targets in user_targets.items()}
    ip_mapping = {}
    for u, targets in user_targets.items():
        for t, ip in targets:
            if ip:
                ip_mapping[t] = ip

    processed_target_sets = {}
    for user in users:
        targets_frozen = frozenset(target_sets[user])
        if targets_frozen not in processed_target_sets:
            processed_target_sets[targets_frozen] = []
        processed_target_sets[targets_frozen].append(user)

    for targets_frozen, group_users in processed_target_sets.items():
        targets_list = sorted(list(targets_frozen))
        target_ips = {t: ip_mapping.get(t) for t in targets_list}
        groups.append({
            "users": sorted(group_users),
            "targets": targets_list,
            "target_ips": target_ips,
        })

    groups.sort(key=lambda g: (-len(g["targets"]), -len(g["users"])))
    return groups


def _generate_monolithic_spray(
    access_data: list,
    domain: str = "",
    use_colors: bool = True,
) -> tuple:
    """
    Generate monolithic spray commands - one attempt per user on their best target.

    Args:
        access_data: List from get_all_users_with_access() with inherited_from field
        domain: Domain name for command templates
        use_colors: Enable ANSI colors

    Returns:
        Tuple of (console_lines, markdown_lines)
    """
    c = Colors if use_colors else NoColors

    console_lines = []
    markdown_lines = []

    if not access_data:
        return [], []

    # Build user -> access_type -> [(computer, ip, inherited_from)] mapping
    user_all_access = {}
    for entry in access_data:
        user = _extract_username(entry["user"])
        computer = entry["computer"]
        access_type = entry["access_type"]
        ip = entry.get("ip")
        inherited_from = entry.get("inherited_from")

        if user not in user_all_access:
            user_all_access[user] = {}
        if access_type not in user_all_access[user]:
            user_all_access[user][access_type] = []
        user_all_access[user][access_type].append((computer, ip, inherited_from))

    # Select best target for each user
    user_selections = {}
    edge_counts = {at: 0 for at in ACCESS_PRIORITY}
    rdp_avoided_count = 0

    for user, access_dict in user_all_access.items():
        selection = _select_best_target_for_user(access_dict)
        if selection:
            user_selections[user] = selection
            edge_counts[selection["access_type"]] += 1
            if selection["had_rdp_but_skipped"]:
                rdp_avoided_count += 1

    if not user_selections:
        return [], []

    # Header
    console_lines.append("")
    console_lines.append(f"  {c.CYAN}{c.BOLD}{'='*74}{c.RESET}")
    console_lines.append(f"  {c.BOLD}MONOLITHIC SPRAY{c.RESET}")
    console_lines.append(f"  {c.DIM}One attempt per user on their best target - set password once{c.RESET}")
    console_lines.append(f"  {c.CYAN}{'='*74}{c.RESET}")

    markdown_lines.append("## Monolithic Spray")
    markdown_lines.append("")
    markdown_lines.append("One attempt per user on their best target. Set `PASSWORD` once at the top.")
    markdown_lines.append("")

    # Edge Selection Logic
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}EDGE SELECTION LOGIC (this report):{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*40}{c.RESET}")

    markdown_lines.append("### Edge Selection Logic")
    markdown_lines.append("")
    markdown_lines.append("```")

    for access_type in ACCESS_PRIORITY:
        count = edge_counts[access_type]
        if count > 0 or access_type == "CanRDP":
            desc = EDGE_DESCRIPTIONS.get(access_type, access_type)
            user_word = "user" if count == 1 else "users"

            if access_type == "CanRDP" and rdp_avoided_count > 0:
                line = f"  {count} {user_word} via {access_type} ({desc}) - {rdp_avoided_count} avoided (had better options)"
            else:
                line = f"  {count} {user_word} via {access_type} ({desc})"

            console_lines.append(f"  {c.DIM}{line}{c.RESET}")
            markdown_lines.append(line)

    console_lines.append(f"  {c.DIM}  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword{c.RESET}")
    console_lines.append(f"  {c.DIM}  Each user sprayed exactly once on their highest-privilege target{c.RESET}")

    markdown_lines.append("  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword")
    markdown_lines.append("  Each user sprayed exactly once on their highest-privilege target")
    markdown_lines.append("```")
    markdown_lines.append("")

    # Commands block
    console_lines.append("")
    console_lines.append(f"  {c.BOLD}Copy-paste command block:{c.RESET}")
    console_lines.append("")

    markdown_lines.append("### Commands")
    markdown_lines.append("")
    markdown_lines.append("```bash")

    console_lines.append(f"  {c.GREEN}PASSWORD='<PASSWORD>'{c.RESET}")
    console_lines.append("")
    markdown_lines.append("PASSWORD='<PASSWORD>'")
    markdown_lines.append("")

    domain_short = domain.split(".")[0] if domain else "<DOMAIN>"

    for user in sorted(user_selections.keys()):
        sel = user_selections[user]
        access_type = sel["access_type"]
        computer = sel["computer"]
        ip = sel["ip"]
        inherited_from = sel["inherited_from"]

        target = ip if ip else _extract_short_hostname(computer)
        hostname_short = _extract_short_hostname(computer)

        if inherited_from:
            inherited_short = _extract_username(inherited_from) if "@" in str(inherited_from) else inherited_from
            cypher_path = f"MATCH ({user})-[:MemberOf*]->({inherited_short})-[:{access_type}]->({hostname_short})"
            access_note = f"{access_type} via {inherited_short}"
        else:
            cypher_path = f"MATCH ({user})-[:{access_type}]->({hostname_short})"
            access_note = f"{access_type} (direct)"

        tool_name, cmd_template = MONOLITHIC_PROTOCOLS.get(access_type, ("unknown", "# unknown access type"))
        cmd = cmd_template.format(target=target, user=user, domain=domain_short)

        console_lines.append(f"  {c.DIM}# --- {user} → {target} ({hostname_short}) ---{c.RESET}")
        console_lines.append(f"  {c.DIM}# {access_note}: {cypher_path}{c.RESET}")

        if sel["had_rdp_but_skipped"]:
            console_lines.append(f"  {c.DIM}# Note: User also has CanRDP, using {access_type} instead{c.RESET}")

        console_lines.append(f"  {c.GREEN}{cmd}{c.RESET}")
        console_lines.append("")

        markdown_lines.append(f"# --- {user} → {target} ({hostname_short}) ---")
        markdown_lines.append(f"# {access_note}: {cypher_path}")
        if sel["had_rdp_but_skipped"]:
            markdown_lines.append(f"# Note: User also has CanRDP, using {access_type} instead")
        markdown_lines.append(cmd)
        markdown_lines.append("")

    markdown_lines.append("```")
    markdown_lines.append("")

    return console_lines, markdown_lines


def print_spray_tailored(
    access_data: list,
    domain: str = "",
    use_colors: bool = True,
) -> tuple:
    """
    Print tailored spray commands based on BloodHound access data.

    Groups users by identical machine access patterns to reduce redundancy.
    Shows both file-based and inline bash loop formats.

    Args:
        access_data: List from get_all_users_with_access()
        domain: Domain name for command templates
        use_colors: Enable ANSI colors

    Returns:
        Tuple of (console_output, markdown_output)
    """
    c = Colors if use_colors else NoColors

    console_lines = []
    markdown_lines = []

    # Build user -> {access_type -> set((target, ip))} mapping
    user_access = {}
    for entry in access_data:
        user = entry["user"]
        computer = entry["computer"]
        access_type = entry["access_type"]
        ip = entry.get("ip")

        if user not in user_access:
            user_access[user] = {}
        if access_type not in user_access[user]:
            user_access[user][access_type] = set()
        user_access[user][access_type].add((computer, ip))

    # Count statistics
    unique_users = len(user_access)
    unique_computers = len(set(e["computer"] for e in access_data))
    access_types_found = set(e["access_type"] for e in access_data)

    # Header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}{'='*78}{c.RESET}")
    console_lines.append(f"  {c.BOLD}TAILORED SPRAY COMMANDS{c.RESET}")
    console_lines.append(f"  {c.DIM}Based on BloodHound access relationships{c.RESET}")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")

    markdown_lines.append("# Tailored Spray Commands")
    markdown_lines.append("")
    markdown_lines.append("Based on BloodHound access relationships.")
    markdown_lines.append("")

    # Summary
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}SUMMARY{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")
    console_lines.append(f"    Users with access:    {c.BOLD}{unique_users}{c.RESET}")
    console_lines.append(f"    Target machines:      {c.BOLD}{unique_computers}{c.RESET}")
    console_lines.append(f"    Access types found:   {c.BOLD}{', '.join(sorted(access_types_found))}{c.RESET}")

    markdown_lines.append("## Summary")
    markdown_lines.append("")
    markdown_lines.append(f"- **Users with access:** {unique_users}")
    markdown_lines.append(f"- **Target machines:** {unique_computers}")
    markdown_lines.append(f"- **Access types:** {', '.join(sorted(access_types_found))}")
    markdown_lines.append("")

    if not access_data:
        console_lines.append("")
        console_lines.append(f"  {c.YELLOW}No user-to-machine access relationships found.{c.RESET}")
        markdown_lines.append("*No user-to-machine access relationships found.*")
        return "\n".join(console_lines), "\n".join(markdown_lines)

    # Group by access type
    for access_type in ["AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "ReadLAPSPassword"]:
        if access_type not in access_types_found:
            continue

        protocol_info = ACCESS_TYPE_PROTOCOLS.get(access_type, {})
        access_name = protocol_info.get("name", access_type)
        protocols = protocol_info.get("protocols", [])

        user_targets = {}
        for user, access_dict in user_access.items():
            if access_type in access_dict:
                user_targets[_extract_username(user)] = access_dict[access_type]

        if not user_targets:
            continue

        groups = _group_by_common_targets(user_targets, access_type)

        console_lines.append("")
        console_lines.append(f"  {c.CYAN}{c.BOLD}{'='*74}{c.RESET}")
        console_lines.append(f"  {c.BOLD}{access_name.upper()} ({access_type}){c.RESET}")
        console_lines.append(f"  {c.DIM}{len(user_targets)} users, {len(groups)} unique target groups{c.RESET}")
        console_lines.append(f"  {c.CYAN}{'='*74}{c.RESET}")

        markdown_lines.append(f"## {access_name} ({access_type})")
        markdown_lines.append("")
        markdown_lines.append(f"{len(user_targets)} users, {len(groups)} unique target groups")
        markdown_lines.append("")

        for group_idx, group in enumerate(groups, 1):
            users = group["users"]
            targets = group["targets"]
            target_ips = group["target_ips"]

            ips_or_hosts = []
            for t in targets:
                ip = target_ips.get(t)
                if ip:
                    ips_or_hosts.append(ip)
                else:
                    hostname = t.split(".")[0] if "." in t else t
                    ips_or_hosts.append(hostname)

            console_lines.append("")
            console_lines.append(f"  {c.YELLOW}{c.BOLD}Group {group_idx}: {len(users)} user(s) → {len(targets)} target(s){c.RESET}")
            console_lines.append(f"  {c.DIM}Users: {', '.join(users)}{c.RESET}")

            markdown_lines.append(f"### Group {group_idx}: {len(users)} user(s) → {len(targets)} target(s)")
            markdown_lines.append("")
            markdown_lines.append(f"**Users:** `{', '.join(users)}`")
            markdown_lines.append("")

            console_lines.append(f"  {c.DIM}Targets:{c.RESET}")
            markdown_lines.append("**Targets:**")
            markdown_lines.append("")
            for t in targets:
                ip = target_ips.get(t)
                if ip:
                    console_lines.append(f"    - {t} ({ip})")
                    markdown_lines.append(f"- `{t}` ({ip})")
                else:
                    console_lines.append(f"    - {t}")
                    markdown_lines.append(f"- `{t}`")
            markdown_lines.append("")

            # File-based commands
            console_lines.append("")
            console_lines.append(f"  {c.BOLD}File-based commands:{c.RESET}")
            markdown_lines.append("#### File-based commands")
            markdown_lines.append("")

            users_str = "\\n".join(users)
            targets_str = "\\n".join(ips_or_hosts)

            console_lines.append(f"    {c.GREEN}# Create user and target files{c.RESET}")
            console_lines.append(f"    {c.GREEN}echo -e \"{users_str}\" > users_g{group_idx}.txt{c.RESET}")
            console_lines.append(f"    {c.GREEN}echo -e \"{targets_str}\" > targets_g{group_idx}.txt{c.RESET}")

            markdown_lines.append("```bash")
            markdown_lines.append("# Create user and target files")
            markdown_lines.append(f'echo -e "{users_str}" > users_g{group_idx}.txt')
            markdown_lines.append(f'echo -e "{targets_str}" > targets_g{group_idx}.txt')

            if protocols:
                proto = protocols[0]
                cmd = proto["cmd"]
                cmd = cmd.replace("{targets}", f"targets_g{group_idx}.txt")
                cmd = cmd.replace("{users}", f"users_g{group_idx}.txt")
                cmd = cmd.replace("{target}", f"targets_g{group_idx}.txt")
                cmd = cmd.replace("{user}", f"users_g{group_idx}.txt")
                cmd = cmd.replace("{domain}", domain.split(".")[0] if domain else "<DOMAIN>")
                console_lines.append(f"    {c.GREEN}{cmd}{c.RESET}")
                markdown_lines.append(cmd)

            markdown_lines.append("```")
            markdown_lines.append("")

            # Inline bash loop
            console_lines.append("")
            console_lines.append(f"  {c.BOLD}Inline bash loop:{c.RESET}")
            markdown_lines.append("#### Inline bash loop")
            markdown_lines.append("")

            users_inline = " ".join(users)
            targets_inline = " ".join(ips_or_hosts)

            if protocols:
                proto = protocols[0]
                single_cmd = proto.get("single", proto["cmd"])
                single_cmd = single_cmd.replace("{domain}", domain.split(".")[0] if domain else "<DOMAIN>")

                console_lines.append(f"    {c.GREEN}for user in {users_inline}; do{c.RESET}")
                console_lines.append(f"    {c.GREEN}  for target in {targets_inline}; do{c.RESET}")
                console_lines.append(f"    {c.GREEN}    {single_cmd.replace('{user}', '$user').replace('{target}', '$target')}{c.RESET}")
                console_lines.append(f"    {c.GREEN}  done{c.RESET}")
                console_lines.append(f"    {c.GREEN}done{c.RESET}")

                markdown_lines.append("```bash")
                markdown_lines.append(f"for user in {users_inline}; do")
                markdown_lines.append(f"  for target in {targets_inline}; do")
                markdown_lines.append(f"    {single_cmd.replace('{user}', '$user').replace('{target}', '$target')}")
                markdown_lines.append("  done")
                markdown_lines.append("done")
                markdown_lines.append("```")
                markdown_lines.append("")

            # Alternative protocols
            if len(protocols) > 1:
                console_lines.append("")
                console_lines.append(f"  {c.DIM}Alternative protocols:{c.RESET}")
                markdown_lines.append("**Alternative protocols:**")
                markdown_lines.append("")

                for proto in protocols[1:]:
                    single_cmd = proto.get("single", proto["cmd"])
                    single_cmd = single_cmd.replace("{domain}", domain.split(".")[0] if domain else "<DOMAIN>")
                    single_cmd = single_cmd.replace("{user}", users[0])
                    single_cmd = single_cmd.replace("{target}", ips_or_hosts[0] if ips_or_hosts else "<TARGET>")

                    console_lines.append(f"    {c.DIM}# {proto['name']}{c.RESET}")
                    console_lines.append(f"    {c.GREEN}{single_cmd}{c.RESET}")

                    markdown_lines.append(f"```bash")
                    markdown_lines.append(f"# {proto['name']}")
                    markdown_lines.append(single_cmd)
                    markdown_lines.append("```")
                    markdown_lines.append("")

    # Monolithic spray section
    mono_console, mono_markdown = _generate_monolithic_spray(access_data, domain, use_colors)
    console_lines.extend(mono_console)
    markdown_lines.extend(mono_markdown)

    # Footer
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}NOTE:{c.RESET} Replace '<PASSWORD>' with actual credentials.")
    console_lines.append(f"  {c.DIM}Commands are based on BloodHound data - verify access before exploitation.{c.RESET}")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")
    console_lines.append("")

    markdown_lines.append("---")
    markdown_lines.append("")
    markdown_lines.append("> **NOTE:** Replace `<PASSWORD>` with actual credentials.")
    markdown_lines.append("")

    return "\n".join(console_lines), "\n".join(markdown_lines)
