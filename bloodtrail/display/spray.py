"""
Password spray recommendations for bloodtrail.

Shows spray methods, scenarios, and one-liners based on captured credentials.
"""

from typing import List

from .base import Colors, NoColors, extract_creds_from_pwned_users, fill_spray_template


def print_spray_recommendations(
    pwned_users: List = None,
    policy = None,
    domain: str = "",
    dc_ip: str = "<DC_IP>",
    use_colors: bool = True,
    method_filter: str = "all",
    all_ips: List[str] = None,
) -> None:
    """
    Print password spray recommendations based on captured credentials and policy.

    Delegates to generate_spray_section() for core output, then handles
    method_filter and all_ips-specific features.

    Args:
        pwned_users: List of PwnedUser objects with credentials
        policy: Optional PasswordPolicy for safe spray planning
        domain: Domain name for command templates
        dc_ip: Domain Controller IP
        use_colors: Enable ANSI colors
        method_filter: Filter to specific method (smb, kerberos, ldap, all)
        all_ips: List of resolved IPs from Neo4j for multi-target loops
    """
    c = Colors if use_colors else NoColors
    pwned_users = pwned_users or []
    passwords, usernames = extract_creds_from_pwned_users(pwned_users)

    # For "all" filter, use full generate_spray_section output
    if method_filter == "all":
        console_out, _ = generate_spray_section(
            pwned_users=pwned_users,
            policy=policy,
            domain=domain,
            dc_ip=dc_ip,
            use_colors=use_colors,
        )
        if console_out:
            lines = console_out.rstrip().split('\n')
            if lines and '=' * 78 in lines[-1]:
                lines = lines[:-1]
            print('\n'.join(lines))

        # Add ALL TARGETS section
        if all_ips is not None:
            first_pwd = passwords[0] if passwords else "<PASSWORD>"
            first_user = usernames[0] if usernames else "<USERNAME>"
            _print_all_targets_section(
                all_ips=all_ips,
                password=first_pwd,
                username=first_user,
                domain=domain,
                c=c,
            )

        print()
        print(f"{c.CYAN}{'='*78}{c.RESET}")
        print()
        return

    # For filtered output (smb/kerberos/ldap only)
    from ..mappings.spray import SPRAY_TECHNIQUES, SPRAY_ONELINERS

    def fill_template(cmd: str, pwd: str = "<PASSWORD>") -> str:
        return fill_spray_template(cmd, dc_ip, domain, pwd, usernames)

    print()
    print(f"{c.CYAN}{c.BOLD}{'='*78}{c.RESET}")
    print(f"  {c.BOLD}PASSWORD SPRAYING - {method_filter.upper()} METHOD{c.RESET}")
    print(f"{c.CYAN}{'='*78}{c.RESET}")

    method_map = {"smb": ("smb", "1"), "kerberos": ("kerberos", "2"), "ldap": ("ldap", "3")}
    if method_filter in method_map:
        tech_key, num = method_map[method_filter]
        tech = SPRAY_TECHNIQUES.get(tech_key)
        if tech:
            print()
            print(f"  {c.CYAN}{c.BOLD}METHOD {num}: {tech.name}{c.RESET}")
            print(f"  {c.DIM}Ports: {', '.join(str(p) for p in tech.ports)} | Noise: {tech.noise_level.upper()}{c.RESET}")
            print()

            template_key = "single_password" if tech_key != "ldap" else "spray_ps1"
            template = tech.command_templates.get(template_key, "")
            if template:
                if passwords and tech_key != "ldap":
                    for pwd in passwords[:3]:
                        cmd = fill_template(template, pwd)
                        print(f"    {c.GREEN}{cmd}{c.RESET}")
                else:
                    pwd = passwords[0] if passwords else "<PASSWORD>"
                    cmd = fill_template(template, pwd)
                    print(f"    {c.GREEN}{cmd}{c.RESET}")

            print()
            print(f"    {c.GREEN}+ {tech.advantages}{c.RESET}")
            print(f"    {c.RED}- {tech.disadvantages}{c.RESET}")

    # Show relevant one-liners
    print()
    print(f"  {c.YELLOW}{c.BOLD}SPRAY ONE-LINERS{c.RESET}")
    print(f"  {c.DIM}{'-'*70}{c.RESET}")
    first_pwd = passwords[0] if passwords else "<PASSWORD>"
    for i, oneliner in enumerate(SPRAY_ONELINERS, 1):
        cmd = fill_template(oneliner["cmd"], first_pwd)
        print(f"  {c.BOLD}{i}. {oneliner['name']}{c.RESET}")
        print(f"     {c.GREEN}{cmd}{c.RESET}")
        print()

    print(f"{c.CYAN}{'='*78}{c.RESET}")
    print()


def _print_all_targets_section(
    all_ips: List[str],
    password: str,
    username: str,
    domain: str,
    c,  # Colors class
) -> None:
    """
    Print credential validation loops for all discovered hosts.

    Shows bash loops for SMB, WinRM, RDP, and MSSQL protocols.
    """
    from ..mappings.spray import ALL_TARGETS_PROTOCOLS, ALL_TARGETS_IP_THRESHOLD

    if not all_ips:
        print()
        print(f"  {c.YELLOW}{c.BOLD}ALL TARGETS - Credential Validation{c.RESET}")
        print(f"  {c.DIM}{'-'*70}{c.RESET}")
        print(f"  {c.RED}No resolved IPs in BloodHound data.{c.RESET}")
        print(f"  {c.DIM}Run: crack bloodtrail --refresh-ips to resolve hostnames{c.RESET}")
        return

    ip_count = len(all_ips)
    use_file = ip_count > ALL_TARGETS_IP_THRESHOLD

    print()
    print(f"  {c.CYAN}{c.BOLD}ALL TARGETS - Credential Validation Loops{c.RESET}")
    print(f"  {c.DIM}Test where captured creds can authenticate across the network{c.RESET}")
    print(f"  {c.DIM}{ip_count} hosts with resolved IPs from BloodHound data{c.RESET}")
    print(f"  {c.DIM}{'-'*70}{c.RESET}")

    safe_password = password.replace("'", "'\"'\"'") if password else "<PASSWORD>"
    safe_username = username if username else "<USERNAME>"
    domain_lower = domain.lower() if domain else "<DOMAIN>"

    if use_file:
        print()
        print(f"  {c.YELLOW}# First, create targets file:{c.RESET}")
        print(f"  {c.GREEN}cat << 'EOF' > targets.txt{c.RESET}")
        for ip in all_ips[:5]:
            print(f"  {c.GREEN}{ip}{c.RESET}")
        if ip_count > 10:
            print(f"  {c.DIM}... ({ip_count - 10} more IPs) ...{c.RESET}")
        for ip in all_ips[-5:]:
            print(f"  {c.GREEN}{ip}{c.RESET}")
        print(f"  {c.GREEN}EOF{c.RESET}")

        print()
        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            port = config["port"]
            desc = config["description"]
            template = config["file_template"]

            cmd = template.format(
                targets_file="targets.txt",
                user_file="users.txt",
                username=safe_username,
                password=safe_password,
                domain=domain_lower,
            )

            print(f"  {c.BOLD}# {proto.upper()} (port {port}){c.RESET} {c.DIM}- {desc}{c.RESET}")
            print(f"  {c.GREEN}{cmd}{c.RESET}")
            print()
    else:
        ips_inline = " ".join(all_ips)

        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            port = config["port"]
            desc = config["description"]
            template = config["loop_template"]

            cmd = template.format(
                ips=ips_inline,
                user_file="users.txt",
                username=safe_username,
                password=safe_password,
                domain=domain_lower,
            )

            print()
            print(f"  {c.BOLD}# {proto.upper()} (port {port}){c.RESET} {c.DIM}- {desc}{c.RESET}")
            print(f"  {c.GREEN}{cmd}{c.RESET}")


def generate_spray_section(
    pwned_users: List = None,
    policy = None,
    domain: str = "",
    dc_ip: str = "<DC_IP>",
    use_colors: bool = True,
) -> tuple:
    """
    Generate Password Spray Recommendations section for the report.

    Returns both console-formatted and markdown-formatted output.

    Args:
        pwned_users: List of PwnedUser objects with credentials
        policy: Optional PasswordPolicy for safe spray planning
        domain: Domain name for command templates
        dc_ip: Domain Controller IP
        use_colors: Enable ANSI colors for console output

    Returns:
        Tuple of (console_output: str, markdown_output: str)
    """
    from ..mappings.spray import (
        SPRAY_TECHNIQUES,
        SPRAY_SCENARIOS,
        USER_ENUM_COMMANDS,
        PASSWORD_LIST_COMMANDS,
        PASSWORD_LIST_SCENARIOS,
        SPRAY_ONELINERS,
    )

    c = Colors if use_colors else NoColors
    pwned_users = pwned_users or []

    passwords, usernames = extract_creds_from_pwned_users(pwned_users)

    # Only show section if we have passwords
    if not passwords:
        return "", ""

    console_lines = []
    markdown_lines = []

    def fill_template(cmd: str, pwd: str = "<PASSWORD>") -> str:
        return fill_spray_template(cmd, dc_ip, domain, pwd, usernames)

    # Header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}╔══════════════════════════════════════════════════════════════════════════╗{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}║{c.RESET}   {c.RED}🔑{c.RESET} {c.BOLD}Password Spray Recommendations{c.RESET}                                     {c.CYAN}{c.BOLD}║{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}╚══════════════════════════════════════════════════════════════════════════╝{c.RESET}")
    console_lines.append("")

    markdown_lines.append("## 🔑 Password Spray Recommendations")
    markdown_lines.append("")

    # Captured passwords
    console_lines.append(f"  {c.BOLD}CAPTURED PASSWORDS{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")
    for pwd in passwords[:5]:
        console_lines.append(f"    {c.GREEN}{pwd}{c.RESET}")
    if len(passwords) > 5:
        console_lines.append(f"    {c.DIM}... and {len(passwords) - 5} more{c.RESET}")
    console_lines.append("")

    markdown_lines.append("### Captured Passwords")
    markdown_lines.append("")
    markdown_lines.append("```")
    for pwd in passwords[:5]:
        markdown_lines.append(pwd)
    if len(passwords) > 5:
        markdown_lines.append(f"... and {len(passwords) - 5} more")
    markdown_lines.append("```")
    markdown_lines.append("")

    # Password policy
    if policy:
        console_lines.append(f"  {c.BOLD}PASSWORD POLICY{c.RESET}")
        console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")
        console_lines.append(f"    Lockout threshold: {c.YELLOW}{policy.lockout_threshold}{c.RESET} attempts")
        console_lines.append(f"    Lockout duration:  {c.YELLOW}{policy.lockout_duration}{c.RESET} minutes")
        console_lines.append(f"    Observation window: {c.YELLOW}{policy.observation_window}{c.RESET} minutes")
        console_lines.append(f"    {c.GREEN}Safe to spray: {policy.safe_spray_attempts} passwords every {policy.spray_delay_minutes} min{c.RESET}")
        console_lines.append("")

        markdown_lines.append("### Password Policy")
        markdown_lines.append("")
        markdown_lines.append(f"- Lockout threshold: **{policy.lockout_threshold}** attempts")
        markdown_lines.append(f"- Lockout duration: **{policy.lockout_duration}** minutes")
        markdown_lines.append(f"- Safe to spray: **{policy.safe_spray_attempts}** passwords every **{policy.spray_delay_minutes}** min")
        markdown_lines.append("")

    # Spray methods
    console_lines.append(f"  {c.BOLD}SPRAY METHODS{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")

    markdown_lines.append("### Spray Methods")
    markdown_lines.append("")

    method_num = 1
    for tech_key, tech in SPRAY_TECHNIQUES.items():
        console_lines.append("")
        console_lines.append(f"  {c.CYAN}{c.BOLD}METHOD {method_num}: {tech.name}{c.RESET}")
        console_lines.append(f"  {c.DIM}Ports: {', '.join(str(p) for p in tech.ports)} | Noise: {tech.noise_level.upper()}{c.RESET}")
        console_lines.append("")

        markdown_lines.append(f"#### Method {method_num}: {tech.name}")
        markdown_lines.append("")
        markdown_lines.append(f"Ports: {', '.join(str(p) for p in tech.ports)} | Noise: {tech.noise_level.upper()}")
        markdown_lines.append("")

        template_key = "single_password" if tech_key != "ldap" else "spray_ps1"
        template = tech.command_templates.get(template_key, "")
        if template:
            for pwd in passwords[:2]:
                cmd = fill_template(template, pwd)
                console_lines.append(f"    {c.GREEN}{cmd}{c.RESET}")
                markdown_lines.append(f"```bash\n{cmd}\n```")

        console_lines.append("")
        console_lines.append(f"    {c.GREEN}+ {tech.advantages}{c.RESET}")
        console_lines.append(f"    {c.RED}- {tech.disadvantages}{c.RESET}")

        markdown_lines.append(f"- ✅ {tech.advantages}")
        markdown_lines.append(f"- ❌ {tech.disadvantages}")
        markdown_lines.append("")

        method_num += 1

    # User enumeration
    console_lines.append("")
    console_lines.append(f"  {c.BOLD}USER ENUMERATION{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")

    markdown_lines.append("### User Enumeration")
    markdown_lines.append("")

    # USER_ENUM_COMMANDS is a nested dict: {"linux": {"name": {...}}, "windows": {...}}
    # Show Linux commands for spray section (Kali-based attacks)
    linux_cmds = USER_ENUM_COMMANDS.get("linux", {})
    for name, cmd_info in linux_cmds.items():
        cmd = fill_template(cmd_info["cmd"])
        console_lines.append(f"  {c.DIM}# {cmd_info.get('description', name)}{c.RESET}")
        console_lines.append(f"  {c.GREEN}{cmd}{c.RESET}")
        console_lines.append("")

        markdown_lines.append(f"**{cmd_info.get('description', name)}**")
        markdown_lines.append(f"```bash\n{cmd}\n```")
        markdown_lines.append("")

    # Spray one-liners
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}SPRAY ONE-LINERS{c.RESET}")
    console_lines.append(f"  {c.DIM}Complete attack workflows - copy/paste ready:{c.RESET}")
    console_lines.append("")

    markdown_lines.append("### Spray One-Liners")
    markdown_lines.append("")

    first_pwd = passwords[0] if passwords else "<PASSWORD>"
    for i, oneliner in enumerate(SPRAY_ONELINERS, 1):
        name = oneliner["name"]
        desc = oneliner["description"]
        cmd = fill_template(oneliner["cmd"], first_pwd)

        console_lines.append(f"  {c.BOLD}{i}. {name}{c.RESET}")
        console_lines.append(f"     {c.DIM}{desc}{c.RESET}")
        console_lines.append(f"     {c.GREEN}{cmd}{c.RESET}")
        console_lines.append("")

        markdown_lines.append(f"**{i}. {name}**")
        markdown_lines.append(f"_{desc}_")
        markdown_lines.append(f"```bash\n{cmd}\n```")
        markdown_lines.append("")

    # Exam tip
    console_lines.append("")
    threshold = policy.lockout_threshold if policy else 5
    safe = policy.safe_spray_attempts if policy else 4
    window = policy.spray_delay_minutes if policy else 30
    console_lines.append(f"  {c.YELLOW}{c.BOLD}EXAM TIP:{c.RESET} Before spraying, always check {c.GREEN}net accounts{c.RESET} to verify lockout.")
    console_lines.append(f"  {c.DIM}With {threshold}-attempt lockout, safely attempt {safe} passwords per {window} min window.{c.RESET}")

    console_lines.append("")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")
    console_lines.append("")

    markdown_lines.append(f"> **EXAM TIP:** Before spraying, check `net accounts` for lockout policy.")
    markdown_lines.append("")

    return "\n".join(console_lines), "\n".join(markdown_lines)
