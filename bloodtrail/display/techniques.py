"""
Technique comparison display for bloodtrail.

Renders technique comparison tables showing noise levels, ports,
advantages and disadvantages of lateral movement techniques.
"""

from typing import List


def print_technique_legend(techniques: List, c) -> None:
    """
    Print comparison table for lateral movement techniques.

    Shows noise level, ports, advantages, and disadvantages for each technique.
    """
    if not techniques:
        return

    # Table dimensions
    w_tech = 10
    w_noise = 6
    w_ports = 7
    w_adv = 28
    w_dis = 24
    total_w = w_tech + w_noise + w_ports + w_adv + w_dis + 6  # +6 for separators

    # Noise level colors
    noise_colors = {"high": c.RED, "medium": c.YELLOW, "low": c.GREEN}

    print()
    print(f"  {c.DIM}┌{'─' * total_w}┐{c.RESET}")
    print(f"  {c.DIM}│{c.RESET} {c.BOLD}Technique Comparison{c.RESET}{' ' * (total_w - 21)}{c.DIM}│{c.RESET}")
    print(f"  {c.DIM}├{'─' * w_tech}┬{'─' * w_noise}┬{'─' * w_ports}┬{'─' * w_adv}┬{'─' * w_dis}┤{c.RESET}")
    print(f"  {c.DIM}│{c.RESET}{'Technique':^{w_tech}}{c.DIM}│{c.RESET}{'Noise':^{w_noise}}{c.DIM}│{c.RESET}{'Ports':^{w_ports}}{c.DIM}│{c.RESET}{'Advantages':^{w_adv}}{c.DIM}│{c.RESET}{'Disadvantages':^{w_dis}}{c.DIM}│{c.RESET}")
    print(f"  {c.DIM}├{'─' * w_tech}┼{'─' * w_noise}┼{'─' * w_ports}┼{'─' * w_adv}┼{'─' * w_dis}┤{c.RESET}")

    for tech in techniques:
        name = tech.name.split()[0].lower()
        noise = tech.noise_level.upper()[:4]
        noise_c = noise_colors.get(tech.noise_level, "")
        ports = ",".join(str(p) for p in tech.ports)

        # Truncate long text
        adv = tech.advantages[:w_adv-2] + ".." if len(tech.advantages) > w_adv else tech.advantages
        dis = tech.disadvantages[:w_dis-2] + ".." if len(tech.disadvantages) > w_dis else tech.disadvantages

        print(f"  {c.DIM}│{c.RESET}{name:^{w_tech}}{c.DIM}│{c.RESET}{noise_c}{noise:^{w_noise}}{c.RESET}{c.DIM}│{c.RESET}{ports:^{w_ports}}{c.DIM}│{c.RESET}{adv:<{w_adv}}{c.DIM}│{c.RESET}{dis:<{w_dis}}{c.DIM}│{c.RESET}")

    print(f"  {c.DIM}└{'─' * w_tech}┴{'─' * w_noise}┴{'─' * w_ports}┴{'─' * w_adv}┴{'─' * w_dis}┘{c.RESET}")


def generate_technique_legend_console(techniques: List, c) -> str:
    """Generate technique comparison table for console output (string version)."""
    if not techniques:
        return ""

    lines = []
    w_tech, w_noise, w_ports, w_adv, w_dis = 10, 6, 7, 28, 24
    total_w = w_tech + w_noise + w_ports + w_adv + w_dis + 6

    noise_colors = {"high": c.RED, "medium": c.YELLOW, "low": c.GREEN}

    lines.append("")
    lines.append(f"  {c.DIM}┌{'─' * total_w}┐{c.RESET}")
    lines.append(f"  {c.DIM}│{c.RESET} {c.BOLD}Technique Comparison{c.RESET}{' ' * (total_w - 21)}{c.DIM}│{c.RESET}")
    lines.append(f"  {c.DIM}├{'─' * w_tech}┬{'─' * w_noise}┬{'─' * w_ports}┬{'─' * w_adv}┬{'─' * w_dis}┤{c.RESET}")
    lines.append(f"  {c.DIM}│{c.RESET}{'Technique':^{w_tech}}{c.DIM}│{c.RESET}{'Noise':^{w_noise}}{c.DIM}│{c.RESET}{'Ports':^{w_ports}}{c.DIM}│{c.RESET}{'Advantages':^{w_adv}}{c.DIM}│{c.RESET}{'Disadvantages':^{w_dis}}{c.DIM}│{c.RESET}")
    lines.append(f"  {c.DIM}├{'─' * w_tech}┼{'─' * w_noise}┼{'─' * w_ports}┼{'─' * w_adv}┼{'─' * w_dis}┤{c.RESET}")

    for tech in techniques:
        name = tech.name.split()[0].lower()
        noise = tech.noise_level.upper()[:4]
        noise_c = noise_colors.get(tech.noise_level, "")
        ports = ",".join(str(p) for p in tech.ports)
        adv = tech.advantages[:w_adv-2] + ".." if len(tech.advantages) > w_adv else tech.advantages
        dis = tech.disadvantages[:w_dis-2] + ".." if len(tech.disadvantages) > w_dis else tech.disadvantages
        lines.append(f"  {c.DIM}│{c.RESET}{name:^{w_tech}}{c.DIM}│{c.RESET}{noise_c}{noise:^{w_noise}}{c.RESET}{c.DIM}│{c.RESET}{ports:^{w_ports}}{c.DIM}│{c.RESET}{adv:<{w_adv}}{c.DIM}│{c.RESET}{dis:<{w_dis}}{c.DIM}│{c.RESET}")

    lines.append(f"  {c.DIM}└{'─' * w_tech}┴{'─' * w_noise}┴{'─' * w_ports}┴{'─' * w_adv}┴{'─' * w_dis}┘{c.RESET}")
    return "\n".join(lines)


def generate_technique_legend_markdown(techniques: List) -> str:
    """Generate technique comparison table as markdown."""
    if not techniques:
        return ""

    lines = []
    lines.append("")
    lines.append("**Technique Comparison**")
    lines.append("")
    lines.append("| Technique | Noise | Ports | Advantages | Disadvantages |")
    lines.append("|-----------|-------|-------|------------|---------------|")

    for tech in techniques:
        name = tech.name.split()[0].lower()
        noise = tech.noise_level.upper()
        ports = ",".join(str(p) for p in tech.ports)
        lines.append(f"| {name} | {noise} | {ports} | {tech.advantages} | {tech.disadvantages} |")

    lines.append("")
    return "\n".join(lines)


# Backward compatibility aliases
_generate_technique_legend_console = generate_technique_legend_console
_generate_technique_legend_markdown = generate_technique_legend_markdown
