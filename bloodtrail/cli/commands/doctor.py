"""
BloodTrail Doctor — pre-flight dependency and connectivity checks.

Usage:
    bloodtrail doctor
"""

import shutil
import os
from argparse import Namespace

from ..base import BaseCommandGroup


TOOLS = [
    ("neo4j", "Neo4j database", "sudo neo4j start"),
    ("kerbrute", "Kerberos brute-force / user enum", "go install github.com/ropnop/kerbrute@latest"),
    ("crackmapexec", "SMB/WinRM/LDAP Swiss army knife", "pipx install crackmapexec"),
    ("netexec", "CrackMapExec successor", "pipx install netexec"),
    ("impacket-psexec", "Impacket (psexec, secretsdump, etc.)", "pipx install impacket"),
    ("bloodhound-python", "BloodHound Python collector", "pip install bloodhound"),
    ("hashcat", "GPU password cracker", "apt install hashcat"),
    ("john", "John the Ripper", "apt install john"),
    ("evil-winrm", "WinRM shell", "gem install evil-winrm"),
    ("xfreerdp", "RDP client", "apt install freerdp2-x11"),
    ("ldapsearch", "LDAP enumeration", "apt install ldap-utils"),
    ("rpcclient", "RPC enumeration", "apt install smbclient"),
    ("smbclient", "SMB client", "apt install smbclient"),
    ("enum4linux", "SMB/NetBIOS enumeration", "apt install enum4linux"),
]


class DoctorCommands(BaseCommandGroup):
    """Pre-flight checks for BloodTrail."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        pass

    @classmethod
    def handle(cls, args: Namespace) -> int:
        print("\nBloodTrail Doctor")
        print("=" * 50)

        issues = 0
        issues += cls._check_neo4j(args)
        issues += cls._check_config()
        issues += cls._check_tools()
        issues += cls._check_python_deps()

        print()
        if issues == 0:
            cls.print_success("All checks passed")
        else:
            cls.print_warning(f"{issues} issue(s) found")

        return 0

    @classmethod
    def _check_neo4j(cls, args: Namespace) -> int:
        print("\n[Neo4j]")
        password = getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", "")

        if not password:
            cls.print_error("NEO4J_PASSWORD not set")
            print("    export NEO4J_PASSWORD='your_password'")
            return 1

        try:
            conn = cls.require_neo4j(args, silent=True)
            if conn:
                cls.print_success("Connected to Neo4j")
                conn.close()
                return 0
            cls.print_error("Cannot connect to Neo4j")
            print("    Check: sudo neo4j start")
            return 1
        except Exception as e:
            cls.print_error(f"Neo4j error: {e}")
            return 1

    @classmethod
    def _check_config(cls) -> int:
        print("\n[Configuration]")
        from ...settings import load_settings, CONFIG_PATH

        settings = load_settings()
        if CONFIG_PATH.exists():
            cls.print_success(f"Config: {CONFIG_PATH}")
        else:
            cls.print_warning(f"No config file (create with: bloodtrail config new <name>)")

        eng = settings.active()
        if eng:
            cls.print_success(f"Active engagement: {eng.name}")
            if eng.dc_ip:
                cls.print_success(f"DC IP: {eng.dc_ip}")
            else:
                cls.print_warning("DC IP not set (bloodtrail config set dc-ip <IP>)")
        else:
            cls.print_warning("No active engagement")

        return 0

    @classmethod
    def _check_tools(cls) -> int:
        print("\n[External Tools]")
        issues = 0
        found = 0

        for binary, description, install_hint in TOOLS:
            if shutil.which(binary):
                found += 1
            else:
                issues += 1

        cls.print_success(f"{found}/{len(TOOLS)} tools available")

        # Show missing tools
        missing = [(b, d, h) for b, d, h in TOOLS if not shutil.which(b)]
        if missing:
            print("    Missing (optional):")
            for binary, desc, hint in missing:
                print(f"      {binary:25s} {hint}")

        # Critical tools check
        critical = ["crackmapexec", "netexec"]
        has_cme = any(shutil.which(t) for t in critical)
        if not has_cme:
            cls.print_warning("No SMB tool (install crackmapexec or netexec)")

        return 0  # Tools are optional, not errors

    @classmethod
    def _check_python_deps(cls) -> int:
        print("\n[Python Dependencies]")
        issues = 0

        deps = [
            ("neo4j", "neo4j"),
            ("requests", "requests"),
            ("bs4", "beautifulsoup4"),
        ]

        optional = [
            ("bloodhound", "bloodhound (pip install bloodtrail[collect])"),
            ("fastapi", "fastapi (pip install bloodtrail[ui])"),
        ]

        for module, name in deps:
            try:
                __import__(module)
                cls.print_success(f"{name}")
            except ImportError:
                cls.print_error(f"{name} — pip install {name}")
                issues += 1

        for module, name in optional:
            try:
                __import__(module)
                cls.print_success(f"{name}")
            except ImportError:
                cls.print_warning(f"{name} (optional)")

        return issues
