"""
BloodTrail CLI Interactive Helpers

Provides interactive selection and input utilities for CLI commands.
Used primarily by --pwn-interactive mode.
"""

from typing import List, Optional, Dict
from neo4j import GraphDatabase

from ..config import Neo4jConfig


def fetch_neo4j_list(config: Neo4jConfig, query: str) -> List[str]:
    """
    Fetch a list from Neo4j.

    Args:
        config: Neo4j connection config
        query: Cypher query that returns a 'name' field

    Returns:
        List of names, or empty list on failure
    """
    try:
        driver = GraphDatabase.driver(config.uri, auth=(config.user, config.password))
        with driver.session() as session:
            result = session.run(query)
            items = [r["name"] for r in result]
        driver.close()
        return items
    except Exception:
        return []


def select_from_list(
    items: List[str],
    prompt: str,
    allow_manual: bool = True
) -> str:
    """
    Present numbered list for selection.

    Args:
        items: List of items to choose from
        prompt: Header prompt to display
        allow_manual: If True, show [M] manual entry option

    Returns:
        Selected item or empty string if cancelled
    """
    if not items:
        if allow_manual:
            return input(f"{prompt} (manual): ").strip()
        return ""

    print(f"\n{prompt}:")
    for i, item in enumerate(items, 1):
        print(f"  [{i}] {item}")
    if allow_manual:
        print(f"  [M] Enter manually")

    choice = input("Choice: ").strip().strip('\r\n')

    # Enter with no input selects first item (default)
    if not choice:
        return items[0]

    if allow_manual and choice.upper() == "M":
        return input("  Enter value: ").strip()

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(items):
            return items[idx]
    except ValueError:
        pass

    # If invalid, treat as manual entry
    if choice:
        return choice.upper()
    return items[0]  # Fallback to first item


def interactive_pwn(
    config: Neo4jConfig,
    prefill_user: Optional[str] = None
) -> Dict[str, Optional[str]]:
    """
    Interactively collect credential information with selection menus.

    Args:
        config: Neo4j connection config for fetching users/computers
        prefill_user: Optional user to pre-fill (for "same user" loop)

    Returns:
        dict with keys: user, cred_type, cred_value, source_machine, notes
        Returns empty dict if user cancels (Ctrl+C)
    """
    CRED_TYPES = ["password", "ntlm-hash", "kerberos-ticket", "certificate"]

    print("\nMark User as Pwned")

    try:
        # Fetch users and computers from Neo4j
        users = fetch_neo4j_list(config, """
            MATCH (u:User)
            WHERE u.enabled = true AND NOT u.name STARTS WITH 'KRBTGT'
            RETURN u.name AS name
            ORDER BY u.name
            LIMIT 50
        """)

        computers = fetch_neo4j_list(config, """
            MATCH (c:Computer)
            WHERE c.enabled = true
            RETURN c.name AS name
            ORDER BY c.name
            LIMIT 30
        """)

        # 1. User selection (required) - skip if pre-filled
        if prefill_user:
            print(f"\nUser: {prefill_user}")
            user = prefill_user
        else:
            user = select_from_list(users, "Select user to mark as pwned")
        if not user:
            print("[!] User is required")
            return {}

        # 2. Credential type (required, with default)
        print("\nCredential type:")
        for i, ct in enumerate(CRED_TYPES, 1):
            print(f"  [{i}] {ct}")

        choice = input("Choice [1]: ").strip() or "1"
        try:
            cred_type = CRED_TYPES[int(choice) - 1]
        except (ValueError, IndexError):
            print("[!] Invalid choice, using 'password'")
            cred_type = "password"

        # 3. Credential value (required - always manual)
        cred_value = input(f"\n{cred_type.replace('-', ' ').title()}: ").strip()
        if not cred_value:
            print("[!] Credential value is required")
            return {}

        # 4. Source machine selection (optional)
        print("\nSource machine (where credential was obtained):")
        print("  [S] Skip")
        if computers:
            for i, comp in enumerate(computers, 1):
                print(f"  [{i}] {comp}")
        print("  [M] Enter manually")

        source_choice = input("Choice [S]: ").strip() or "S"
        source = None
        if source_choice.upper() == "M":
            source = input("  Enter machine: ").strip() or None
        elif source_choice.upper() != "S":
            try:
                idx = int(source_choice) - 1
                if 0 <= idx < len(computers):
                    source = computers[idx]
            except ValueError:
                if source_choice:
                    source = source_choice.upper()

        # 5. Notes (optional - always manual)
        notes = input("\nNotes (optional): ").strip() or None

        return {
            "user": user,
            "cred_type": cred_type,
            "cred_value": cred_value,
            "source_machine": source,
            "notes": notes,
        }

    except (KeyboardInterrupt, EOFError):
        print("\n[*] Cancelled")
        return {}


# Backward compatibility aliases
_fetch_neo4j_list = fetch_neo4j_list
_select_from_list = select_from_list
