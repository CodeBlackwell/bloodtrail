"""In-memory graph analysis — detects quick wins and attack chains without Neo4j."""

from bloodtrail.mappings.edge_mappings import get_edge_commands


def analyze(nodes: list, edges: list) -> dict:
    """Analyze parsed graph, return chains and quick wins."""
    node_map = {n["id"]: n for n in nodes}
    adj = _build_adjacency(edges)
    edge_index = _build_edge_index(edges)
    quick_wins = _detect_quick_wins(nodes, edges, adj)
    chains = _detect_chains(nodes, edges, adj, edge_index, quick_wins, node_map)
    return {"chains": chains, "quick_wins": quick_wins}


def _build_adjacency(edges: list) -> dict:
    adj = {}
    for e in edges:
        adj.setdefault(e["source_id"], []).append((e["target_id"], e["edge"]))
    return adj


def _build_edge_index(edges: list) -> dict:
    idx = {}
    for e in edges:
        idx[(e["source_id"], e["target_id"], e["edge"])] = e
    return idx


def _has_edge(adj: dict, src: str, edge_type: str, target_label: str = None, node_map: dict = None) -> list:
    """Find targets reachable from src via edge_type, optionally filtered by target label."""
    results = []
    for tgt, etype in adj.get(src, []):
        if etype == edge_type:
            if target_label and node_map:
                t = node_map.get(tgt)
                if t and t["label"] != target_label:
                    continue
            results.append(tgt)
    return results


def _detect_quick_wins(nodes: list, edges: list, adj: dict) -> list:
    wins = []
    edge_targets = {}
    for e in edges:
        edge_targets.setdefault(e["edge"], []).append((e["source_id"], e["target_id"], e))

    for n in nodes:
        p = n.get("props", {})
        nid, name = n["id"], n["name"]

        if p.get("dontreqpreauth"):
            wins.append({"type": "asrep_roastable", "node": nid, "name": name,
                         "reason": "DoNotRequirePreAuth enabled"})
        spns = p.get("serviceprincipalnames", [])
        if spns and n["label"] == "User":
            wins.append({"type": "kerberoastable", "node": nid, "name": name,
                         "reason": f"SPN: {spns[0] if isinstance(spns, list) else spns}"})
        if p.get("unconstraineddelegation") and n["label"] == "Computer":
            wins.append({"type": "unconstrained_delegation", "node": nid, "name": name,
                         "reason": "Unconstrained delegation enabled"})
        delegate = p.get("allowedtodelegate", [])
        if delegate and n["label"] == "Computer":
            wins.append({"type": "constrained_delegation", "node": nid, "name": name,
                         "reason": f"Constrained delegation to {delegate[0] if isinstance(delegate, list) else delegate}"})

    for src, tgt, e in edge_targets.get("WriteDacl", []):
        t = next((n for n in nodes if n["id"] == tgt), None)
        if t and t["label"] == "Domain":
            wins.append({"type": "writedacl_on_domain", "node": src, "name": e["source_name"],
                         "reason": f"WriteDACL on {t['name']}"})
    for src, tgt, e in edge_targets.get("AddKeyCredentialLink", []):
        wins.append({"type": "shadow_credentials", "node": src, "name": e["source_name"],
                     "reason": f"AddKeyCredentialLink on {e['target_name']}"})
    for src, tgt, e in edge_targets.get("WriteAccountRestrictions", []):
        wins.append({"type": "rbcd_writable", "node": src, "name": e["source_name"],
                     "reason": f"WriteAccountRestrictions on {e['target_name']}"})
    for src, tgt, e in edge_targets.get("ReadLAPSPassword", []):
        wins.append({"type": "laps_readable", "node": src, "name": e["source_name"],
                     "reason": f"ReadLAPSPassword on {e['target_name']}"})
    for src, tgt, e in edge_targets.get("MemberOf", []):
        t = next((n for n in nodes if n["id"] == tgt), None)
        if t and "DNSADMIN" in t["name"].upper():
            wins.append({"type": "dnsadmins_member", "node": src, "name": e["source_name"],
                         "reason": "DnsAdmins group membership"})
        if t and "ACCOUNT OPERATOR" in t["name"].upper():
            wins.append({"type": "account_operators", "node": src, "name": e["source_name"],
                         "reason": "Account Operators membership"})
        if t and "BACKUP OPERATOR" in t["name"].upper():
            wins.append({"type": "backup_operators", "node": src, "name": e["source_name"],
                         "reason": "Backup Operators membership"})
    for src, tgt, e in edge_targets.get("GenericWrite", []):
        t = next((n for n in nodes if n["id"] == tgt), None)
        if t and t["label"] == "User":
            wins.append({"type": "targeted_kerberoast", "node": src, "name": e["source_name"],
                         "reason": f"GenericWrite on user {t['name']}"})

    return wins


def _detect_chains(nodes, edges, adj, edge_index, quick_wins, node_map) -> list:
    """Template-based chain detection — check for known attack patterns."""
    chains = []
    da_groups = [n["id"] for n in nodes if n["label"] == "Group" and "DOMAIN ADMIN" in n["name"].upper()]
    domains = [n["id"] for n in nodes if n["label"] == "Domain"]

    # Find DA members
    da_members = set()
    for dag in da_groups:
        for e in edges:
            if e["target_id"] == dag and e["edge"] == "MemberOf":
                da_members.add(e["source_id"])

    # Kerberoast -> AdminTo -> HasSession DA -> DCSync
    for qw in quick_wins:
        if qw["type"] != "kerberoastable":
            continue
        user = qw["node"]
        for comp in _has_edge(adj, user, "AdminTo"):
            for da in da_members:
                if (da, comp, "HasSession") in edge_index:
                    chains.append(_chain("kerberoast-dcsync", "Kerberoast -> AdminTo -> DCSync",
                                         "critical", [
                        {"action": "Kerberoast", "from": user, "description": f"Crack SPN hash for {qw['name']}"},
                        {"action": "AdminTo", "from": user, "to": comp, "description": "Admin access to computer"},
                        {"action": "HasSession", "from": da, "to": comp, "description": "DA has session on this host"},
                        {"action": "DCSync", "from": da, "description": "Dump domain credentials"},
                    ]))

    # AS-REP -> GenericAll -> DA
    for qw in quick_wins:
        if qw["type"] != "asrep_roastable":
            continue
        user = qw["node"]
        for grp in _has_edge(adj, user, "GenericAll", "Group", node_map):
            if grp in da_groups:
                chains.append(_chain("asrep-da", "AS-REP Roast -> GenericAll -> DA", "critical", [
                    {"action": "AS-REP Roast", "from": user, "description": f"Crack AS-REP hash for {qw['name']}"},
                    {"action": "GenericAll", "from": user, "to": grp, "description": "Full control over DA group"},
                    {"action": "Add to DA", "from": user, "to": grp, "description": "Add self to Domain Admins"},
                ]))

    # WriteDACL -> DCSync
    for qw in quick_wins:
        if qw["type"] != "writedacl_on_domain":
            continue
        src = qw["node"]
        for dom in domains:
            if (src, dom, "WriteDacl") in edge_index:
                chains.append(_chain("writedacl-dcsync", "WriteDACL -> Grant DCSync", "critical", [
                    {"action": "WriteDACL", "from": src, "to": dom, "description": "Modify domain DACL"},
                    {"action": "Grant DCSync", "from": src, "description": "Grant self GetChanges + GetChangesAll"},
                    {"action": "DCSync", "from": src, "description": "Dump all domain credentials"},
                ]))

    # Shadow Credentials
    for qw in quick_wins:
        if qw["type"] != "shadow_credentials":
            continue
        src = qw["node"]
        chains.append(_chain("shadow-creds", "Shadow Credentials -> NTLM", "critical", [
            {"action": "AddKeyCredentialLink", "from": src, "description": "Add shadow credential to target"},
            {"action": "Request TGT", "from": src, "description": "Authenticate with shadow credential"},
            {"action": "UnPAC-the-hash", "from": src, "description": "Extract NTLM from TGT"},
        ]))

    # RBCD
    for qw in quick_wins:
        if qw["type"] != "rbcd_writable":
            continue
        src = qw["node"]
        chains.append(_chain("rbcd", "RBCD via WriteAccountRestrictions", "high", [
            {"action": "WriteAccountRestrictions", "from": src, "description": "Configure RBCD on target computer"},
            {"action": "S4U2Self + S4U2Proxy", "from": src, "description": "Impersonate admin via delegation"},
            {"action": "Access", "from": src, "description": "Service ticket grants admin access"},
        ]))

    return chains


def _chain(id: str, name: str, severity: str, steps: list) -> dict:
    return {"id": f"chain-{id}", "name": name, "severity": severity, "steps": steps}
