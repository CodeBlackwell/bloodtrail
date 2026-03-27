"""SharpHound JSON/ZIP parser — converts raw BloodHound output to demo format."""

import re
from pathlib import Path

from bloodtrail.data_source import create_data_source


def parse_upload(path: Path) -> dict:
    """Parse a SharpHound ZIP or JSON file into demo-compatible format."""
    source = create_data_source(path)
    nodes = []
    edges = []
    node_map = {}  # objectid/SID -> {id, name, label}

    for filename, data in source.iter_json_files():
        file_type = _detect_type(filename, data)
        if not file_type:
            continue
        items = data.get("data", data) if isinstance(data.get("data"), list) else []
        for item in items:
            props = item.get("Properties", {})
            if not props:
                continue
            node = _extract_node(item, props, file_type)
            if node and node["id"] not in node_map:
                nodes.append(node)
                node_map[node["id"]] = node
            _extract_edges(item, props, file_type, node_map, edges)

    if hasattr(source, "close"):
        source.close()

    return {
        "meta": {
            "name": "Uploaded SharpHound Data",
            "description": "User-uploaded dataset",
            "source": "SharpHound upload",
            "node_count": len(nodes),
            "edge_count": len(edges),
            "chain_count": 0,
        },
        "nodes": nodes,
        "edges": edges,
        "chains": [],
        "quick_wins": [],
    }


def _detect_type(filename: str, data: dict) -> str:
    meta_type = data.get("meta", {}).get("type", "").lower()
    if meta_type:
        return meta_type
    fn = filename.lower()
    for t in ("users", "computers", "groups", "domains", "sessions", "ous", "gpos", "containers"):
        if t in fn:
            return t
    return ""


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60]


def _extract_node(item: dict, props: dict, file_type: str) -> dict:
    oid = item.get("ObjectIdentifier", props.get("objectid", ""))
    name = props.get("name", oid)
    label_map = {"users": "User", "computers": "Computer", "groups": "Group", "domains": "Domain"}
    label = label_map.get(file_type, file_type.title())
    node_id = f"{label.lower()}-{_slugify(name)}"

    kept_props = {}
    for key in ("enabled", "unconstraineddelegation", "dontreqpreauth",
                "serviceprincipalnames", "allowedtodelegate", "haslaps",
                "admincount", "operatingsystem", "is_dc", "functionallevel"):
        lk = key.lower()
        for pk, pv in props.items():
            if pk.lower() == lk:
                kept_props[key] = pv
                break

    return {"id": node_id, "label": label, "name": name, "props": kept_props,
            "_oid": oid}


def _resolve(oid: str, node_map: dict) -> dict:
    """Find node info by objectid."""
    for n in node_map.values():
        if n.get("_oid") == oid:
            return n
    return None


def _add_edge(edges: list, src: dict, tgt: dict, edge_type: str):
    edges.append({
        "source_id": src["id"], "source_name": src["name"], "source_label": src["label"],
        "target_id": tgt["id"], "target_name": tgt["name"], "target_label": tgt["label"],
        "edge": edge_type, "props": {},
    })


def _extract_edges(item: dict, props: dict, file_type: str, node_map: dict, edges: list):
    oid = item.get("ObjectIdentifier", props.get("objectid", ""))
    src = _resolve(oid, node_map)
    if not src:
        return

    # ACEs -> ACL edges
    for ace in item.get("Aces", []):
        if not isinstance(ace, dict):
            continue
        principal_sid = ace.get("PrincipalSID", "")
        right = ace.get("RightName", "")
        if not right or not principal_sid:
            continue
        principal = _resolve(principal_sid, node_map)
        if principal:
            _add_edge(edges, principal, src, right)

    # Members -> MemberOf
    for member in item.get("Members", []):
        if not isinstance(member, dict):
            continue
        mid = member.get("ObjectIdentifier", "")
        m = _resolve(mid, node_map)
        if m:
            _add_edge(edges, m, src, "MemberOf")

    if file_type == "computers":
        for rel_key, edge_type in [("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                                    ("PSRemoteUsers", "CanPSRemote"), ("DcomUsers", "ExecuteDCOM")]:
            for entry in _get_results(item, rel_key):
                e = _resolve(entry.get("ObjectIdentifier", ""), node_map)
                if e:
                    _add_edge(edges, e, src, edge_type)
        for entry in _get_results(item, "Sessions"):
            e = _resolve(entry.get("UserSID", entry.get("ObjectIdentifier", "")), node_map)
            if e:
                _add_edge(edges, e, src, "HasSession")
        for entry in item.get("AllowedToDelegate", []) or []:
            if isinstance(entry, dict):
                e = _resolve(entry.get("ObjectIdentifier", ""), node_map)
                if e:
                    _add_edge(edges, src, e, "AllowedToDelegate")
        for entry in item.get("AllowedToAct", []) or []:
            if isinstance(entry, dict):
                e = _resolve(entry.get("ObjectIdentifier", ""), node_map)
                if e:
                    _add_edge(edges, e, src, "AllowedToAct")


def _get_results(item: dict, key: str) -> list:
    val = item.get(key, [])
    if isinstance(val, dict):
        return val.get("Results", [])
    return val if isinstance(val, list) else []
