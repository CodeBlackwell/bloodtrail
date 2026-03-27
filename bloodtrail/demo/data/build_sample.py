"""
Build augmented sample AD dataset for BloodTrail demo.

Takes GOADv2 NORTH domain as base, trims to interesting nodes,
injects missing attack chains that showcase BloodTrail's analysis.

Output: sample_ad.json — a self-contained graph with nodes + edges.
"""

import json
from pathlib import Path

# --- Node definitions ---
# Format: {id, label (User/Group/Computer/Domain), name, properties}

NODES = [
    # Domain
    {"id": "domain-north", "label": "Domain", "name": "NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"functionallevel": "2016", "collected": True}},

    # Domain Controllers
    {"id": "comp-winterfell", "label": "Computer", "name": "WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"os": "Windows Server 2019", "enabled": True, "unconstraineddelegation": True, "is_dc": True}},
    {"id": "comp-castelblack", "label": "Computer", "name": "CASTELBLACK.NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"os": "Windows Server 2019", "enabled": True, "unconstraineddelegation": False, "is_dc": False}},

    # Injected computers for attack chains
    {"id": "comp-dreadfort", "label": "Computer", "name": "DREADFORT.NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"os": "Windows Server 2019", "enabled": True, "unconstraineddelegation": False, "is_dc": False}},
    {"id": "comp-moat-cailin", "label": "Computer", "name": "MOAT-CAILIN.NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"os": "Windows Server 2016", "enabled": True, "unconstraineddelegation": False, "is_dc": False,
              "haslaps": True}},

    # Users — from GOADv2
    {"id": "user-eddard", "label": "User", "name": "EDDARD.STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": True, "title": "Lord of Winterfell"}},
    {"id": "user-robb", "label": "User", "name": "ROBB.STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": True, "title": "King in the North"}},
    {"id": "user-jon", "label": "User", "name": "JON.SNOW@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False, "title": "Lord Commander"}},
    {"id": "user-arya", "label": "User", "name": "ARYA.STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False}},
    {"id": "user-sansa", "label": "User", "name": "SANSA.STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False}},
    {"id": "user-brandon", "label": "User", "name": "BRANDON.STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False}},
    {"id": "user-catelyn", "label": "User", "name": "CATELYN.STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": True}},
    {"id": "user-hodor", "label": "User", "name": "HODOR@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False}},
    {"id": "user-samwell", "label": "User", "name": "SAMWELL.TARLY@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False}},
    {"id": "user-jeor", "label": "User", "name": "JEOR.MORMONT@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False}},
    {"id": "user-rickon", "label": "User", "name": "RICKON.STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False}},
    {"id": "user-admin", "label": "User", "name": "ADMINISTRATOR@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": True}},

    # Kerberoastable service account (from GOADv2)
    {"id": "user-sqlsvc", "label": "User", "name": "SQL_SVC@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False,
              "serviceprincipalnames": ["MSSQL/CASTELBLACK.NORTH.SEVENKINGDOMS.LOCAL:1433",
                                         "MSSQL/CASTELBLACK.NORTH.SEVENKINGDOMS.LOCAL"]}},

    # Injected: AS-REP roastable user
    {"id": "user-theon", "label": "User", "name": "THEON.GREYJOY@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False, "dontreqpreauth": True,
              "title": "Ward of Winterfell"}},

    # Injected: DnsAdmins member
    {"id": "user-luwin", "label": "User", "name": "MAESTER.LUWIN@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False, "title": "Maester of Winterfell"}},

    # Injected: Exchange service account (for WriteDACL chain)
    {"id": "user-raven", "label": "User", "name": "SVC_RAVEN@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False, "description": "Raven message relay service"}},

    # Groups
    {"id": "group-da", "label": "Group", "name": "DOMAIN ADMINS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"admincount": True}},
    {"id": "group-nightwatch", "label": "Group", "name": "NIGHT WATCH@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},
    {"id": "group-stark", "label": "Group", "name": "STARK@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},
    {"id": "group-mormont", "label": "Group", "name": "MORMONT@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},
    {"id": "group-dnsadmins", "label": "Group", "name": "DNSADMINS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},
    {"id": "group-domainusers", "label": "Group", "name": "DOMAIN USERS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},

    # Injected: Exchange-like group for WriteDACL chain
    {"id": "group-ravens", "label": "Group", "name": "RAVEN KEEPERS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"description": "Raven message relay operators"}},

    # Injected: IT operations group (dead-end noise)
    {"id": "group-builders", "label": "Group", "name": "BUILDERS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},
    {"id": "group-stewards", "label": "Group", "name": "STEWARDS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},

    # --- Complex chain nodes ---

    # Account Operators group (for the 7-step Exchange chain)
    {"id": "group-accountops", "label": "Group", "name": "ACCOUNT OPERATORS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},

    # Constrained delegation computer (for targeted kerberoast + delegation chain)
    {"id": "comp-deepwood", "label": "Computer", "name": "DEEPWOOD.NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"os": "Windows Server 2016", "enabled": True, "unconstraineddelegation": False, "is_dc": False,
              "allowedtodelegate": ["cifs/WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL"]}},

    # User with GenericWrite for targeted kerberoast
    {"id": "user-osha", "label": "User", "name": "OSHA@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False, "title": "Wildling servant"}},

    # User to be targeted-kerberoasted (no SPN yet — GenericWrite sets one)
    {"id": "user-rodrik", "label": "User", "name": "RODRIK.CASSEL@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {"enabled": True, "admincount": False, "title": "Master-at-Arms"}},

    # Cross-domain trust target (SEVENKINGDOMS forest root)
    {"id": "domain-seven", "label": "Domain", "name": "SEVENKINGDOMS.LOCAL",
     "props": {"functionallevel": "2016", "collected": True}},
    {"id": "group-ea", "label": "Group", "name": "ENTERPRISE ADMINS@SEVENKINGDOMS.LOCAL",
     "props": {"admincount": True}},
    {"id": "comp-kingslanding", "label": "Computer", "name": "KINGSLANDING.SEVENKINGDOMS.LOCAL",
     "props": {"os": "Windows Server 2019", "enabled": True, "unconstraineddelegation": True, "is_dc": True}},

    # Backup Operators member (for backup→SAM dump chain)
    {"id": "group-backupops", "label": "Group", "name": "BACKUP OPERATORS@NORTH.SEVENKINGDOMS.LOCAL",
     "props": {}},
]


# --- Edge definitions ---
# Format: {source, target, label, props}
# source/target are node IDs

EDGES = [
    # ============================================================
    # CHAIN 1: Kerberoast → AdminTo → HasSession DA → DCSync
    # SQL_SVC is kerberoastable → has AdminTo on CASTELBLACK →
    # EDDARD.STARK (DA) has session on CASTELBLACK → DCSync domain
    # ============================================================
    {"source": "user-sqlsvc", "target": "comp-castelblack", "label": "AdminTo"},
    {"source": "user-eddard", "target": "comp-castelblack", "label": "HasSession"},
    {"source": "user-eddard", "target": "domain-north", "label": "GetChanges"},
    {"source": "user-eddard", "target": "domain-north", "label": "GetChangesAll"},
    # (Kerberoast SQL_SVC → crack → AdminTo CASTELBLACK → harvest EDDARD session → DCSync)

    # ============================================================
    # CHAIN 2: AS-REP Roast → GenericAll on group → DA membership
    # THEON is AS-REP roastable → has GenericAll on STARK group →
    # STARK group has GenericAll on DA group → add self to DA
    # ============================================================
    {"source": "user-theon", "target": "group-stark", "label": "GenericAll"},
    {"source": "group-stark", "target": "group-da", "label": "GenericAll"},

    # ============================================================
    # CHAIN 3: WriteDACL → DCSync (Exchange-style)
    # SVC_RAVEN is in RAVEN KEEPERS → RAVEN KEEPERS has WriteDacl
    # on domain → grant DCSync rights → dump all hashes
    # ============================================================
    {"source": "user-raven", "target": "group-ravens", "label": "MemberOf"},
    {"source": "group-ravens", "target": "domain-north", "label": "WriteDacl"},

    # ============================================================
    # CHAIN 4: RBCD (WriteAccountRestrictions)
    # JON.SNOW has WriteAccountRestrictions on DREADFORT →
    # configure RBCD → impersonate admin → shell
    # ============================================================
    {"source": "user-jon", "target": "comp-dreadfort", "label": "WriteAccountRestrictions"},

    # ============================================================
    # CHAIN 5: Shadow Credentials (AddKeyCredentialLink)
    # ARYA has AddKeyCredentialLink on CATELYN →
    # add shadow credential → get TGT as CATELYN (who is DA)
    # ============================================================
    {"source": "user-arya", "target": "user-catelyn", "label": "AddKeyCredentialLink"},

    # ============================================================
    # CHAIN 6: DnsAdmins → DC compromise
    # MAESTER.LUWIN is in DNSADMINS → DnsAdmins can load
    # arbitrary DLL on DC → SYSTEM shell on WINTERFELL
    # ============================================================
    {"source": "user-luwin", "target": "group-dnsadmins", "label": "MemberOf"},
    # DnsAdmins implicitly has ability to compromise DC via dnscmd

    # ============================================================
    # Standard group memberships
    # ============================================================
    # Domain Admins members
    {"source": "user-eddard", "target": "group-da", "label": "MemberOf"},
    {"source": "user-admin", "target": "group-da", "label": "MemberOf"},
    {"source": "user-robb", "target": "group-da", "label": "MemberOf"},

    # Night Watch (from GOADv2)
    {"source": "user-jon", "target": "group-nightwatch", "label": "MemberOf"},
    {"source": "user-samwell", "target": "group-nightwatch", "label": "MemberOf"},
    {"source": "user-jeor", "target": "group-nightwatch", "label": "MemberOf"},

    # Stark family
    {"source": "user-eddard", "target": "group-stark", "label": "MemberOf"},
    {"source": "user-robb", "target": "group-stark", "label": "MemberOf"},
    {"source": "user-arya", "target": "group-stark", "label": "MemberOf"},
    {"source": "user-sansa", "target": "group-stark", "label": "MemberOf"},
    {"source": "user-brandon", "target": "group-stark", "label": "MemberOf"},
    {"source": "user-rickon", "target": "group-stark", "label": "MemberOf"},
    {"source": "user-catelyn", "target": "group-stark", "label": "MemberOf"},

    # Mormont
    {"source": "user-jeor", "target": "group-mormont", "label": "MemberOf"},

    # Domain Users (everyone)
    {"source": "user-hodor", "target": "group-domainusers", "label": "MemberOf"},
    {"source": "user-theon", "target": "group-domainusers", "label": "MemberOf"},
    {"source": "user-luwin", "target": "group-domainusers", "label": "MemberOf"},
    {"source": "user-sqlsvc", "target": "group-domainusers", "label": "MemberOf"},
    {"source": "user-raven", "target": "group-domainusers", "label": "MemberOf"},

    # Noise groups
    {"source": "user-hodor", "target": "group-builders", "label": "MemberOf"},
    {"source": "user-brandon", "target": "group-builders", "label": "MemberOf"},
    {"source": "user-samwell", "target": "group-stewards", "label": "MemberOf"},
    {"source": "user-rickon", "target": "group-stewards", "label": "MemberOf"},

    # ============================================================
    # AdminTo / CanRDP / CanPSRemote edges
    # ============================================================
    {"source": "group-da", "target": "comp-winterfell", "label": "AdminTo"},
    {"source": "group-da", "target": "comp-castelblack", "label": "AdminTo"},
    {"source": "group-da", "target": "comp-dreadfort", "label": "AdminTo"},
    {"source": "group-da", "target": "comp-moat-cailin", "label": "AdminTo"},
    {"source": "user-jon", "target": "comp-castelblack", "label": "CanPSRemote"},
    {"source": "group-nightwatch", "target": "comp-castelblack", "label": "CanRDP"},

    # ============================================================
    # More sessions (context for blast radius visualization)
    # ============================================================
    {"source": "user-robb", "target": "comp-winterfell", "label": "HasSession"},
    {"source": "user-jon", "target": "comp-castelblack", "label": "HasSession"},
    {"source": "user-sqlsvc", "target": "comp-castelblack", "label": "HasSession"},
    {"source": "user-theon", "target": "comp-dreadfort", "label": "HasSession"},
    {"source": "user-hodor", "target": "comp-winterfell", "label": "HasSession"},

    # ============================================================
    # Dead-end ACL edges (noise — BT should NOT highlight these)
    # ============================================================
    # SANSA has ForceChangePassword on HODOR — leads nowhere
    {"source": "user-sansa", "target": "user-hodor", "label": "ForceChangePassword"},
    # BRANDON has GenericWrite on RICKON — leads nowhere
    {"source": "user-brandon", "target": "user-rickon", "label": "GenericWrite"},
    # STEWARDS has AddSelf — group has no useful permissions
    {"source": "user-samwell", "target": "group-stewards", "label": "AddSelf"},
    # HODOR has WriteOwner on BUILDERS — group has no useful permissions
    {"source": "user-hodor", "target": "group-builders", "label": "WriteOwner"},

    # ============================================================
    # LAPS (readable password on MOAT-CAILIN)
    # ============================================================
    {"source": "group-nightwatch", "target": "comp-moat-cailin", "label": "ReadLAPSPassword"},

    # ============================================================
    # Domain → Computer containment
    # ============================================================
    {"source": "comp-winterfell", "target": "domain-north", "label": "Contains"},
    {"source": "comp-castelblack", "target": "domain-north", "label": "Contains"},
    {"source": "comp-dreadfort", "target": "domain-north", "label": "Contains"},
    {"source": "comp-moat-cailin", "target": "domain-north", "label": "Contains"},
    {"source": "comp-deepwood", "target": "domain-north", "label": "Contains"},

    # ============================================================
    # CHAIN 7: Account Operators → Raven Keepers → WriteDACL → DCSync
    # (7-step Exchange-style chain — the longest in BT)
    # SAMWELL is in Account Operators → can create users →
    # create fake user → add to RAVEN KEEPERS → WriteDACL on domain →
    # grant DCSync → secretsdump → pass-the-hash DA
    # ============================================================
    {"source": "user-samwell", "target": "group-accountops", "label": "MemberOf"},
    {"source": "group-accountops", "target": "group-ravens", "label": "GenericAll"},
    # (Steps 3-7 are implicit: create user, add to ravens, WriteDACL, grant DCSync, PtH)
    # The graph edges needed: samwell → accountops → ravens → domain (WriteDACL already exists)

    # ============================================================
    # CHAIN 8: Targeted Kerberoast (GenericWrite → Set SPN → Roast)
    # OSHA has GenericWrite on RODRIK → set SPN → kerberoast →
    # RODRIK has AdminTo DREADFORT → harvest THEON session →
    # THEON is AS-REP roastable (already owned, but also
    # RODRIK path shows convergent chains)
    # ============================================================
    {"source": "user-osha", "target": "user-rodrik", "label": "GenericWrite"},
    {"source": "user-rodrik", "target": "comp-dreadfort", "label": "AdminTo"},
    {"source": "user-rodrik", "target": "group-domainusers", "label": "MemberOf"},
    {"source": "user-osha", "target": "group-domainusers", "label": "MemberOf"},

    # ============================================================
    # CHAIN 9: Unconstrained Delegation + Coercion → DCSync
    # WINTERFELL has unconstrained delegation (it's the DC) →
    # coerce KINGSLANDING (forest root DC) via PetitPotam →
    # capture TGT → DCSync SEVENKINGDOMS.LOCAL
    # This chain crosses domain boundaries via the trust
    # ============================================================
    {"source": "domain-north", "target": "domain-seven", "label": "TrustedBy"},
    {"source": "comp-kingslanding", "target": "domain-seven", "label": "Contains"},
    {"source": "group-ea", "target": "domain-seven", "label": "Contains"},
    # CoerceToTGT: WINTERFELL can coerce KINGSLANDING
    {"source": "comp-winterfell", "target": "comp-kingslanding", "label": "CoerceToTGT"},

    # ============================================================
    # CHAIN 10: Constrained Delegation → DC impersonation
    # DEEPWOOD has constrained delegation to cifs/WINTERFELL →
    # compromise DEEPWOOD (JON has CanPSRemote) →
    # S4U2Self + S4U2Proxy → impersonate DA on WINTERFELL
    # ============================================================
    {"source": "comp-deepwood", "target": "comp-winterfell", "label": "AllowedToDelegate"},
    {"source": "user-jon", "target": "comp-deepwood", "label": "CanPSRemote"},
    {"source": "user-jeor", "target": "comp-deepwood", "label": "HasSession"},

    # ============================================================
    # CHAIN 11: Backup Operators → SAM/SYSTEM dump → Local admin hashes
    # JEOR is in Backup Operators → can backup SAM+SYSTEM hives
    # from any machine → extract local admin hashes → PtH
    # ============================================================
    {"source": "user-jeor", "target": "group-backupops", "label": "MemberOf"},

    # ============================================================
    # CHAIN 12: Convergent mega-chain (RBCD + session harvest + cross-domain)
    # JON → RBCD DREADFORT → harvest THEON session →
    # THEON AS-REP → GenericAll STARK → GenericAll DA →
    # DA on WINTERFELL (unconstrained) → coerce KINGSLANDING →
    # Enterprise Admin on SEVENKINGDOMS.LOCAL
    # This is the "crown jewel" — 8 hops across 2 domains
    # All edges already exist, this chain just connects them
    # ============================================================
    # (No new edges needed — this chain composes chains 4, 2, 1, and 9)
]


def build_dataset():
    # Build node index for quick lookups
    node_index = {n["id"]: n for n in NODES}

    # Resolve edges to use node names
    resolved_edges = []
    for e in EDGES:
        src = node_index[e["source"]]
        tgt = node_index[e["target"]]
        resolved_edges.append({
            "source_id": e["source"],
            "source_name": src["name"],
            "source_label": src["label"],
            "target_id": e["target"],
            "target_name": tgt["name"],
            "target_label": tgt["label"],
            "edge": e["label"],
            "props": e.get("props", {}),
        })

    # Build attack chain annotations (what BT would detect)
    chains = [
        {
            "id": "chain-kerberoast-dcsync",
            "name": "Kerberoast → Admin → Session Harvest → DCSync",
            "severity": "critical",
            "steps": [
                {"action": "Kerberoast", "from": "user-sqlsvc", "description": "Crack SQL_SVC SPN ticket offline"},
                {"action": "AdminTo", "from": "user-sqlsvc", "to": "comp-castelblack", "description": "Local admin access to CASTELBLACK"},
                {"action": "HasSession", "from": "user-eddard", "to": "comp-castelblack", "description": "Harvest EDDARD.STARK credentials from memory"},
                {"action": "DCSync", "from": "user-eddard", "to": "domain-north", "description": "DCSync all domain hashes as Domain Admin"},
            ],
        },
        {
            "id": "chain-asrep-da",
            "name": "AS-REP Roast → GenericAll Chain → Domain Admin",
            "severity": "critical",
            "steps": [
                {"action": "AS-REP Roast", "from": "user-theon", "description": "Crack THEON.GREYJOY AS-REP hash offline"},
                {"action": "GenericAll", "from": "user-theon", "to": "group-stark", "description": "Full control over STARK group"},
                {"action": "GenericAll", "from": "group-stark", "to": "group-da", "description": "STARK group has full control over Domain Admins"},
                {"action": "AddMember", "from": "user-theon", "to": "group-da", "description": "Add self to Domain Admins"},
            ],
        },
        {
            "id": "chain-writedacl-dcsync",
            "name": "WriteDACL → Grant DCSync → Full Domain Compromise",
            "severity": "critical",
            "steps": [
                {"action": "Compromise", "from": "user-raven", "description": "Compromise SVC_RAVEN service account"},
                {"action": "MemberOf", "from": "user-raven", "to": "group-ravens", "description": "SVC_RAVEN is member of RAVEN KEEPERS"},
                {"action": "WriteDacl", "from": "group-ravens", "to": "domain-north", "description": "RAVEN KEEPERS can modify domain DACL"},
                {"action": "DCSync", "from": "user-raven", "to": "domain-north", "description": "Grant self DCSync rights, dump all hashes"},
            ],
        },
        {
            "id": "chain-rbcd",
            "name": "RBCD via WriteAccountRestrictions",
            "severity": "high",
            "steps": [
                {"action": "WriteAccountRestrictions", "from": "user-jon", "to": "comp-dreadfort", "description": "JON.SNOW can modify msDS-AllowedToActOnBehalfOfOtherIdentity"},
                {"action": "RBCD", "from": "user-jon", "to": "comp-dreadfort", "description": "Configure RBCD, request S4U2Proxy ticket"},
                {"action": "AdminTo", "from": "user-jon", "to": "comp-dreadfort", "description": "Impersonate admin, get SYSTEM on DREADFORT"},
            ],
        },
        {
            "id": "chain-shadow-creds",
            "name": "Shadow Credentials → Domain Admin",
            "severity": "critical",
            "steps": [
                {"action": "AddKeyCredentialLink", "from": "user-arya", "to": "user-catelyn", "description": "Add shadow credential to CATELYN.STARK"},
                {"action": "Authenticate", "from": "user-arya", "description": "Request TGT as CATELYN using shadow credential"},
                {"action": "MemberOf", "from": "user-catelyn", "to": "group-stark", "description": "CATELYN is in STARK group"},
                {"action": "GenericAll", "from": "group-stark", "to": "group-da", "description": "STARK → DA escalation"},
            ],
        },
        {
            "id": "chain-dnsadmins",
            "name": "DnsAdmins → DC Compromise",
            "severity": "high",
            "steps": [
                {"action": "MemberOf", "from": "user-luwin", "to": "group-dnsadmins", "description": "MAESTER.LUWIN is DnsAdmins member"},
                {"action": "DnsAdmin DLL", "from": "user-luwin", "to": "comp-winterfell", "description": "Load malicious DLL via dnscmd on DC"},
                {"action": "SYSTEM", "from": "user-luwin", "to": "comp-winterfell", "description": "SYSTEM shell on domain controller"},
            ],
        },
        # --- Complex chains ---
        {
            "id": "chain-accountops-exchange-dcsync",
            "name": "Account Operators → Exchange Group → WriteDACL → DCSync",
            "severity": "critical",
            "steps": [
                {"action": "MemberOf", "from": "user-samwell", "to": "group-accountops", "description": "SAMWELL.TARLY is Account Operators member"},
                {"action": "CreateUser", "from": "user-samwell", "description": "Account Operators can create domain users"},
                {"action": "GenericAll", "from": "group-accountops", "to": "group-ravens", "description": "Account Operators has GenericAll on RAVEN KEEPERS"},
                {"action": "AddMember", "from": "user-samwell", "to": "group-ravens", "description": "Add fake user to RAVEN KEEPERS"},
                {"action": "WriteDacl", "from": "group-ravens", "to": "domain-north", "description": "RAVEN KEEPERS has WriteDACL on domain"},
                {"action": "GrantDCSync", "from": "user-samwell", "to": "domain-north", "description": "Grant fake user DCSync rights via DACL edit"},
                {"action": "DCSync", "from": "user-samwell", "to": "domain-north", "description": "Dump all domain hashes with secretsdump"},
            ],
        },
        {
            "id": "chain-targeted-kerberoast",
            "name": "GenericWrite → Targeted Kerberoast → Pivot → Session Harvest",
            "severity": "high",
            "steps": [
                {"action": "GenericWrite", "from": "user-osha", "to": "user-rodrik", "description": "OSHA has GenericWrite on RODRIK.CASSEL"},
                {"action": "SetSPN", "from": "user-osha", "to": "user-rodrik", "description": "Set fake SPN on RODRIK (targeted kerberoast setup)"},
                {"action": "Kerberoast", "from": "user-osha", "description": "Request TGS for RODRIK's new SPN, crack offline"},
                {"action": "AdminTo", "from": "user-rodrik", "to": "comp-dreadfort", "description": "RODRIK has local admin on DREADFORT"},
                {"action": "HasSession", "from": "user-theon", "to": "comp-dreadfort", "description": "Harvest THEON.GREYJOY session from DREADFORT"},
            ],
        },
        {
            "id": "chain-unconstrained-coercion",
            "name": "Unconstrained Delegation + PetitPotam Coercion → Forest Compromise",
            "severity": "critical",
            "steps": [
                {"action": "Compromise", "from": "user-eddard", "to": "comp-winterfell", "description": "Gain access to WINTERFELL (DA or any chain above)"},
                {"action": "Monitor", "from": "comp-winterfell", "description": "Start Rubeus monitor on WINTERFELL (unconstrained delegation)"},
                {"action": "CoerceToTGT", "from": "comp-winterfell", "to": "comp-kingslanding", "description": "PetitPotam coerce KINGSLANDING DC to authenticate to WINTERFELL"},
                {"action": "CaptureTGT", "from": "comp-winterfell", "description": "Capture KINGSLANDING$ machine TGT via unconstrained delegation"},
                {"action": "DCSync", "from": "comp-winterfell", "to": "domain-seven", "description": "DCSync SEVENKINGDOMS.LOCAL using captured DC TGT"},
                {"action": "ForestCompromise", "from": "comp-winterfell", "to": "group-ea", "description": "Full forest compromise — Enterprise Admin across all domains"},
            ],
        },
        {
            "id": "chain-constrained-delegation",
            "name": "CanPSRemote → Constrained Delegation → DC Impersonation",
            "severity": "critical",
            "steps": [
                {"action": "CanPSRemote", "from": "user-jon", "to": "comp-deepwood", "description": "JON.SNOW has PS Remoting access to DEEPWOOD"},
                {"action": "ExtractKeys", "from": "user-jon", "to": "comp-deepwood", "description": "Extract DEEPWOOD$ machine account hash"},
                {"action": "S4U2Self", "from": "comp-deepwood", "description": "Request S4U2Self ticket as DEEPWOOD$"},
                {"action": "S4U2Proxy", "from": "comp-deepwood", "to": "comp-winterfell", "description": "S4U2Proxy to cifs/WINTERFELL impersonating Administrator"},
                {"action": "AdminTo", "from": "comp-deepwood", "to": "comp-winterfell", "description": "SYSTEM access on domain controller via constrained delegation"},
            ],
        },
        {
            "id": "chain-backup-operators",
            "name": "Backup Operators → Registry Hive Dump → Credential Extraction",
            "severity": "high",
            "steps": [
                {"action": "MemberOf", "from": "user-jeor", "to": "group-backupops", "description": "JEOR.MORMONT is Backup Operators member"},
                {"action": "BackupSAM", "from": "user-jeor", "to": "comp-winterfell", "description": "Backup SAM and SYSTEM registry hives from DC"},
                {"action": "ExtractHashes", "from": "user-jeor", "description": "Extract local admin NTLM hashes with secretsdump"},
                {"action": "PassTheHash", "from": "user-jeor", "to": "comp-winterfell", "description": "Pass-the-hash with extracted Administrator NTLM"},
            ],
        },
        {
            "id": "chain-mega-convergent",
            "name": "RBCD → AS-REP → ACL Chain → DA → Coercion → Forest Compromise",
            "severity": "critical",
            "steps": [
                {"action": "WriteAccountRestrictions", "from": "user-jon", "to": "comp-dreadfort", "description": "JON.SNOW configures RBCD on DREADFORT"},
                {"action": "RBCD", "from": "user-jon", "to": "comp-dreadfort", "description": "S4U2Proxy impersonation → SYSTEM on DREADFORT"},
                {"action": "HasSession", "from": "user-theon", "to": "comp-dreadfort", "description": "Harvest THEON.GREYJOY credentials from DREADFORT memory"},
                {"action": "AS-REP Roast", "from": "user-theon", "description": "Crack THEON offline (or use harvested creds directly)"},
                {"action": "GenericAll", "from": "user-theon", "to": "group-stark", "description": "THEON has full control over STARK group"},
                {"action": "GenericAll", "from": "group-stark", "to": "group-da", "description": "STARK group controls Domain Admins"},
                {"action": "AddMember", "from": "user-theon", "to": "group-da", "description": "Add JON to Domain Admins via STARK → DA chain"},
                {"action": "Compromise", "from": "user-jon", "to": "comp-winterfell", "description": "DA access to WINTERFELL (unconstrained delegation DC)"},
                {"action": "CoerceToTGT", "from": "comp-winterfell", "to": "comp-kingslanding", "description": "PetitPotam coerce forest root DC"},
                {"action": "DCSync", "from": "comp-winterfell", "to": "domain-seven", "description": "DCSync entire forest — full Enterprise Admin compromise"},
            ],
        },
    ]

    # Quick wins annotation (what BT highlights immediately)
    quick_wins = [
        {"type": "kerberoastable", "node": "user-sqlsvc", "name": "SQL_SVC",
         "reason": "Has SPN: MSSQL/CASTELBLACK:1433"},
        {"type": "asrep_roastable", "node": "user-theon", "name": "THEON.GREYJOY",
         "reason": "DoNotRequirePreAuth is set"},
        {"type": "unconstrained_delegation", "node": "comp-winterfell", "name": "WINTERFELL",
         "reason": "Domain controller with unconstrained delegation"},
        {"type": "dnsadmins_member", "node": "user-luwin", "name": "MAESTER.LUWIN",
         "reason": "Member of DnsAdmins group"},
        {"type": "writedacl_on_domain", "node": "group-ravens", "name": "RAVEN KEEPERS",
         "reason": "WriteDACL on domain object — can grant DCSync"},
        {"type": "shadow_credentials", "node": "user-arya", "name": "ARYA.STARK",
         "reason": "AddKeyCredentialLink on CATELYN.STARK (Domain Admin path)"},
        {"type": "rbcd_writable", "node": "user-jon", "name": "JON.SNOW",
         "reason": "WriteAccountRestrictions on DREADFORT"},
        {"type": "laps_readable", "node": "group-nightwatch", "name": "NIGHT WATCH",
         "reason": "ReadLAPSPassword on MOAT-CAILIN"},
        {"type": "constrained_delegation", "node": "comp-deepwood", "name": "DEEPWOOD",
         "reason": "Constrained delegation to cifs/WINTERFELL (DC)"},
        {"type": "account_operators", "node": "user-samwell", "name": "SAMWELL.TARLY",
         "reason": "Account Operators member — can create users and modify groups"},
        {"type": "backup_operators", "node": "user-jeor", "name": "JEOR.MORMONT",
         "reason": "Backup Operators member — can dump SAM/SYSTEM hives"},
        {"type": "cross_domain_trust", "node": "domain-north", "name": "NORTH → SEVENKINGDOMS",
         "reason": "Bidirectional trust to forest root — coercion path to Enterprise Admin"},
        {"type": "targeted_kerberoast", "node": "user-osha", "name": "OSHA",
         "reason": "GenericWrite on RODRIK.CASSEL — can set SPN for targeted kerberoast"},
    ]

    dataset = {
        "meta": {
            "name": "NORTH.SEVENKINGDOMS.LOCAL",
            "description": "Augmented GOADv2 NORTH domain — BloodTrail demo dataset",
            "source": "GOADv2 (m4lwhere/Bloodhound-CE-Sample-Data) + synthetic augmentation",
            "node_count": len(NODES),
            "edge_count": len(EDGES),
            "chain_count": len(chains),
        },
        "nodes": NODES,
        "edges": resolved_edges,
        "chains": chains,
        "quick_wins": quick_wins,
    }

    return dataset


if __name__ == "__main__":
    dataset = build_dataset()
    out = Path(__file__).parent / "sample_ad.json"
    out.write_text(json.dumps(dataset, indent=2))
    print(f"Wrote {out} ({dataset['meta']['node_count']} nodes, {dataset['meta']['edge_count']} edges, {dataset['meta']['chain_count']} chains)")
