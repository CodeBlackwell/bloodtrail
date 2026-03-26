"""
BloodHound Trail - IP Address Resolution

Uses nslookup to resolve hostnames via the Domain Controller's DNS.

Usage:
    resolver = IPResolver(dc_ip="192.168.50.70")
    ip = resolver.resolve("FILES04.CORP.COM")  # -> "10.0.0.15" or None

    # Batch resolution (parallel)
    computers = ["FILES04.CORP.COM", "CLIENT74.CORP.COM", "DC1.CORP.COM"]
    ip_map = resolver.resolve_batch(computers)
"""

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional


class IPResolver:
    """
    nslookup-based IP resolver with caching and parallel batch processing.
    """

    def __init__(self, timeout: float = 2.0, max_workers: int = 10, dc_ip: Optional[str] = None):
        self._cache: Dict[str, Optional[str]] = {}
        self.timeout = timeout
        self.max_workers = max_workers
        self.dc_ip = dc_ip
        self._stats = {"resolved": 0, "failed": 0, "cached": 0}

    def resolve(self, fqdn: str) -> Optional[str]:
        """Resolve FQDN to IPv4 using nslookup."""
        if not fqdn or not self.dc_ip:
            return None

        # Check cache
        if fqdn in self._cache:
            self._stats["cached"] += 1
            return self._cache[fqdn]

        try:
            # nslookup HOSTNAME DNS_SERVER
            result = subprocess.run(
                ["nslookup", fqdn, self.dc_ip],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Parse output for IP address
            # Look for "Address: X.X.X.X" after the server info
            output = result.stdout

            # Split into lines and find the answer section
            lines = output.strip().split('\n')
            found_name = False
            for line in lines:
                # Skip server info section
                if 'Name:' in line and fqdn.lower() in line.lower():
                    found_name = True
                    continue
                if found_name and 'Address:' in line:
                    # Extract IP from "Address: X.X.X.X"
                    match = re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        self._cache[fqdn] = ip
                        self._stats["resolved"] += 1
                        return ip

            # No IP found
            self._cache[fqdn] = None
            self._stats["failed"] += 1
            return None

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception):
            self._cache[fqdn] = None
            self._stats["failed"] += 1
            return None

    def resolve_batch(self, fqdns: List[str]) -> Dict[str, Optional[str]]:
        """Resolve multiple FQDNs in parallel."""
        results: Dict[str, Optional[str]] = {}
        unique_fqdns = [f for f in set(fqdns) if f]

        if not unique_fqdns:
            return results

        # Check cache first
        to_resolve = []
        for fqdn in unique_fqdns:
            if fqdn in self._cache:
                results[fqdn] = self._cache[fqdn]
                self._stats["cached"] += 1
            else:
                to_resolve.append(fqdn)

        # Resolve in parallel
        if to_resolve:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_fqdn = {executor.submit(self.resolve, fqdn): fqdn for fqdn in to_resolve}
                for future in as_completed(future_to_fqdn):
                    fqdn = future_to_fqdn[future]
                    try:
                        results[fqdn] = future.result()
                    except Exception:
                        results[fqdn] = None
                        self._cache[fqdn] = None

        return results

    def get_stats(self) -> Dict[str, int]:
        """Get resolution statistics."""
        return dict(self._stats)

    def clear_cache(self):
        """Clear the resolution cache."""
        self._cache.clear()

    def get_cache_size(self) -> int:
        """Get number of entries in cache."""
        return len(self._cache)
