import shutil
import os
import subprocess
from datetime import datetime
from typing import List, Optional
import asyncio
import time


def get_nmap_path() -> str:
    """Find Nmap executable on the system."""
    if shutil.which("nmap"):
        return "nmap"

    default_paths = [r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe"]

    for path in default_paths:
        if os.path.exists(path):
            return path

    return ""



class PortScanner:

    async def scan_port(self, host: str, port: int, semaphore: asyncio.Semaphore, timeout: float) -> Optional[int]:
        """Check whether a single TCP port is reachable."""
        async with semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, OSError):
                return None

    async def fast_scan(self, host: str, ports: List[int], concurrency: int = 500, timeout: float = 0.3) -> List[int]:
        """Scan multiple TCP ports concurrently."""
        semaphore = asyncio.Semaphore(concurrency)
        tasks = [self.scan_port(host, port, semaphore, timeout) for port in ports]
        results = await asyncio.gather(*tasks)
        return sorted(port for port in results if port is not None)

class InfoGrabber:

    def __init__(self, host: str, open_ports: Optional[List[int]] = None):
        self.host = host
        self.open_ports = open_ports or []

    def nmap_scan(self, ports: Optional[List[int]] = None):
        """Run Nmap service detection."""
        scan_ports = ports if ports is not None else self.open_ports

        if not scan_ports:
            return "No ports specified for Nmap scan.", 0.0

        nmap_exe = get_nmap_path()

        if not nmap_exe:
            return "Error: Nmap is not installed on the system.", 0.0

        port_str = ",".join(map(str, scan_ports))

        cmd = [nmap_exe, "-sV", "--version-light", "-p", port_str, self.host]

        start_time = time.perf_counter()

        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, shell=False, check=False)
            elapsed = time.perf_counter() - start_time

            if completed.returncode != 0:
                return f"Nmap error:\n{completed.stderr}", elapsed

            return completed.stdout, elapsed

        except OSError as e:
            return f"Error running Nmap: {e}", 0.0



