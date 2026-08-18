import argparse
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
        if concurrency <= 0:
            raise ValueError("concurrency must be greater than 0")

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

def parse_args():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default=None, help="Port: 80 | 80,443,8080 | 1-1024 | 22,80,8000-8100")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrency (default: 500)")
    parser.add_argument("--timeout", type=float, default=0.3, help="Timeout in seconds (default: 0.3)")
    return parser.parse_args()

def parse_ports(port_string):
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {part}")
            ports.add(port)
    return sorted(ports)


async def main():
    args = parse_args()
    target_host = args.target
    ports_to_scan = parse_ports(args.ports) if args.ports else list(range(1, 1001))
    concurrency = args.concurrency
    timeout = args.timeout
    port_range_str = f"{ports_to_scan[0]}-{ports_to_scan[-1]}"
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 60)
    print(f"Starting Scan for target: {target_host}")
    print(f"Port Range: {port_range_str}")
    print(f"Scan Timestamp: {scan_timestamp}")
    print("=" * 60)

    print("\n>>> [1/3] RUNNING ASYNC PORT SCAN <<<")

    scanner = PortScanner()
    start_p1 = time.perf_counter()
    open_ports = await scanner.fast_scan(host=target_host, ports=ports_to_scan, concurrency=concurrency, timeout=timeout)
    p1_time = time.perf_counter() - start_p1

    print(f"[Phase 1] Async Python Scan Completed. Discovered Open Ports: {open_ports}")
    print(f"Scan Time: {p1_time:.3f} seconds")

    print("\n>>> [2/3] RUNNING TARGETED NMAP SCAN <<<")

    info_grabber = InfoGrabber(host=target_host, open_ports=open_ports)

    if open_ports:
        print(f"Running Nmap on discovered ports: {open_ports}")
        hybrid_nmap_output, nmap_time = info_grabber.nmap_scan()
        print(f"Targeted Nmap Time: {nmap_time:.3f} seconds")
        print("\nTargeted Nmap Output:")
        # print(hybrid_nmap_output)
        #print(type(hybrid_nmap_output))
        print("\n".join(hybrid_nmap_output.split("\n")[2:-3]))
    else:
        print("No open ports found. Skipping targeted Nmap.")
        hybrid_nmap_output = ""
        nmap_time = 0.0

    hybrid_total_time = p1_time + nmap_time


    # print("\n>>> [3/3] RUNNING PURE NMAP SCAN <<<")
    #
    # pure_nmap_output, pure_nmap_time = info_grabber.nmap_scan(ports=ports_to_scan)
    #
    # print("\nPure Nmap Output:")
    # print(pure_nmap_output)

    print("\n" + "=" * 60)
    print("PERFORMANCE & EXECUTION TIME COMPARISON")
    print("=" * 60)
    print(f"Hybrid - Python Discovery: {p1_time:.3f} seconds")
    print(f"Hybrid - Targeted Nmap: {nmap_time:.3f} seconds")
    print(f"Hybrid TOTAL: {hybrid_total_time:.3f} seconds")
    # print("-" * 60)
    # print(f"Pure Nmap: {pure_nmap_time:.3f} seconds")
    print("=" * 60)
    #
    # if hybrid_total_time > 0 and pure_nmap_time > 0:
    #     if pure_nmap_time > hybrid_total_time:
    #         time_saved = pure_nmap_time - hybrid_total_time
    #         speedup = pure_nmap_time / hybrid_total_time
    #         print(f"RESULT: Hybrid Scan was {speedup:.2f}x faster! Saved: {time_saved:.3f} seconds")
    #     else:
    #         print("RESULT: Pure Nmap was comparable or faster.")
    #
    # print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())