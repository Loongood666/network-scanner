"""
TCP Port Scanner with threading support.
Scans IP ranges and port ranges efficiently.
"""

import socket
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Network utilities
# ---------------------------------------------------------------------------

def ip_range(start_ip: str, end_ip: str):
    """Generate all IPs in range [start_ip, end_ip] inclusive."""
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    for ip_int in range(start, end + 1):
        yield str(ipaddress.IPv4Address(ip_int))


def parse_ports(port_str: str, start_port: int = 0, end_port: int = 0):
    """
    Parse port specification string into a sorted list of unique ports.
    Supports comma-separated ports like '80,443,554' and port ranges like '8000-8010'.
    Also merges start_port:end_port range if specified.
    """
    ports = set()
    if port_str and port_str.strip():
        for part in port_str.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                # Port range like 8000-8010
                try:
                    lo, hi = part.split("-", 1)
                    lo, hi = int(lo.strip()), int(hi.strip())
                    for p in range(lo, hi + 1):
                        if 1 <= p <= 65535:
                            ports.add(p)
                except (ValueError, IndexError):
                    continue
            else:
                # Single port
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    continue
    # Add start_port:end_port range
    if start_port > 0 and end_port >= start_port:
        for p in range(start_port, end_port + 1):
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


# ---------------------------------------------------------------------------
# TCP Scan
# ---------------------------------------------------------------------------

def scan_tcp_port(ip: str, port: int, timeout: float = 1.5) -> Optional[dict]:
    """
    Scan a single TCP port on a host.
    Returns dict with result or None if filtered/closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Try to grab banner
            banner = ""
            try:
                sock.settimeout(2.0)
                # Send HTTP probe for web ports
                if port in (80, 8080, 8000, 8081, 8443, 443, 8090):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                else:
                    sock.sendall(b"\r\n")
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace")[:200]
            except (socket.timeout, Exception):
                pass
            sock.close()
            return {
                "ip": ip,
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "banner": banner.strip(),
            }
        sock.close()
    except (socket.timeout, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Multi-threaded Scanner
# ---------------------------------------------------------------------------

class PortScanner:
    """Threaded port scanner with progress callback."""

    def __init__(
        self,
        start_ip: str,
        end_ip: str,
        ports: list,
        timeout: float = 1.5,
        max_threads: int = 100,
        on_result: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
    ):
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.on_result = on_result
        self.on_progress = on_progress
        self._stop_event = threading.Event()
        self.results = []
        self._lock = threading.Lock()

    def stop(self):
        """Signal the scanner to stop."""
        self._stop_event.set()

    @property
    def is_stopped(self):
        return self._stop_event.is_set()

    def _scan_one(self, ip, port):
        """Scan one target; called from thread pool."""
        if self._stop_event.is_set():
            return None
        result = scan_tcp_port(ip, port, self.timeout)
        if result:
            with self._lock:
                self.results.append(result)
            if self.on_result:
                self.on_result(result)
        return result

    def scan(self):
        """Run the full scan with thread pool."""
        self.results = []
        self._stop_event.clear()

        targets = []
        for ip in ip_range(self.start_ip, self.end_ip):
            for port in self.ports:
                targets.append((ip, port))

        total = len(targets)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_one, ip, port): (ip, port)
                for ip, port in targets
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                completed += 1
                if self.on_progress and completed % 10 == 0:
                    self.on_progress(completed, total)

        if self.on_progress:
            self.on_progress(completed, total)

        return self.results