import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .models import ValidationError

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data.ec2.internal",
}


class ScopeError(ValueError):
    pass


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, ip: str, sni_host: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(ip, port=port, timeout=timeout, context=context)
        self.sni_host = sni_host

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.sni_host)


@dataclass(frozen=True)
class ScopePolicy:
    program: str
    allowed_hosts: tuple[str, ...]
    denied_hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    max_requests_per_second: float
    require_https: bool
    allow_redirects: bool
    probe_timeout_seconds: float
    max_response_bytes: int

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScopePolicy":
        if not isinstance(value, dict):
            raise ScopeError("configuration must be an object")
        program = value.get("program")
        if not isinstance(program, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", program):
            raise ScopeError("program must be a simple identifier")
        allowed_hosts = value.get("allowed_hosts")
        if not isinstance(allowed_hosts, list) or not allowed_hosts:
            raise ScopeError("allowed_hosts must be a non-empty list")
        if any(not isinstance(host, str) or not host.strip() for host in allowed_hosts):
            raise ScopeError("allowed_hosts must contain only non-empty strings")
        normalized_hosts = tuple(sorted({host.lower().rstrip(".") for host in allowed_hosts}))
        if any(host in {"*", ""} for host in normalized_hosts):
            raise ScopeError("wildcard '*' is not allowed")
        denied_hosts = value.get("denied_hosts", [])
        if not isinstance(denied_hosts, list) or any(not isinstance(host, str) for host in denied_hosts):
            raise ScopeError("denied_hosts must be a list of strings")
        methods = tuple(str(method).upper() for method in value.get("allowed_methods", ["GET", "HEAD"]))
        if not methods or any(method not in {"GET", "HEAD", "OPTIONS"} for method in methods):
            raise ScopeError("allowed_methods must contain only GET, HEAD, or OPTIONS")
        ports = tuple(sorted({int(port) for port in value.get("allowed_ports", [443])}))
        if any(port < 1 or port > 65535 for port in ports):
            raise ScopeError("allowed_ports contains an invalid port")
        rate = float(value.get("max_requests_per_second", 0.2))
        if rate <= 0 or rate > 10:
            raise ScopeError("max_requests_per_second must be between 0 and 10")
        timeout = float(value.get("probe_timeout_seconds", 10))
        if timeout <= 0 or timeout > 60:
            raise ScopeError("probe_timeout_seconds must be between 0 and 60")
        max_bytes = int(value.get("max_response_bytes", 1048576))
        if max_bytes < 1024 or max_bytes > 10_000_000:
            raise ScopeError("max_response_bytes must be between 1024 and 10000000")
        if bool(value.get("allow_redirects", False)):
            raise ScopeError("redirects are disabled for safe probes")
        return cls(
            program=program,
            allowed_hosts=normalized_hosts,
            denied_hosts=tuple(sorted({host.lower().rstrip(".") for host in denied_hosts})),
            allowed_methods=methods,
            allowed_ports=ports,
            max_requests_per_second=rate,
            require_https=bool(value.get("require_https", True)),
            allow_redirects=False,
            probe_timeout_seconds=timeout,
            max_response_bytes=max_bytes,
        )

    def host_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in BLOCKED_HOSTS or host.endswith((".localhost", ".internal", ".local")):
            return False
        if any(host == denied or host.endswith("." + denied.lstrip("*.")) for denied in self.denied_hosts):
            return False
        for allowed in self.allowed_hosts:
            if allowed.startswith("*."):
                suffix = allowed[1:]
                if host.endswith(suffix) and host != allowed[2:]:
                    return True
            elif host == allowed:
                return True
        return False

    def validate_url(self, url: str) -> tuple[str, str, int]:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise ScopeError(f"invalid URL: {exc}") from exc
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ScopeError("only HTTP and HTTPS URLs are allowed")
        if self.require_https and scheme != "https":
            raise ScopeError("HTTPS is required by this program")
        if parsed.username or parsed.password:
            raise ScopeError("URLs with embedded credentials are not allowed")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or not self.host_allowed(host):
            raise ScopeError(f"host is outside the allowlist: {host or '<empty>'}")
        port = port or (443 if scheme == "https" else 80)
        if port not in self.allowed_ports:
            raise ScopeError(f"port {port} is outside the allowlist")
        return scheme, host, port

    def assert_public_host(self, host: str) -> str:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if not literal.is_global:
                raise ScopeError(f"non-public address is blocked: {host}")
            return str(literal)
        try:
            addresses = {
                result[4][0]
                for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except OSError as exc:
            raise ScopeError(f"DNS resolution failed for {host}") from exc
        if not addresses:
            raise ScopeError(f"DNS returned no addresses for {host}")
        parsed_addresses = []
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ScopeError(f"DNS returned an invalid address for {host}") from exc
            if not parsed.is_global:
                raise ScopeError(f"DNS resolved {host} to a non-public address")
            parsed_addresses.append(str(parsed))
        return sorted(parsed_addresses)[0]

    def probe(self, url: str, method: str = "GET", headers: dict[str, str] | None = None) -> dict[str, Any]:
        method = method.upper()
        if method not in self.allowed_methods:
            raise ScopeError(f"method {method} is not allowed")
        scheme, host, port = self.validate_url(url)
        address = self.assert_public_host(host)
        self._wait_for_slot()
        parsed = urlsplit(url)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        host_header = f"[{host}]" if ":" in host else host
        if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
            host_header += f":{port}"
        if scheme == "https":
            connection = _PinnedHTTPSConnection(
                address,
                host,
                port,
                self.probe_timeout_seconds,
                ssl.create_default_context(),
            )
        else:
            connection = _PinnedHTTPConnection(address, port=port, timeout=self.probe_timeout_seconds)
        base_headers: dict[str, str] = {
            "Host": host_header,
            "User-Agent": "hunt-v2-safe-probe/0.1",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            for key, value in headers.items():
                if key.lower() not in {"host", "content-length"}:
                    base_headers[key] = value
        try:
            connection.request(
                method,
                target,
                headers=base_headers,
            )
            response = connection.getresponse()
            body = response.read(self.max_response_bytes + 1)
            status = response.status
            headers = dict(response.getheaders())
        except (http.client.HTTPException, OSError, TimeoutError) as exc:
            raise ScopeError(f"probe failed: {exc}") from exc
        finally:
            connection.close()
        truncated = len(body) > self.max_response_bytes
        if truncated:
            body = body[: self.max_response_bytes]
        return {
            "url": url,
            "scheme": scheme,
            "host": host,
            "method": method,
            "status": status,
            "headers": {key.lower(): value for key, value in headers.items()},
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body),
            "truncated": truncated,
        }

    def _wait_for_slot(self) -> None:
        interval = 1 / self.max_requests_per_second
        now = time.monotonic()
        previous = getattr(self, "_last_request", 0.0)
        wait = interval - (now - previous)
        if wait > 0:
            time.sleep(wait)
        object.__setattr__(self, "_last_request", time.monotonic())


def load_policy(path: str) -> ScopePolicy:
    with open(path, encoding="utf-8") as handle:
        return ScopePolicy.from_dict(json.load(handle))


def validate_config(value: dict[str, Any]) -> dict[str, Any]:
    policy = ScopePolicy.from_dict(value)
    if not value.get("authorization_reference"):
        raise ValidationError("authorization_reference is required")
    return {
        "program": policy.program,
        "hosts": list(policy.allowed_hosts),
        "methods": list(policy.allowed_methods),
        "rate_per_second": policy.max_requests_per_second,
        "enabled": bool(value.get("enabled", False)),
    }
