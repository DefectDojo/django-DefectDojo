"""
SSRF (Server-Side Request Forgery) protection utilities.

Provides a requests.Session that validates outbound URLs against private/reserved
IP ranges at socket-creation time, closing the DNS rebinding (TOCTOU) window that
exists when validation is performed only as a pre-flight step.

Usage:
    from dojo.utils_ssrf import make_ssrf_safe_session, validate_url_for_ssrf, SSRFError

    # Pre-flight validation (raises SSRFError with a human-readable message):
    validate_url_for_ssrf(url)

    # Safe session (validates at socket-creation time on every request):
    session = make_ssrf_safe_session()
    response = session.get(url)
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests
import urllib3.connection
import urllib3.connectionpool
from requests.adapters import DEFAULT_POOLBLOCK, DEFAULT_POOLSIZE, HTTPAdapter


class SSRFError(ValueError):

    """Raised when a URL is determined to be unsafe for server-side requests."""


_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _check_ip(ip_str: str) -> None:
    """Raise SSRFError if the IP address is not globally routable."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        msg = f"Cannot parse IP address: {ip_str!r}"
        raise SSRFError(msg) from exc

    # ip.is_global is False for loopback, link-local (169.254.x.x), RFC 1918,
    # reserved, multicast, and unspecified addresses.
    if not ip.is_global:
        msg = (
            f"Blocked: URL resolved to non-public address {ip}. "
            "Requests to private, loopback, link-local, or reserved "
            "addresses are not permitted."
        )
        raise SSRFError(msg)


def _resolve_and_check(hostname: str, port: int) -> None:
    """Resolve hostname and verify every returned address is publicly routable."""
    try:
        addr_infos = socket.getaddrinfo(
            hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        msg = f"Unable to resolve hostname {hostname!r}: {exc}"
        raise SSRFError(msg) from exc

    if not addr_infos:
        msg = f"No addresses returned for hostname {hostname!r}"
        raise SSRFError(msg)

    for _family, _type, _proto, _canon, sockaddr in addr_infos:
        _check_ip(sockaddr[0])


def validate_url_for_ssrf(url: str) -> None:
    """
    Pre-flight SSRF validation for a URL.

    Checks:
    - Scheme is http or https (blocks file://, gopher://, etc.)
    - Every resolved IP address is globally routable (blocks RFC 1918,
      loopback 127.x, link-local 169.254.x.x, and other reserved ranges)

    Raises SSRFError with a descriptive message if the URL is unsafe.
    This is a best-effort pre-flight check; use make_ssrf_safe_session() for
    socket-level enforcement that also mitigates DNS rebinding.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        msg = f"Malformed URL: {url!r}"
        raise SSRFError(msg) from exc

    if parsed.scheme not in _ALLOWED_SCHEMES:
        msg = (
            f"URL scheme {parsed.scheme!r} is not permitted. "
            "Only 'http' and 'https' are allowed."
        )
        raise SSRFError(msg)

    hostname = parsed.hostname
    if not hostname:
        msg = f"URL has no hostname: {url!r}"
        raise SSRFError(msg)

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    _resolve_and_check(hostname, port)


# ---------------------------------------------------------------------------
# urllib3 connection subclasses — validation runs at socket-creation time.
# Overriding _new_conn() (called immediately before the OS connect() syscall)
# minimises the TOCTOU window to microseconds, making DNS rebinding attacks
# impractical in practice.
# ---------------------------------------------------------------------------

class _SSRFSafeHTTPConnection(urllib3.connection.HTTPConnection):
    def _new_conn(self) -> socket.socket:
        _resolve_and_check(self._dns_host, self.port)
        return super()._new_conn()


class _SSRFSafeHTTPSConnection(urllib3.connection.HTTPSConnection):
    def _new_conn(self) -> socket.socket:
        _resolve_and_check(self._dns_host, self.port)
        return super()._new_conn()


class _SSRFSafeHTTPConnectionPool(urllib3.connectionpool.HTTPConnectionPool):
    ConnectionCls = _SSRFSafeHTTPConnection


class _SSRFSafeHTTPSConnectionPool(urllib3.connectionpool.HTTPSConnectionPool):
    ConnectionCls = _SSRFSafeHTTPSConnection


_SAFE_POOL_CLASSES = {
    "http": _SSRFSafeHTTPConnectionPool,
    "https": _SSRFSafeHTTPSConnectionPool,
}


class _SSRFSafeAdapter(HTTPAdapter):

    """
    A requests HTTPAdapter that injects SSRF-safe connection classes into the
    urllib3 pool manager so that IP validation happens at socket-creation time
    on every request, including after redirects.
    """

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        # Replace the pool classes after the manager is created.
        # pool_classes_by_scheme is a plain dict on the instance, so this
        # only affects this adapter's pool manager.
        self.poolmanager.pool_classes_by_scheme = _SAFE_POOL_CLASSES


def make_ssrf_safe_session() -> requests.Session:
    """
    Return a requests.Session with SSRF protection applied at the socket level.

    Every outbound request made through this session will have its resolved IP
    validated against the private/reserved range blocklist immediately before
    the OS socket is opened, preventing both:
    - Direct requests to internal IP ranges
    - DNS rebinding attacks
    """
    session = requests.Session()
    adapter = _SSRFSafeAdapter(pool_maxsize=DEFAULT_POOLSIZE)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
