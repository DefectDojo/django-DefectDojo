import socket
from unittest.mock import patch

import requests
import urllib3.connection

from dojo.utils_ssrf import (
    SSRFError,
    _SSRFSafeAdapter,  # noqa: PLC2701
    _SSRFSafeHTTPConnection,  # noqa: PLC2701
    make_ssrf_safe_session,
    validate_url_for_ssrf,
)
from unittests.dojo_test_case import DojoTestCase


def _addr_info(ip, port=80):
    """Build a minimal getaddrinfo-style return value for a single IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


_MIXED_ADDR_INFO = [
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80)),
]


class TestValidateUrlForSsrf(DojoTestCase):

    @patch("dojo.utils_ssrf.socket.getaddrinfo", return_value=_addr_info("8.8.8.8"))
    def test_valid_public_url_does_not_raise(self, mock_getaddrinfo):
        validate_url_for_ssrf("http://example.com/api")  # should not raise

    def test_file_scheme_raises(self):
        with self.assertRaisesRegex(SSRFError, "not permitted"):
            validate_url_for_ssrf("file:///etc/passwd")

    def test_gopher_scheme_raises(self):
        with self.assertRaisesRegex(SSRFError, "not permitted"):
            validate_url_for_ssrf("gopher://example.com")

    def test_no_hostname_raises(self):
        with self.assertRaisesRegex(SSRFError, "no hostname"):
            validate_url_for_ssrf("http://")

    def test_loopback_ip_raises(self):
        with self.assertRaisesRegex(SSRFError, "non-public address"):
            validate_url_for_ssrf("http://127.0.0.1/")

    def test_private_class_c_raises(self):
        with self.assertRaisesRegex(SSRFError, "non-public address"):
            validate_url_for_ssrf("http://192.168.1.1/")

    def test_private_class_a_raises(self):
        with self.assertRaisesRegex(SSRFError, "non-public address"):
            validate_url_for_ssrf("http://10.0.0.1/")

    def test_link_local_raises(self):
        with self.assertRaisesRegex(SSRFError, "non-public address"):
            validate_url_for_ssrf("http://169.254.1.1/")

    @patch("dojo.utils_ssrf.socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known"))
    def test_unresolvable_hostname_raises(self, mock_getaddrinfo):
        with self.assertRaisesRegex(SSRFError, "Unable to resolve"):
            validate_url_for_ssrf("http://nonexistent.invalid/")

    @patch("dojo.utils_ssrf.socket.getaddrinfo", return_value=_MIXED_ADDR_INFO)
    def test_multi_address_with_private_ip_raises(self, mock_getaddrinfo):
        with self.assertRaisesRegex(SSRFError, "non-public address"):
            validate_url_for_ssrf("http://example.com/")


class TestMakeSsrfSafeSession(DojoTestCase):

    def test_returns_requests_session(self):
        session = make_ssrf_safe_session()
        self.assertIsInstance(session, requests.Session)

    def test_http_and_https_mounted_with_safe_adapter(self):
        session = make_ssrf_safe_session()
        self.assertIsInstance(session.get_adapter("http://example.com"), _SSRFSafeAdapter)
        self.assertIsInstance(session.get_adapter("https://example.com"), _SSRFSafeAdapter)


class TestConnectionAddressPinning(DojoTestCase):

    """The address the socket connects to must be the address that was checked."""

    def _connect_with(self, addr_infos):
        """Run _new_conn() and report the address urllib3 was handed."""
        seen = {}

        def capture(conn):
            seen["dns_host"] = conn._dns_host

        conn = _SSRFSafeHTTPConnection(host="example.com", port=80)
        with patch("dojo.utils_ssrf.socket.getaddrinfo", side_effect=addr_infos), \
             patch.object(urllib3.connection.HTTPConnection, "_new_conn", capture):
            conn._new_conn()
        return conn, seen["dns_host"]

    def test_second_lookup_cannot_redirect_the_connection(self):
        # A rebinding resolver answers public first, then loopback. Only the
        # first answer is checked, so only the first answer may be used.
        _conn, dns_host = self._connect_with([_addr_info("8.8.8.8"), _addr_info("127.0.0.1")])
        self.assertEqual(dns_host, "8.8.8.8")

    def test_hostname_restored_after_connecting(self):
        conn, _dns_host = self._connect_with([_addr_info("8.8.8.8")])
        self.assertEqual(conn.host, "example.com")

    @patch("dojo.utils_ssrf.socket.getaddrinfo", return_value=_addr_info("127.0.0.1"))
    def test_private_address_blocked_at_socket_creation(self, mock_getaddrinfo):
        conn = _SSRFSafeHTTPConnection(host="rebind.invalid", port=80)
        with self.assertRaisesRegex(SSRFError, "non-public address"):
            conn._new_conn()
