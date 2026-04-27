import socket
from unittest.mock import patch

import requests

from dojo.utils_ssrf import SSRFError, _SSRFSafeAdapter, make_ssrf_safe_session, validate_url_for_ssrf  # noqa: PLC2701
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
