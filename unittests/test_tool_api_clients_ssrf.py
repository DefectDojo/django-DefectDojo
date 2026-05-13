import socket
from types import SimpleNamespace
from unittest.mock import patch

from dojo.tools.api_bugcrowd.api_client import BugcrowdAPI
from dojo.tools.api_cobalt.api_client import CobaltAPI
from dojo.tools.api_edgescan.api_client import EdgescanAPI
from dojo.tools.api_sonarqube.api_client import SonarQubeAPI
from dojo.tools.api_vulners.api_client import VulnersAPI
from dojo.utils_ssrf import _SSRFSafeAdapter  # noqa: PLC2701
from unittests.dojo_test_case import DojoTestCase


def _sonarqube_config(url):
    return SimpleNamespace(
        url=url,
        authentication_type="API",
        api_key="dummy-key",
        extras=None,
    )


def _edgescan_config(url):
    return SimpleNamespace(
        url=url,
        authentication_type="API",
        api_key="dummy-key",
        extras=None,
    )


def _vulners_config(url):
    return SimpleNamespace(
        url=url,
        authentication_type="API",
        api_key="dummy-key",
    )


def _bugcrowd_config():
    return SimpleNamespace(
        authentication_type="API",
        api_key="dummy-key",
    )


def _cobalt_config():
    return SimpleNamespace(
        authentication_type="API",
        api_key="dummy-key",
        extras=None,
    )


class TestSonarQubeUrlValidation(DojoTestCase):

    def test_private_url_raises(self):
        with self.assertRaisesRegex(ValueError, "SonarQube URL is not allowed"):
            SonarQubeAPI(_sonarqube_config("http://192.168.1.1/"))

    def test_loopback_url_raises(self):
        with self.assertRaisesRegex(ValueError, "SonarQube URL is not allowed"):
            SonarQubeAPI(_sonarqube_config("http://127.0.0.1/"))

    def test_link_local_metadata_url_raises(self):
        with self.assertRaisesRegex(ValueError, "SonarQube URL is not allowed"):
            SonarQubeAPI(_sonarqube_config("http://169.254.169.254/"))

    def test_public_url_succeeds(self):
        # 8.8.8.8 is a numeric literal — no DNS lookup required, so this is
        # reliable in CI.
        client = SonarQubeAPI(_sonarqube_config("http://8.8.8.8/"))
        self.assertEqual(client.sonar_api_url, "http://8.8.8.8/")


class TestEdgescanUrlValidation(DojoTestCase):

    def test_private_url_raises(self):
        with self.assertRaisesRegex(ValueError, "Edgescan URL is not allowed"):
            EdgescanAPI(_edgescan_config("http://192.168.1.1/"))

    def test_loopback_url_raises(self):
        with self.assertRaisesRegex(ValueError, "Edgescan URL is not allowed"):
            EdgescanAPI(_edgescan_config("http://127.0.0.1/"))

    def test_public_url_succeeds(self):
        client = EdgescanAPI(_edgescan_config("http://8.8.8.8/"))
        self.assertEqual(client.url, "http://8.8.8.8/")

    def test_default_url_succeeds(self):
        # tool_config.url=None should fall back to DEFAULT_URL (a public host).
        with patch("dojo.utils_ssrf.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            ]
            client = EdgescanAPI(_edgescan_config(None))
            self.assertEqual(client.url, EdgescanAPI.DEFAULT_URL)


class TestVulnersUrlValidation(DojoTestCase):

    def test_private_url_raises(self):
        with self.assertRaisesRegex(ValueError, "Vulners URL is not allowed"):
            VulnersAPI(_vulners_config("http://192.168.1.1/"))

    def test_loopback_url_raises(self):
        with self.assertRaisesRegex(ValueError, "Vulners URL is not allowed"):
            VulnersAPI(_vulners_config("http://127.0.0.1/"))

    def test_public_url_succeeds(self):
        client = VulnersAPI(_vulners_config("http://8.8.8.8/"))
        self.assertEqual(client.vulners_api_url, "http://8.8.8.8/")

    def test_no_url_uses_library_default(self):
        # When no URL is configured, the validation is skipped and the
        # external `vulners` library uses its own default endpoint.
        client = VulnersAPI(_vulners_config(None))
        self.assertIsNone(client.vulners_api_url)


class TestBugcrowdSessionIsSafe(DojoTestCase):

    def test_session_uses_ssrf_safe_adapter(self):
        client = BugcrowdAPI(_bugcrowd_config())
        for adapter in client.session.adapters.values():
            self.assertIsInstance(adapter, _SSRFSafeAdapter)


class TestCobaltSessionIsSafe(DojoTestCase):

    def test_session_uses_ssrf_safe_adapter(self):
        client = CobaltAPI(_cobalt_config())
        for adapter in client.session.adapters.values():
            self.assertIsInstance(adapter, _SSRFSafeAdapter)
