
from django.core.exceptions import ValidationError

from dojo.location.utils import url_get_or_create
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3


@skip_unless_v3
class TestURLModel(DojoTestCase):

    def test_empty(self):
        url = URL()
        self.assertEqual(url.protocol, "")
        self.assertEqual(url.user_info, "")
        self.assertEqual(url.host, "")
        self.assertIsNone(url.port, "")
        self.assertEqual(url.path, "")
        self.assertEqual(url.query, "")
        self.assertEqual(url.fragment, "")

    def test_url_full(self):
        url = URL.from_value("http://alice@foo.bar:8080/path1/path2?key1=value&no_value_key#fragment1")
        self.assertEqual(url.protocol, "http")
        self.assertEqual(url.user_info, "alice")
        self.assertEqual(url.host, "foo.bar")
        self.assertEqual(url.port, 8080)
        self.assertEqual(url.path, "path1/path2")  # path begins with '/' but Location store "root-less" path
        self.assertEqual(url.query, "key1=value&no_value_key")
        self.assertEqual(url.fragment, "fragment1")

    def test_truncates_large_attributes(self):
        path = "foo" * 1000
        query = "bar" * 1000
        fragment = "baz" * 1000
        url = URL.from_value(f"http://alice@foo.bar:8080/{path}?{query}#{fragment}")
        self.assertEqual(len(url.path), 2048)
        self.assertEqual(len(url.query), 2048)
        self.assertEqual(len(url.fragment), 2048)

    def test_noscheme(self):
        url = URL.from_value("//" + "localhost:22")
        self.assertEqual(url.protocol, "")
        self.assertEqual(url.user_info, "")
        self.assertEqual(url.host, "localhost")
        self.assertEqual(url.port, 22)
        self.assertEqual(url.path, "")
        self.assertEqual(url.query, "")
        self.assertEqual(url.fragment, "")

    def test_paths(self):
        url = URL.from_value("https://foo.bar")
        self.assertEqual(url.path, "")
        url = URL.from_value("https://foo.bar/")
        self.assertEqual(url.path, "")

    def test_ip(self):
        url = URL.from_value("http://127.0.0.1/")
        self.assertEqual(url.host, "127.0.0.1")
        url = URL(host="127.0.0.1")
        self.assertEqual(url.host, "127.0.0.1")

    # Regression: a bare (unbracketed) IPv6 endpoint -- infra scanners such as
    # Tenable emit fe80::... -- raised ValidationError("No host provided") out of
    # URL.from_value, which failed an entire connector reimport chunk. RFC 3986
    # requires an IPv6 literal in a URL authority to be bracketed, so the parser now
    # normalises a bare (or scheme-less bracketed) IPv6 host to //[...] before it
    # reaches hyperlink.
    def test_ipv6(self):
        cases = [
            # (input, expected host, expected port, expected protocol)
            ("fe80::0250:56ff:febb:0000", "fe80::0250:56ff:febb:0000", None, ""),  # the reported bug
            ("[fe80::1]", "fe80::1", None, ""),                                    # bracketed, no scheme
            ("2001:db8::1", "2001:db8::1", None, ""),                              # bare, no scheme
            ("http://[fe80::1]:8080/path", "fe80::1", 8080, "http"),              # already-schemed, unchanged
        ]
        for value, host, port, protocol in cases:
            with self.subTest(value=value):
                url = URL.from_value(value)
                self.assertEqual(url.host, host, msg=f"{value!r} -> host={url.host!r}")
                self.assertEqual(url.port, port, msg=f"{value!r} -> port={url.port!r}")
                self.assertEqual(url.protocol, protocol, msg=f"{value!r} -> protocol={url.protocol!r}")

        # A bracketed IPv6 host round-trips through str() with its brackets intact.
        self.assertEqual(
            str(URL.from_value("http://[fe80::1]:8080/path")),
            "http://[fe80::1]:8080/path",
        )

        # A bare IPv6 host is canonicalised (compressed) at clean() time.
        url = URL(host="fe80::0250:56ff:febb:0000")
        url.full_clean()
        self.assertEqual(url.host, "fe80::250:56ff:febb:0")

    def test_host_with_port_is_not_treated_as_ipv6(self):
        # Control: the bare-IPv6 normalisation must not disturb a scheme-relative
        # host:port -- a single colon is not an IPv6 literal.
        url = URL.from_value("//example.com:8080")
        self.assertEqual(url.host, "example.com")
        self.assertEqual(url.port, 8080)

    def test_less_standard_hosts(self):
        url = URL.from_value("http://123_server/")
        url.full_clean()
        url = URL(host="456_desktop")
        url.full_clean()
        url = URL(host="_invalid._host.com")
        url.full_clean()

    def test_invalid(self):
        self.assertRaises(ValidationError, URL.from_value, "http://127.0.0.1:portNo/")
        self.assertRaises(ValidationError, URL.from_value, "http://127.0.0.1:-1/")
        self.assertRaises(ValidationError, URL.from_value, "http://127.0.0.1:66666/")
        url = URL(host="127.0.0.1", port=-1)
        self.assertRaises(ValidationError, url.full_clean)
        url = URL(host="127.0.0.1", port=66666)
        self.assertRaises(ValidationError, url.full_clean)

    def test_ports(self):
        # known port
        url = URL.from_value("http://foo.bar/")
        self.assertEqual(url.port, 80)
        # unknown port
        url = URL.from_value("tcp://foo.bar/")
        self.assertIsNone(url.port)

    # Regression: network/infra-scanner endpoints using udp/snmp/ipp/icmp
    # protocols were rejected by URL validation ("<proto> is not a supported
    # protocol"), so migrate_endpoints_to_locations silently dropped them —
    # ~65% of endpoints on infra-scan-heavy instances.
    def test_scanner_protocols_supported(self):
        for protocol, expected_port in (
            ("udp", None),
            ("icmp", None),
            ("snmp", 161),
            ("ipp", 631),
        ):
            url = URL(protocol=protocol, host="foo.bar")
            url.full_clean()  # must not raise
            self.assertEqual(
                url.port, expected_port,
                msg=f"expected default port {expected_port} for {protocol!r}, got {url.port!r}",
            )

    def test_unsupported_protocol_still_rejected(self):
        # Control: a genuinely unknown protocol must still fail validation.
        url = URL(protocol="definitelynotaprotocol", host="foo.bar")
        self.assertRaises(ValidationError, url.full_clean)

    def test_spacial_char(self):
        url = URL.from_value("http://foo.bar/beforeSpace%20afterSpace")
        self.assertEqual(url.path, "beforeSpace%20afterSpace")
        self.assertEqual(str(url), "http://foo.bar/beforeSpace%20afterSpace")
        url = URL.from_value("//" + "foo.bar/beforeSpace%20afterSpace")
        self.assertEqual(url.path, "beforeSpace%20afterSpace")
        self.assertEqual(str(url), "foo.bar/beforeSpace%20afterSpace")

    def test_url_normalize(self):
        url1 = URL.from_value("HTTP://FOO.BAR/")
        url2 = URL.from_value("HtTp://foo.BAR/")
        self.assertEqual(url1.protocol, "http")
        self.assertEqual(url1.host, "foo.bar")
        self.assertEqual(str(url1), "http://foo.bar")
        self.assertEqual(str(url2), "http://foo.bar")
        self.assertEqual(url1, url2)

    def test_get_or_create(self):
        _url1, created1 = url_get_or_create(
            protocol="http",
            host="bar.foo",
        )
        self.assertTrue(created1)

        _url2, created2 = url_get_or_create(
            protocol="http",
            host="bar.foo",
        )
        self.assertFalse(created2)

        _url3, created3 = url_get_or_create(
            protocol="http",
            host="bar.foo",
            port=80,
        )
        self.assertFalse(created3)

        _url4, created4 = url_get_or_create(
            protocol="http",
            host="bar.foo",
            port=8080,
        )
        self.assertTrue(created4)

        _url5, created5 = url_get_or_create(
            protocol="https",
            host="bar.foo",
            port=443,
        )
        self.assertTrue(created5)

        _url6, created6 = url_get_or_create(
            protocol="https",
            host="bar.foo",
        )
        self.assertFalse(created6)

        _url7, created7 = url_get_or_create(
            protocol="https",
            host="bar.foo",
            port=8443,
        )
        self.assertTrue(created7)

    def test_equality(self):
        # Test with all the fields
        url1 = URL(protocol="https", host="localhost", port=5439, path="test", query="param=value")
        url2 = URL(protocol="https", host="localhost", port=5439, path="test", query="param=value")
        url3 = URL(protocol="https", host="localhost", port=5439, path="different", query="param=value")
        # Verify e1 and e2 are actually equal
        self.assertEqual(url1, url2)
        # Verify e1 and e2 are not equal because the path is different
        self.assertNotEqual(url1, url3)
