from django.test import TestCase

from dojo.importers.endpoint_manager import EndpointManager, EndpointUniqueKey


class TestMakeEndpointUniqueTuple(TestCase):

    """Tests for EndpointManager._make_endpoint_unique_tuple normalization."""

    def _make(self, **kwargs):
        defaults = {
            "protocol": None,
            "userinfo": None,
            "host": None,
            "port": None,
            "path": None,
            "query": None,
            "fragment": None,
            "product_id": 1,
        }
        defaults.update(kwargs)
        return EndpointManager._make_endpoint_unique_tuple(**defaults)

    def test_protocol_case_insensitive(self):
        a = self._make(protocol="HTTP", host="example.com")
        b = self._make(protocol="http", host="example.com")
        self.assertEqual(a, b)

    def test_host_case_insensitive(self):
        a = self._make(host="Example.COM")
        b = self._make(host="example.com")
        self.assertEqual(a, b)

    def test_default_port_normalized_to_none_https(self):
        a = self._make(protocol="https", host="example.com", port=443)
        b = self._make(protocol="https", host="example.com", port=None)
        self.assertEqual(a, b)
        self.assertIsNone(a.port)

    def test_default_port_normalized_to_none_http(self):
        a = self._make(protocol="http", host="example.com", port=80)
        b = self._make(protocol="http", host="example.com", port=None)
        self.assertEqual(a, b)

    def test_non_default_port_preserved(self):
        a = self._make(protocol="https", host="example.com", port=8443)
        b = self._make(protocol="https", host="example.com", port=None)
        self.assertNotEqual(a, b)
        self.assertEqual(a.port, 8443)

    def test_none_fields_handled(self):
        key = self._make()
        self.assertIsNone(key.protocol)
        self.assertIsNone(key.host)
        self.assertIsNone(key.port)
        self.assertIsNone(key.path)

    def test_empty_string_fields_normalized_to_none(self):
        key = self._make(userinfo="", path="", query="", fragment="")
        self.assertIsNone(key.userinfo)
        self.assertIsNone(key.path)
        self.assertIsNone(key.query)
        self.assertIsNone(key.fragment)

    def test_different_products_different_keys(self):
        a = self._make(host="example.com", product_id=1)
        b = self._make(host="example.com", product_id=2)
        self.assertNotEqual(a, b)

    def test_returns_named_tuple(self):
        key = self._make(protocol="https", host="example.com", path="/api")
        self.assertIsInstance(key, EndpointUniqueKey)
        self.assertEqual(key.protocol, "https")
        self.assertEqual(key.host, "example.com")
        self.assertEqual(key.path, "/api")

    def test_port_without_known_protocol_preserved(self):
        key = self._make(protocol="custom", host="example.com", port=9999)
        self.assertEqual(key.port, 9999)

    def test_port_none_without_known_protocol(self):
        key = self._make(protocol="custom", host="example.com", port=None)
        self.assertIsNone(key.port)
