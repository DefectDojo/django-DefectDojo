from django.test import TestCase
from dojo.models import Endpoint
from django.core.exceptions import ValidationError


class TestEndpointModel(TestCase):

    def test_empty(self):
        endpoint = Endpoint()
        self.assertIsNone(endpoint.protocol)
        self.assertIsNone(endpoint.userinfo)
        self.assertIsNone(endpoint.host)
        self.assertIsNone(endpoint.fqdn)
        self.assertIsNone(endpoint.port)
        self.assertIsNone(endpoint.path)
        self.assertIsNone(endpoint.query)
        self.assertIsNone(endpoint.fragment)
        self.assertIsNone(endpoint.product)

    def test_url_full(self):
        endpoint = Endpoint.from_uri('http://alice@foo.bar:8080/path1/path2?key1=value&no_value_key#fragment1')
        self.assertEqual(endpoint.protocol, 'http')
        self.assertEqual(endpoint.userinfo, 'alice')
        self.assertEqual(endpoint.host, 'foo.bar')
        self.assertEqual(endpoint.port, 8080)
        self.assertEqual(endpoint.path, 'path1/path2')  # path begins with '/' but Endpoint store "root-less" path
        self.assertEqual(endpoint.query, 'key1=value&no_value_key')
        self.assertEqual(endpoint.fragment, 'fragment1')

    def test_noscheme(self):
        endpoint = Endpoint.from_uri('//' + 'localhost:22')
        self.assertIsNone(endpoint.protocol)
        self.assertIsNone(endpoint.userinfo)
        self.assertEqual(endpoint.host, 'localhost')
        self.assertEqual(endpoint.port, 22)
        self.assertIsNone(endpoint.path)
        self.assertIsNone(endpoint.query)
        self.assertIsNone(endpoint.fragment)
        self.assertIsNone(endpoint.product)

    def test_ip(self):
        endpoint = Endpoint.from_uri('http://127.0.0.1/')
        self.assertEqual(endpoint.host, '127.0.0.1')
        endpoint = Endpoint(host='127.0.0.1')
        self.assertEqual(endpoint.host, '127.0.0.1')

    def test_invalid(self):
        self.assertRaises(ValidationError, Endpoint.from_uri, 'http://127.0.1/')
        self.assertRaises(ValidationError, Endpoint.from_uri, 'http://127.0.0.1:portNo/')
        self.assertRaises(ValidationError, Endpoint.from_uri, 'http://127.0.0.1:-1/')
        self.assertRaises(ValidationError, Endpoint.from_uri, 'http://127.0.0.1:66666/')
        self.assertRaises(ValidationError, Endpoint, host='127.0.1')
        self.assertRaises(ValidationError, Endpoint, host='127.0.0.1', port=-1)
        self.assertRaises(ValidationError, Endpoint, host='127.0.0.1', port=66666)

    def test_ports(self):
        # known port
        endpoint = Endpoint.from_uri('http://foo.bar/')
        self.assertEqual(endpoint.port, 80)
        # unknown port
        endpoint = Endpoint.from_uri('this-scheme-is-unknown://foo.bar/')
        self.assertIsNone(endpoint.port)

    def test_spacial_char(self):
        endpoint = Endpoint.from_uri('http://foo.bar/beforeSpace%20afterSpace')
        self.assertEqual(endpoint.path, 'beforeSpace afterSpace')
        self.assertEqual(str(endpoint), 'http://foo.bar/beforeSpace%20afterSpace')
        endpoint = Endpoint.from_uri('//' + 'foo.bar/beforeSpace%20afterSpace')
        self.assertEqual(endpoint.path, 'beforeSpace afterSpace')
        self.assertEqual(str(endpoint), 'foo.bar/beforeSpace%20afterSpace')

    def test_url_normalize(self):
        endpoint1 = Endpoint.from_uri('HTTP://FOO.BAR/')
        endpoint2 = Endpoint.from_uri('HtTp://foo.BAR/')
        self.assertEqual(endpoint1.protocol, 'HTTP')
        self.assertEqual(endpoint1.host, 'foo.bar')
        self.assertEqual(str(endpoint1), 'http://foo.bar/')
        self.assertEqual(endpoint1, endpoint2)
