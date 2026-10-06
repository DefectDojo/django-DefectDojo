from unittest import mock

from django.test import TestCase

from dojo.importers.endpoint_manager import EndpointManager, EndpointUniqueKey
from dojo.models import Endpoint, Product, Product_Type
from unittests.dojo_test_case import skip_unless_v2


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


# Regression: every import/reimport flush loaded ALL of the product's endpoints into Python to
# match the handful the report names, so on a product with millions of endpoints one flush spent
# minutes iterating rows (wall time far above SQL time) even when nothing had to be created.
@skip_unless_v2
class TestGetOrCreateEndpointsScopedLookup(TestCase):

    """get_or_create_endpoints reads only the product's endpoints the report could match."""

    def setUp(self):
        prod_type = Product_Type.objects.create(name="Endpoint manager lookup org")
        self.product = Product.objects.create(name="Endpoint manager lookup", description="test", prod_type=prod_type)
        self.other_product = Product.objects.create(name="Endpoint manager other", description="test", prod_type=prod_type)

    def _manager_for(self, *endpoints):
        manager = EndpointManager(self.product)
        for endpoint in endpoints:
            manager.record_endpoint(endpoint)
        return manager

    def _unrelated_endpoints(self, count):
        Endpoint.objects.bulk_create(
            Endpoint(protocol="https", host=f"unrelated-{i}.example.com", product=self.product) for i in range(count)
        )

    def _rows_loaded(self, manager):
        loaded = []
        original = Endpoint.from_db.__func__

        def counting_from_db(cls, db, field_names, values):
            instance = original(cls, db, field_names, values)
            loaded.append(instance)
            return instance

        with mock.patch.object(Endpoint, "from_db", classmethod(counting_from_db)):
            endpoints_by_key, created = manager.get_or_create_endpoints()
        return endpoints_by_key, created, loaded

    def test_rows_loaded_do_not_grow_with_unrelated_product_endpoints(self):
        existing = Endpoint.objects.create(protocol="https", host="match.example.com", path="/a", product=self.product)
        results = {}
        for unrelated in (0, 60):
            if unrelated:
                self._unrelated_endpoints(unrelated)
            manager = self._manager_for(Endpoint(protocol="https", host="match.example.com", path="/a"))
            endpoints_by_key, created, loaded = self._rows_loaded(manager)
            results[unrelated] = len(loaded)
            with self.subTest(unrelated=unrelated):
                self.assertEqual([], created)
                self.assertEqual([existing.id], [ep.id for ep in endpoints_by_key.values()])
        self.assertEqual(
            results[0], results[60],
            msg=f"rows loaded from dojo_endpoint grew with unrelated endpoints in the product: {results}",
        )

    def test_matching_semantics_are_unchanged(self):
        # host and protocol compare case-insensitively, the scheme's default port equals no port,
        # the first endpoint by id wins, and endpoints of other products never match.
        first = Endpoint.objects.create(protocol="HTTPS", host="Mixed.Example.COM", port=443, product=self.product)
        Endpoint.objects.create(protocol="https", host="mixed.example.com", port=None, product=self.product)
        Endpoint.objects.create(protocol="https", host="only-other.example.com", product=self.other_product)
        no_host = Endpoint.objects.create(protocol=None, host=None, path="/no-host", product=self.product)
        self._unrelated_endpoints(5)

        manager = self._manager_for(
            Endpoint(protocol="https", host="mixed.example.com"),
            Endpoint(protocol="https", host="only-other.example.com"),
            Endpoint(protocol=None, host=None, path="/no-host"),
        )
        endpoints_by_key, created, _ = self._rows_loaded(manager)

        by_host = {key.host: ep for key, ep in endpoints_by_key.items()}
        with self.subTest("case and default port"):
            self.assertEqual(first.id, by_host["mixed.example.com"].id)
        with self.subTest("null host"):
            self.assertEqual(no_host.id, by_host[None].id)
        with self.subTest("other product's endpoint is not reused"):
            self.assertEqual(["only-other.example.com"], [ep.host for ep in created])
            self.assertEqual(self.product.id, by_host["only-other.example.com"].product_id)
        with self.subTest("nothing else created"):
            self.assertEqual(1, len(created))
