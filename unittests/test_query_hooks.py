from dojo.models import Engagement, Finding, Product, Product_Type, Test
from dojo.query_hooks import _DEFAULT_QUERYSET_FILTERS, register_default_queryset_filter  # noqa: PLC2701
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestDefaultQuerysetHooks(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self._saved = {label: dict(funcs) for label, funcs in _DEFAULT_QUERYSET_FILTERS.items()}
        _DEFAULT_QUERYSET_FILTERS.clear()

    def tearDown(self):
        _DEFAULT_QUERYSET_FILTERS.clear()
        _DEFAULT_QUERYSET_FILTERS.update(self._saved)

    def test_nothing_registered_leaves_querysets_unchanged(self):
        for model in (Product_Type, Product, Engagement, Test, Finding):
            with self.subTest(model=model.__name__):
                self.assertEqual(model.objects.count(), model.unfiltered.count())

    def test_hooked_manager_is_the_default_manager(self):
        for model in (Product_Type, Product, Engagement, Test, Finding):
            with self.subTest(model=model.__name__):
                self.assertIs(model._default_manager, model.objects)
                self.assertIsNot(model._base_manager, model.objects)

    def test_registered_filter_applies_to_objects_get_and_reverse_relations(self):
        finding = Finding.objects.filter(test__isnull=False).first()
        register_default_queryset_filter("dojo.Finding", "hide-one", lambda qs: qs.exclude(pk=finding.pk))

        with self.subTest("objects"):
            self.assertFalse(Finding.objects.filter(pk=finding.pk).exists())
        with self.subTest("get"), self.assertRaises(Finding.DoesNotExist):
            Finding.objects.get(pk=finding.pk)
        with self.subTest("reverse relation"):
            self.assertNotIn(finding.pk, finding.test.finding_set.values_list("pk", flat=True))
        with self.subTest("unfiltered bypasses"):
            self.assertTrue(Finding.unfiltered.filter(pk=finding.pk).exists())
        with self.subTest("base manager bypasses"):
            self.assertTrue(Finding._base_manager.filter(pk=finding.pk).exists())

    def test_registering_the_same_key_replaces_the_filter(self):
        register_default_queryset_filter("dojo.Product", "k", lambda qs: qs.none())
        register_default_queryset_filter("dojo.Product", "k", lambda qs: qs)
        self.assertEqual(Product.objects.count(), Product.unfiltered.count())
