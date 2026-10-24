from django.db.models import Case, Count, When
from django.test import RequestFactory
from django.utils import timezone

from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.models import (
    DEFAULT_STATS,
    IMPORT_ACTIONS,
    STATS_FIELDS,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    User,
)

from .dojo_test_case import DojoTestCase


def _counts():
    counts = {field: Count(Case(When(**{field: True}, then=1))) for field in STATS_FIELDS if field != "total"}
    return {**counts, "total": Count("id")}


class TestImportRequestQueries(DojoTestCase):

    """
    Regression: a small import or reimport through the API cost about 300 queries, most of them
    outside the importer. The permission check, the view and the serializer each resolved the
    target product, engagement and test again, and every statistics read ran a grouped query plus
    a separate aggregate for the totals (eight queries for ``Test_Import.statistics``).
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        self.product_type, _ = Product_Type.objects.get_or_create(name="Request Queries Org")
        self.product, _ = Product.objects.get_or_create(
            name="Request Queries App", defaults={"prod_type": self.product_type, "description": "App"},
        )
        self.engagement = Engagement.objects.create(
            name="CI", product=self.product, target_start=timezone.now(), target_end=timezone.now(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Request Queries Scan")
        self.test = Test.objects.create(
            engagement=self.engagement, test_type=test_type, scan_type=test_type.name,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        self.test_import = Test_Import.objects.create(test=self.test, type=Test_Import.REIMPORT_TYPE)
        severities = ["Critical", "High", "High", "Medium", "Low", "Info"]
        for n, (severity, (action, _label)) in enumerate(zip(severities, IMPORT_ACTIONS * 2, strict=False)):
            finding = Finding.objects.create(
                test=self.test, title=f"Finding {n}", severity=severity, reporter=self.user,
                active=n % 2 == 0, verified=n % 3 == 0, is_mitigated=n % 2 == 1,
            )
            Test_Import_Finding_Action.objects.create(test_import=self.test_import, finding=finding, action=action)

    def _reference_statistics(self, queryset):
        """What the statistics were computed as before: a grouped query plus a total aggregate."""
        stats = {
            severity: queryset.filter(severity__iexact=severity).aggregate(**_counts())
            for severity in DEFAULT_STATS
        }
        stats["total"] = queryset.aggregate(**_counts())
        return stats

    def test_test_statistics_is_one_query(self):
        with self.assertNumQueries(1):
            stats = self.test.statistics
        self.assertEqual(self._reference_statistics(Finding.objects.filter(test=self.test)), stats)

    def test_test_import_statistics_is_one_query_for_every_action(self):
        with self.assertNumQueries(1):
            stats = self.test_import.statistics
        self.assertEqual([label for _action, label in IMPORT_ACTIONS], list(stats))
        for action, label in IMPORT_ACTIONS:
            with self.subTest(action=label):
                findings = Finding.objects.filter(
                    test_import_finding_action__test_import=self.test_import,
                    test_import_finding_action__action=action,
                )
                self.assertEqual(self._reference_statistics(findings), stats[label])

    def test_test_import_statistics_of_an_action_with_no_findings_is_all_zero(self):
        Test_Import_Finding_Action.objects.filter(action=IMPORT_ACTIONS[1][0]).delete()
        stats = self.test_import.statistics[IMPORT_ACTIONS[1][1]]
        self.assertEqual(0, stats["total"]["total"])
        self.assertEqual(0, stats["high"]["total"])

    def test_one_request_resolves_each_target_once(self):
        request = RequestFactory().post("/api/v2/reimport-scan/")
        names = {
            "product_type_name": self.product_type.name,
            "product_name": self.product.name,
            "engagement_name": self.engagement.name,
            "scan_type": self.test.scan_type,
        }

        def resolve(manager):
            product = manager.get_target_product_if_exists(**names)
            engagement = manager.get_target_engagement_if_exists(product=product, **names)
            return manager.get_target_test_if_exists(engagement=engagement, **names)

        # The permission check: product (with its organization), engagement, test.
        with self.assertNumQueries(3):
            self.assertEqual(self.test, resolve(AutoCreateContextManager.for_request(request)))
        # The view and then the serializer handle the same request: nothing is looked up again.
        with self.assertNumQueries(0):
            self.assertEqual(self.test, resolve(AutoCreateContextManager.for_request(request)))
            self.assertEqual(self.test, resolve(AutoCreateContextManager.for_request(request)))
        # Another request looks the targets up afresh.
        with self.assertNumQueries(3):
            resolve(AutoCreateContextManager.for_request(RequestFactory().post("/api/v2/reimport-scan/")))

    def test_a_target_not_found_is_looked_up_again(self):
        # The creators look again before they create, so a miss is never remembered.
        manager = AutoCreateContextManager.for_request(RequestFactory().post("/api/v2/import-scan/"))
        with self.assertNumQueries(1):
            self.assertIsNone(manager.get_target_product_if_exists(product_name="Not Yet Created"))
        with self.assertNumQueries(1):
            self.assertIsNone(manager.get_target_product_if_exists(product_name="Not Yet Created"))

    def test_a_remembered_product_still_checks_the_organization_supplied(self):
        manager = AutoCreateContextManager.for_request(RequestFactory().post("/api/v2/import-scan/"))
        manager.get_target_product_if_exists(product_name=self.product.name)
        with self.assertNumQueries(0), self.assertRaisesRegex(ValueError, "conflict with the supplied product type"):
            manager.get_target_product_if_exists(product_name=self.product.name, product_type_name="Another Org")

    def test_without_a_request_nothing_is_shared(self):
        self.assertIsNot(AutoCreateContextManager.for_request(None), AutoCreateContextManager.for_request(None))
