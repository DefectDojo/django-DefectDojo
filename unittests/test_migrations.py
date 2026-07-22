import datetime
from unittest import skip

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from django_test_migrations.contrib.unittest_case import MigratorTestCase

from dojo.finding.vulnerability_id import resolve_vulnerability_id_type
from dojo.models import (
    Engagement,
    Finding,
    FindingVulnerabilityReference,
    Product,
    Product_Type,
    Test,
    Test_Type,
    Vulnerability_Id,
    VulnerabilityId,
)
from dojo.vulnerability_id.backfill import run_backfill


@skip("Outdated - this class was testing some version of migration; it is not needed anymore")
class TestOptiEndpointStatus(MigratorTestCase):
    migrate_from = ("dojo", "0171_jira_labels_per_product_and_engagement")
    migrate_to = ("dojo", "0172_optimize_usage_of_endpoint_status")

    def prepare(self):
        Product_Type = self.old_state.apps.get_model("dojo", "Product_Type")
        Product = self.old_state.apps.get_model("dojo", "Product")
        Engagement = self.old_state.apps.get_model("dojo", "Engagement")
        Test = self.old_state.apps.get_model("dojo", "Test")
        Finding = self.old_state.apps.get_model("dojo", "Finding")
        Endpoint = self.old_state.apps.get_model("dojo", "Endpoint")
        Endpoint_Status = self.old_state.apps.get_model("dojo", "Endpoint_Status")

        self.prod_type = Product_Type.objects.create()
        self.product = Product.objects.create(prod_type=self.prod_type)
        self.engagement = Engagement.objects.create(
            product_id=self.product.pk,
            target_start=datetime.datetime(2020, 1, 1, tzinfo=timezone.utc),
            target_end=datetime.datetime(2022, 1, 1, tzinfo=timezone.utc),
        )
        self.test = Test.objects.create(
            engagement_id=self.engagement.pk,
            target_start=datetime.datetime(2020, 1, 1, tzinfo=timezone.utc),
            target_end=datetime.datetime(2022, 1, 1, tzinfo=timezone.utc),
            test_type_id=1,
        )
        user = get_user_model().objects.create().pk

        self.finding = Finding.objects.create(test_id=self.test.pk, reporter_id=user).pk
        self.endpoint = Endpoint.objects.create(host="foo.bar", product_id=self.product.pk).pk
        self.endpoint_status = Endpoint_Status.objects.create(
                finding_id=self.finding,
                endpoint_id=self.endpoint,
        ).pk
        Endpoint.objects.get(id=self.endpoint).endpoint_status.add(
            Endpoint_Status.objects.get(id=self.endpoint_status),
        )
        Finding.objects.get(id=self.finding).endpoint_status.add(
            Endpoint_Status.objects.get(id=self.endpoint_status),
        )
        Finding.objects.get(id=self.finding).endpoints.add(
            Endpoint.objects.get(id=self.endpoint).pk,
        )

        self.presudotest_before_migration()

    def case_add_status_endpoint(self, endpoint, status):
        endpoint.endpoint_status.add(status)

    def case_add_status_finding(self, finding, status):
        finding.endpoint_status.add(status)

    def case_from_finding_get_endpoints(self, finding):
        return finding.endpoints.all()

    def case_add_endpoint_finding(self, finding, endpoint):
        finding.endpoints.add(endpoint)

    def case_list_with_status_finding(self, finding):
        return finding.status_finding

    def case_list_with_status_endpoint(self, endpoint):
        return endpoint.status_endpoint

    def presudotest_before_migration(self):
        Finding = self.old_state.apps.get_model("dojo", "Finding")
        Endpoint = self.old_state.apps.get_model("dojo", "Endpoint")
        Endpoint_Status = self.old_state.apps.get_model("dojo", "Endpoint_Status")

        with self.subTest("Old: Add existing EPS to endpoint"):
            self.case_add_status_endpoint(
                Endpoint.objects.get(id=self.endpoint),
                Endpoint_Status.objects.get(id=self.endpoint_status),
            )

        with self.subTest("Old: Add existing EPS to finding"):
            self.case_add_status_finding(
                Finding.objects.get(id=self.finding),
                Endpoint_Status.objects.get(id=self.endpoint_status),
            )

        with self.subTest("Old: From finding get endpoints"):
            ep = self.case_from_finding_get_endpoints(
                Finding.objects.get(id=self.finding),
            ).all()
            self.assertEqual(ep.all().count(), 1, ep)

        with self.subTest("Old: Add existing endpoint to finding"):
            self.case_add_endpoint_finding(
                Finding.objects.get(id=self.finding),
                Endpoint.objects.get(id=self.endpoint).pk,
            )

        with self.subTest("Old: List EPS from finding"):
            eps = self.case_list_with_status_finding(
                Finding.objects.get(id=self.finding),
            )
            self.assertEqual(eps.all().count(), 1, ep)
            self.assertIsInstance(eps.all().first(), Endpoint_Status)

        with self.subTest("Old: List EPS from endpoint"):
            with self.assertRaises(AttributeError) as exc:
                eps = self.case_list_with_status_endpoint(
                    Endpoint.objects.get(id=self.endpoint),
                )
            self.assertEqual(str(exc.exception), "'Endpoint' object has no attribute 'status_endpoint'")

    def test_after_migration(self):
        Finding = self.new_state.apps.get_model("dojo", "Finding")
        Endpoint = self.new_state.apps.get_model("dojo", "Endpoint")
        Endpoint_Status = self.new_state.apps.get_model("dojo", "Endpoint_Status")

        with self.subTest("New: Add existing EPS to endpoint"):
            with self.assertRaises(AttributeError) as exc:
                self.case_add_status_endpoint(
                    Endpoint.objects.get(id=self.endpoint),
                    Endpoint_Status.objects.get(id=self.endpoint_status),
                )
            self.assertEqual(str(exc.exception), "'Endpoint' object has no attribute 'endpoint_status'")

        with self.subTest("New: Add existing EPS to finding"):
            with self.assertRaises(AttributeError) as exc:
                self.case_add_status_endpoint(
                    Finding.objects.get(id=self.finding),
                    Endpoint_Status.objects.get(id=self.endpoint_status),
                )
            self.assertEqual(str(exc.exception), "'Finding' object has no attribute 'endpoint_status'")

        with self.subTest("New: From finding get endpoints"):
            ep = self.case_from_finding_get_endpoints(
                Finding.objects.get(id=self.finding),
            ).all()
            self.assertEqual(ep.all().count(), 1, ep)

        with self.subTest("New: Add existing endpoint to finding"):
            # Yes, this method is still available. It could create Endpoint_Status with default values
            self.case_add_endpoint_finding(
                Finding.objects.get(id=self.finding),
                Endpoint.objects.get(id=self.endpoint),
            )

        with self.subTest("New: List EPS from finding"):
            eps = self.case_list_with_status_finding(
                Finding.objects.get(id=self.finding),
            )
            self.assertEqual(eps.all().count(), 1, ep)
            self.assertIsInstance(eps.all().first(), Endpoint_Status)

        with self.subTest("New: List EPS from endpoint"):
            eps = self.case_list_with_status_endpoint(
                Endpoint.objects.get(id=self.endpoint),
            )
            self.assertEqual(eps.all().count(), 1, ep)
            self.assertIsInstance(eps.all().first(), Endpoint_Status)


class TestVulnerabilityIdBackfill(TestCase):

    """
    dojo.vulnerability_id.backfill.run_backfill (the routine migration 0286 delegates to) turns
    legacy dojo_vulnerability_id rows + dojo_finding.cve into VulnerabilityId entities and ordered
    FindingVulnerabilityReference rows (order 0 == cve). Covers ordered ids, cve-drift (cve is not
    the lowest-PK row), case-variant ids (2 distinct entities), cve-only findings (no legacy rows),
    null-cve findings, and an idempotent re-run.

    A plain TestCase rather than MigratorTestCase: django_test_migrations replays the full squashed
    migration chain from a wiped schema in setUp, which is unusable in this codebase (the replay
    collides on tables such as dojo_cred_user whose model no longer matches the squash) — the very
    reason the only other MigratorTestCase here is skipped. run_backfill IS what 0286 runs, and the
    migration's application is separately covered by the create-db and dev-DB migrate runs.
    """

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        prod_type = Product_Type.objects.create(name="vulnid-pt")
        product = Product.objects.create(prod_type=prod_type, name="vulnid-prod")
        engagement = Engagement.objects.create(product=product, target_start=now, target_end=now)
        test_type = Test_Type.objects.create(name="vulnid-tt")
        test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=now,
            target_end=now,
        )
        user = get_user_model().objects.create(username="vulnid-user")

        def make_finding(title, cve):
            return Finding.objects.create(
                test=test,
                reporter=user,
                title=title,
                description=title,
                severity="High",
                numerical_severity="S0",
                active=True,
                verified=False,
                cve=cve,
            )

        def add_legacy(finding, vulnerability_id):
            # Real save() stamps vulnerability_id_type, mirroring production legacy rows.
            Vulnerability_Id.objects.create(finding=finding, vulnerability_id=vulnerability_id)

        # A: ordered ids, cve == first (lowest-PK) row.
        cls.finding_a = make_finding("A", "CVE-A1")
        for vid in ("CVE-A1", "CVE-A2", "CVE-A3"):
            add_legacy(cls.finding_a, vid)

        # B: cve-drift — rows created B1,B2,B3 (ascending PK) but cve == CVE-B2 (middle row).
        cls.finding_b = make_finding("B", "CVE-B2")
        for vid in ("CVE-B1", "CVE-B2", "CVE-B3"):
            add_legacy(cls.finding_b, vid)

        # C: case-variant ids — CVE-C1 and cve-c1 are distinct exact-cased strings => 2 entities.
        cls.finding_c = make_finding("C", "CVE-C1")
        for vid in ("CVE-C1", "cve-c1"):
            add_legacy(cls.finding_c, vid)

        # D: cve-only — cve set, NO legacy rows => step-4 order-0 ref to the cve entity.
        cls.finding_d = make_finding("D", "CVE-D1")

        # E: legacy rows but NULL cve => order by PK, no cve-only ref.
        cls.finding_e = make_finding("E", None)
        for vid in ("CVE-E1", "CVE-E2"):
            add_legacy(cls.finding_e, vid)

    def _order_map(self, finding):
        return {
            ref.order: ref.vulnerability.vulnerability_id
            for ref in FindingVulnerabilityReference.objects.filter(finding=finding)
        }

    def test_backfill(self):
        run_backfill()

        expected_entities = {
            "CVE-A1", "CVE-A2", "CVE-A3",
            "CVE-B1", "CVE-B2", "CVE-B3",
            "CVE-C1", "cve-c1",
            "CVE-D1",
            "CVE-E1", "CVE-E2",
        }

        with self.subTest("entity extraction (exact-cased, case-variant = 2 entities)"):
            self.assertEqual(
                set(VulnerabilityId.objects.values_list("vulnerability_id", flat=True)),
                expected_entities,
            )

        with self.subTest("entity type carried / stamped from prefix"):
            for entity in VulnerabilityId.objects.all():
                self.assertEqual(
                    entity.vulnerability_id_type,
                    resolve_vulnerability_id_type(entity.vulnerability_id),
                )

        with self.subTest("A: ordered ids, cve first"):
            self.assertEqual(self._order_map(self.finding_a), {0: "CVE-A1", 1: "CVE-A2", 2: "CVE-A3"})

        with self.subTest("B: cve-drift resolves cve to order 0, rest by PK asc"):
            self.assertEqual(self._order_map(self.finding_b), {0: "CVE-B2", 1: "CVE-B1", 2: "CVE-B3"})

        with self.subTest("C: case-variant ids both referenced, exact cve at order 0"):
            self.assertEqual(self._order_map(self.finding_c), {0: "CVE-C1", 1: "cve-c1"})

        with self.subTest("D: cve-only finding gets an order-0 reference"):
            self.assertEqual(self._order_map(self.finding_d), {0: "CVE-D1"})

        with self.subTest("E: null-cve finding ordered by PK, no cve-only ref"):
            self.assertEqual(self._order_map(self.finding_e), {0: "CVE-E1", 1: "CVE-E2"})

        with self.subTest("pair sets: every legacy pair is in the new store; extras are cve-only"):
            legacy_pairs = set(Vulnerability_Id.objects.values_list("finding_id", "vulnerability_id"))
            new_pairs = {
                (ref.finding_id, ref.vulnerability.vulnerability_id)
                for ref in FindingVulnerabilityReference.objects.all()
            }
            self.assertTrue(legacy_pairs.issubset(new_pairs))
            self.assertEqual(new_pairs - legacy_pairs, {(self.finding_d.id, "CVE-D1")})

        with self.subTest("idempotency: re-running the backfill changes nothing"):
            entities_before = VulnerabilityId.objects.count()
            refs_before = FindingVulnerabilityReference.objects.count()
            counts = run_backfill()
            self.assertEqual(VulnerabilityId.objects.count(), entities_before)
            self.assertEqual(FindingVulnerabilityReference.objects.count(), refs_before)
            self.assertEqual(
                counts,
                {
                    "entities_from_legacy": 0,
                    "entities_from_cve": 0,
                    "types_stamped": 0,
                    "references_from_legacy": 0,
                    "references_from_cve_only": 0,
                },
            )
