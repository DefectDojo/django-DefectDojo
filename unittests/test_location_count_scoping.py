from crum import impersonate
from django.utils.timezone import now
from rest_framework.test import APIRequestFactory

from dojo.authorization.roles_permissions import Roles
from dojo.location.api.endpoint_compat import V3EndpointCompatibleViewSet
from dojo.location.models import Location
from dojo.location.queries import annotate_location_counts_and_status, prefetch_for_locations
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Role,
    Test,
    Test_Type,
    User,
)
from dojo.url.models import URL
from dojo.url.queries import annotate_host_contents
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3, versioned_fixtures

SHARED_HOST = "counts-shared.example.com"
OWN_HOST = "counts-own.example.com"


@skip_unless_v3
@versioned_fixtures
class TestLocationCountScoping(DojoTestCase):

    """
    Two products sharing one deduplicated Location. The counts annotated onto the
    rows must describe only the caller's own products, like the rows themselves do.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="CountScope PT")
        test_type, _ = Test_Type.objects.get_or_create(name="CountScope Scan")
        reader = Role.objects.get(id=Roles.Reader)

        def build(name, *finding_titles):
            product = Product.objects.create(name=name, description=name, prod_type=prod_type)
            engagement = Engagement.objects.create(
                product=product, name=f"{name} eng",
                target_start=now().date(), target_end=now().date(),
            )
            test = Test.objects.create(
                engagement=engagement, test_type=test_type,
                target_start=now(), target_end=now(),
            )
            findings = [
                Finding.objects.create(
                    test=test, title=title, severity="High", numerical_severity="S1",
                    active=True, verified=True,
                )
                for title in finding_titles
            ]
            return product, findings

        cls.product_a, (finding_a, control_a) = build(
            "CountScope Product A", "CountScope A Shared", "CountScope A Own")
        cls.product_b, findings_b = build(
            "CountScope Product B", "CountScope B One", "CountScope B Two")

        cls.alice = User.objects.create_user(
            username="countscope_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        # Legacy authorization reads authorized_users, the role model reads Product_Member.
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))
        Product_Member.objects.create(product=cls.product_a, user=cls.alice, role=reader)

        # One URL referenced by both products dedupes to a single Location row.
        cls.shared = URL.get_or_create_from_values(
            protocol="https", host=SHARED_HOST, path="app").location
        for finding in [finding_a, *findings_b]:
            cls.shared.associate_with_finding(finding, audit_time=now())

        # Control: a Location only product A references, so its counts must not move.
        cls.own = URL.get_or_create_from_values(
            protocol="https", host=OWN_HOST, path="x").location
        cls.own.associate_with_finding(control_a, audit_time=now())

        cls.admin = User.objects.filter(is_superuser=True).first()

    def _rows(self, annotate, user):
        locations = Location.objects.filter(id__in=[self.shared.id, self.own.id])
        with impersonate(user):
            return {row.id: row for row in annotate(locations, user=user)}

    def test_shared_location_is_a_single_row(self):
        """The premise: both products reference one deduplicated Location."""
        self.assertEqual(Location.objects.filter(url__host=SHARED_HOST).count(), 1)
        related = {p.name for p in self.shared.all_related_products()}
        self.assertEqual(related, {self.product_a.name, self.product_b.name})

    def test_location_counts_exclude_other_products(self):
        rows = self._rows(annotate_location_counts_and_status, self.alice)
        shared = rows[self.shared.id]
        self.assertEqual(
            (shared.total_findings, shared.active_findings), (1, 1),
            "finding counts on a shared location included another product's findings",
        )
        self.assertEqual(
            (shared.total_products, shared.active_products), (1, 1),
            "product counts on a shared location included another product",
        )

    def test_location_counts_unaffected_for_an_unshared_location(self):
        rows = self._rows(annotate_location_counts_and_status, self.alice)
        own = rows[self.own.id]
        self.assertEqual((own.total_findings, own.active_findings), (1, 1))
        self.assertEqual((own.total_products, own.active_products), (1, 1))

    def test_location_counts_still_complete_for_a_superuser(self):
        shared = self._rows(annotate_location_counts_and_status, self.admin)[self.shared.id]
        self.assertEqual((shared.total_findings, shared.active_findings), (3, 3))
        self.assertEqual((shared.total_products, shared.active_products), (2, 2))

    def test_host_counts_exclude_other_products(self):
        shared = self._rows(annotate_host_contents, self.alice)[self.shared.id]
        self.assertEqual((shared.total_findings, shared.active_findings), (1, 1))
        self.assertEqual((shared.total_products, shared.active_products), (1, 1))

    def test_host_counts_still_complete_for_a_superuser(self):
        shared = self._rows(annotate_host_contents, self.admin)[self.shared.id]
        self.assertEqual((shared.total_findings, shared.active_findings), (3, 3))
        self.assertEqual((shared.total_products, shared.active_products), (2, 2))

    def test_search_prefetch_counts_exclude_other_products(self):
        rows = self._rows(prefetch_for_locations, self.alice)
        self.assertEqual(rows[self.shared.id].active_finding_count, 1)
        self.assertEqual(rows[self.own.id].active_finding_count, 1)

    def _endpoint_api_counts(self, user):
        view = V3EndpointCompatibleViewSet()
        view.request = APIRequestFactory().get("/api/v2/endpoints/")
        view.request.user = user
        with impersonate(user):
            return {
                row.location_id: row.active_finding_count
                for row in view.get_queryset().filter(
                    location__in=[self.shared.id, self.own.id],
                )
            }

    def test_endpoint_api_count_excludes_other_products(self):
        counts = self._endpoint_api_counts(self.alice)
        self.assertEqual(counts[self.shared.id], 1)
        self.assertEqual(counts[self.own.id], 1)

    def test_endpoint_api_count_still_complete_for_a_superuser(self):
        self.assertEqual(self._endpoint_api_counts(self.admin)[self.shared.id], 3)
