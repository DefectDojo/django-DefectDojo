from crum import impersonate
from django.utils.timezone import now

from dojo.authorization.roles_permissions import Permissions, Roles
from dojo.finding.queries import get_authorized_findings
from dojo.location.models import Location
from dojo.location.status import FindingLocationStatus
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
from dojo.reports.queries import prefetch_related_endpoints_for_report
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3, versioned_fixtures


@skip_unless_v3
@versioned_fixtures
class TestReportLocationFindingScoping(DojoTestCase):

    """
    Two products sharing one deduplicated Location. Findings rendered into a report
    must still be limited to the caller's own products.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="RptScope PT")
        test_type, _ = Test_Type.objects.get_or_create(name="RptScope Scan")
        reader = Role.objects.get(id=Roles.Reader)

        def build(name, finding_title):
            product = Product.objects.create(name=name, description=name, prod_type=prod_type)
            engagement = Engagement.objects.create(
                product=product, name=f"{name} eng",
                target_start=now().date(), target_end=now().date(),
            )
            test = Test.objects.create(
                engagement=engagement, test_type=test_type,
                target_start=now(), target_end=now(),
            )
            finding = Finding.objects.create(
                test=test, title=finding_title, severity="High", numerical_severity="S1",
                active=True, verified=True, description=f"body of {finding_title}",
            )
            return product, finding

        cls.product_a, cls.finding_a = build("RptScope Product A", "Finding A")
        cls.product_b, cls.finding_b = build("RptScope Product B", "Finding B")

        cls.alice = User.objects.create_user(
            username="rptscope_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        # Legacy authorization reads authorized_users, the role model reads Product_Member.
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))
        Product_Member.objects.create(product=cls.product_a, user=cls.alice, role=reader)

        # One URL referenced by both products dedupes to a single Location row.
        url = URL.get_or_create_from_values(protocol="https", host="shared.example.com", path="login")
        cls.shared = url.location
        cls.shared.associate_with_finding(cls.finding_a, audit_time=now())
        cls.shared.associate_with_product(cls.product_a)
        cls.shared.associate_with_finding(cls.finding_b, audit_time=now())
        cls.shared.associate_with_product(cls.product_b)

    def _findings_in_report_for(self, user):
        """Findings the report widget would render for this user, via the real prefetch."""
        locations = Location.objects.filter(
            id=self.shared.id, findings__status=FindingLocationStatus.Active,
        ).distinct()
        return [
            finding
            for location in prefetch_related_endpoints_for_report(locations, user=user)
            for finding in location.active_annotated_findings
        ]

    def test_shared_location_is_a_single_row(self):
        """The premise: both products reference one deduplicated Location."""
        related = {p.name for p in self.shared.all_related_products()}
        self.assertIn(self.product_a.name, related)
        self.assertIn(self.product_b.name, related)

    def test_reader_does_not_receive_another_products_finding(self):
        with impersonate(self.alice):
            titles = {f.title for f in self._findings_in_report_for(self.alice)}
        self.assertEqual(
            titles, {"Finding A"},
            "report rendered findings outside the user's products",
        )

    def test_report_matches_direct_finding_authorization(self):
        """The report must not show anything get_authorized_findings would deny."""
        with impersonate(self.alice):
            allowed = set(
                get_authorized_findings(Permissions.Finding_View, user=self.alice)
                .values_list("id", flat=True),
            )
            rendered = {f.id for f in self._findings_in_report_for(self.alice)}
        self.assertEqual(
            rendered - allowed, set(),
            "report rendered findings the user is not authorized to see",
        )

    def test_superuser_still_sees_both(self):
        """The scoping must not break the legitimate case."""
        admin = User.objects.filter(is_superuser=True).first()
        with impersonate(admin):
            titles = {f.title for f in self._findings_in_report_for(admin)}
        self.assertEqual(titles, {"Finding A", "Finding B"})
