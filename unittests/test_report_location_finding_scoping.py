from crum import impersonate
from django.utils.timezone import now

from dojo.authorization.roles_permissions import Permissions, Roles
from dojo.finding.queries import get_authorized_findings
from dojo.location.models import Location
from dojo.location.status import FindingLocationStatus
from dojo.models import (
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
    `prefetch_related_endpoints_for_report` attached findings to each Location from
    the whole LocationFindingReference table. A Location is deduplicated across
    products, so its own authorization check passes for any associated product the
    user can see -- which meant a member of product A received the full body of
    product B's findings in a rendered report, for every URL the two products
    happened to share.

    The prefetched references must be reduced to the requesting user's authorized
    findings, matching what the direct finding routes enforce.
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
        assert {self.product_a.name, self.product_b.name} <= {
            p.name for p in self.shared.all_related_products()
        }

    def test_reader_does_not_receive_another_products_finding(self):
        with impersonate(self.alice):
            titles = {f.title for f in self._findings_in_report_for(self.alice)}
        assert titles == {"Finding A"}, (
            f"report leaked findings outside the user's products: {titles}"
        )

    def test_report_matches_direct_finding_authorization(self):
        """The report must not show anything get_authorized_findings would deny."""
        with impersonate(self.alice):
            allowed = set(
                get_authorized_findings(Permissions.Finding_View, user=self.alice)
                .values_list("id", flat=True),
            )
            rendered = {f.id for f in self._findings_in_report_for(self.alice)}
        assert rendered <= allowed, f"unauthorized findings in report: {rendered - allowed}"

    def test_superuser_still_sees_both(self):
        """The scoping must not break the legitimate case."""
        admin = User.objects.filter(is_superuser=True).first()
        with impersonate(admin):
            titles = {f.title for f in self._findings_in_report_for(admin)}
        assert titles == {"Finding A", "Finding B"}
