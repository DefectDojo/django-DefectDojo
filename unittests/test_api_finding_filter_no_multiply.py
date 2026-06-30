from django.utils.timezone import now

from dojo.filters import ApiFindingFilter, ExistsRiskAcceptanceFilter
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Risk_Acceptance,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase


class TestApiFindingFilterNoMultiply(DojoTestCase):

    """
    Regression: FindingViewSet.get_queryset() dropped the blanket DISTINCT, so every genuinely
    to-many filter on ApiFindingFilter (and ordering by a to-many field) must dedupe itself.

    Each test pins the intent two ways: the naive join the old filter relied on demonstrably
    multiplies the matching finding, while filtering/ordering through the real filterset returns
    that finding exactly once and still excludes non-matching findings.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="nm_user", is_staff=True, is_superuser=True)
        cls.reviewer1 = Dojo_User.objects.create(username="nm_reviewer1")
        cls.reviewer2 = Dojo_User.objects.create(username="nm_reviewer2")
        cls.prod_type = Product_Type.objects.create(name="NM Product Type")
        cls.product = Product.objects.create(name="NM Product", prod_type=cls.prod_type, description="NM Product")
        cls.engagement = Engagement.objects.create(
            name="NM Engagement", product=cls.product, target_start=now(), target_end=now(),
        )
        cls.test_type = Test_Type.objects.create(name="NM Test Type A")
        cls.test_type2 = Test_Type.objects.create(name="NM Test Type B")
        cls.test = Test.objects.create(
            title="NM Test", engagement=cls.engagement, test_type=cls.test_type,
            target_start=now(), target_end=now(),
        )

    def _make_finding(self, title):
        return Finding.objects.create(title=title, test=self.test, reporter=self.user, severity="High")

    def _ids(self, queryset):
        return sorted(queryset.values_list("id", flat=True))

    def test_finding_group_filter_does_not_multiply(self):
        # ?finding_group= used to duplicate findings belonging to >1 matching group: the inherited
        # NumberInFilter joined the finding_group reverse-M2M and the DISTINCT was gone.
        finding = self._make_finding("fg match")
        self._make_finding("fg decoy")  # in no group, must be excluded
        g1 = Finding_Group.objects.create(name="NM G1", test=self.test, creator=self.user)
        g2 = Finding_Group.objects.create(name="NM G2", test=self.test, creator=self.user)
        g1.findings.add(finding)
        g2.findings.add(finding)

        # The reverse-M2M join the filter must avoid genuinely multiplies the matching row.
        self.assertEqual(Finding.objects.filter(finding_group__id__in=[g1.id, g2.id]).count(), 2)

        qs = ApiFindingFilter(data={"finding_group": f"{g1.id},{g2.id}"}, queryset=Finding.objects.all()).qs
        self.assertEqual(self._ids(qs), [finding.id])

    def test_found_by_filter_does_not_multiply(self):
        # found_by is auto-seeded with the test's own test_type via signal, so filter on two *other*
        # test types to keep the decoy (which only carries the auto-seeded type) genuinely excluded.
        tt_x = Test_Type.objects.create(name="NM Found By X")
        tt_y = Test_Type.objects.create(name="NM Found By Y")
        finding = self._make_finding("fb match")
        self._make_finding("fb decoy")
        finding.found_by.add(tt_x, tt_y)

        self.assertEqual(Finding.objects.filter(found_by__in=[tt_x.id, tt_y.id]).count(), 2)

        qs = ApiFindingFilter(data={"found_by": f"{tt_x.id},{tt_y.id}"}, queryset=Finding.objects.all()).qs
        self.assertEqual(self._ids(qs), [finding.id])

    def test_reviewers_filter_does_not_multiply(self):
        finding = self._make_finding("rv match")
        self._make_finding("rv decoy")
        finding.reviewers.add(self.reviewer1, self.reviewer2)

        self.assertEqual(Finding.objects.filter(reviewers__in=[self.reviewer1.id, self.reviewer2.id]).count(), 2)

        qs = ApiFindingFilter(
            data={"reviewers": f"{self.reviewer1.id},{self.reviewer2.id}"}, queryset=Finding.objects.all(),
        ).qs
        self.assertEqual(self._ids(qs), [finding.id])

    def test_ordering_by_reviewers_does_not_multiply(self):
        # Ordering by a to-many field joins the relation and multiplies rows; MultivaluedOrderingFilter
        # aggregates with Min() so each finding still appears once after the blanket DISTINCT is gone.
        finding = self._make_finding("ord match")
        finding.reviewers.add(self.reviewer1, self.reviewer2)

        # The naive ordering join the filter must avoid emits the finding once per reviewer.
        naive = list(Finding.objects.order_by("reviewers").values_list("id", flat=True))
        self.assertEqual(naive.count(finding.id), 2)

        ordered = list(
            ApiFindingFilter(data={"o": "reviewers"}, queryset=Finding.objects.all()).qs.values_list("id", flat=True),
        )
        self.assertEqual(ordered.count(finding.id), 1)

    def test_risk_acceptance_filter_is_wired_to_exists_subclass(self):
        # The filter must be the Exists-based subclass; the plain ReportRiskAcceptanceFilter would
        # re-introduce the row-multiplying "Expired" join.
        self.assertIsInstance(ApiFindingFilter.base_filters["risk_acceptance"], ExistsRiskAcceptanceFilter)

    def test_risk_acceptance_expired_does_not_multiply(self):
        # ?risk_acceptance=3 (Expired) used to duplicate findings with >1 expired risk acceptance.
        # ExistsRiskAcceptanceFilter.filter() dispatches "Expired" to an Exists() subquery instead.
        finding = self._make_finding("ra match")
        self._make_finding("ra decoy")  # no risk acceptance, must be excluded
        ra1 = Risk_Acceptance.objects.create(name="NM RA1", owner=self.user, expiration_date_handled=now())
        ra2 = Risk_Acceptance.objects.create(name="NM RA2", owner=self.user, expiration_date_handled=now())
        ra1.accepted_findings.add(finding)
        ra2.accepted_findings.add(finding)

        # The WAS_ACCEPTED join the parent branch uses genuinely multiplies the matching row.
        self.assertEqual(
            Finding.objects.filter(
                risk_acceptance__isnull=False,
                risk_acceptance__expiration_date_handled__isnull=False,
            ).count(),
            2,
        )

        filt = ExistsRiskAcceptanceFilter()
        filt.field_name = "risk_acceptance"
        result = filt.filter(Finding.objects.all(), 3)  # 3 == "Expired"
        self.assertEqual(self._ids(result), [finding.id])
