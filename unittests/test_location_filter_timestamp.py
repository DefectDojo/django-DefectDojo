from django.utils.timezone import now, timedelta

from dojo.location.api.filters import (
    LocationFilter,
    LocationFindingReferenceFilter,
    LocationProductReferenceFilter,
)
from dojo.location.models import (
    Location,
    LocationFindingReference,
    LocationProductReference,
)
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.url.api.filters import URLFilter
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3, versioned_fixtures

HOST = "timestamp-filter.example.com"


@skip_unless_v3
@versioned_fixtures
class TestLocationFilterTimestamps(DojoTestCase):

    """
    The Location filtersets expose ``created_at``/``updated_at`` query parameters
    (range filters and ordering keys), but the underlying models store those
    timestamps in the ``created``/``updated`` fields inherited from BaseModel.

    A request such as ``GET /api/v2/location/?created_at_after=...`` therefore
    raised ``FieldError: Cannot resolve keyword 'created_at' into field`` and
    returned HTTP 500 to the customer. These tests reproduce that path against
    every affected filterset and assert the parameters resolve to the real
    model fields.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type = Product_Type.objects.create(name="Timestamp PT")
        cls.product = Product.objects.create(
            name="Timestamp Product", description="ts", prod_type=prod_type,
        )
        engagement = Engagement.objects.create(
            product=cls.product, name="ts eng",
            target_start=now().date(), target_end=now().date(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.create(name="Timestamp Scan"),
            target_start=now(), target_end=now(),
        )
        cls.finding = Finding.objects.create(
            test=test, title="Timestamp Finding", severity="High",
            numerical_severity="S1", active=True, verified=True,
        )
        cls.location = URL.get_or_create_from_values(
            protocol="https", host=HOST, path="app").location
        cls.location.associate_with_product(cls.product)
        cls.location.associate_with_finding(cls.finding, audit_time=now())

    def test_location_created_at_range_resolves_to_created_field(self):
        """`/api/v2/location/?created_at_after=...` must not raise FieldError."""
        past = (now() - timedelta(days=1)).isoformat()
        future = (now() + timedelta(days=1)).isoformat()
        matched = set(
            LocationFilter(
                {"created_at_after": past, "created_at_before": future},
                queryset=Location.objects.filter(id=self.location.id),
            ).qs.values_list("id", flat=True),
        )
        self.assertEqual(matched, {self.location.id})

        excluded = set(
            LocationFilter(
                {"created_at_before": past},
                queryset=Location.objects.filter(id=self.location.id),
            ).qs.values_list("id", flat=True),
        )
        self.assertEqual(excluded, set())

    def test_location_updated_at_range_resolves_to_updated_field(self):
        future = (now() + timedelta(days=1)).isoformat()
        past = (now() - timedelta(days=1)).isoformat()
        matched = set(
            LocationFilter(
                {"updated_at_after": past, "updated_at_before": future},
                queryset=Location.objects.filter(id=self.location.id),
            ).qs.values_list("id", flat=True),
        )
        self.assertEqual(matched, {self.location.id})

    def test_location_ordering_by_timestamps_does_not_raise(self):
        for ordering in ("created_at", "-created_at", "updated_at", "-updated_at"):
            ids = list(
                LocationFilter(
                    {"ordering": ordering},
                    queryset=Location.objects.filter(id=self.location.id),
                ).qs.values_list("id", flat=True),
            )
            self.assertEqual(ids, [self.location.id])

    def test_location_findings_created_at_range_resolves(self):
        """`/api/v2/location_findings/?created_at_after=...` must not raise."""
        past = (now() - timedelta(days=1)).isoformat()
        future = (now() + timedelta(days=1)).isoformat()
        qs = LocationFindingReference.objects.filter(location=self.location)
        matched = set(
            LocationFindingReferenceFilter(
                {"created_at_after": past, "created_at_before": future},
                queryset=qs,
            ).qs.values_list("id", flat=True),
        )
        self.assertEqual(matched, set(qs.values_list("id", flat=True)))
        self.assertTrue(matched)

    def test_location_findings_ordering_by_timestamps_does_not_raise(self):
        qs = LocationFindingReference.objects.filter(location=self.location)
        for ordering in ("created_at", "-updated_at"):
            evaluated = list(
                LocationFindingReferenceFilter({"ordering": ordering}, queryset=qs).qs,
            )
            self.assertEqual(len(evaluated), qs.count())

    def test_location_products_created_at_range_resolves(self):
        past = (now() - timedelta(days=1)).isoformat()
        future = (now() + timedelta(days=1)).isoformat()
        qs = LocationProductReference.objects.filter(location=self.location)
        matched = set(
            LocationProductReferenceFilter(
                {"created_at_after": past, "created_at_before": future},
                queryset=qs,
            ).qs.values_list("id", flat=True),
        )
        self.assertEqual(matched, set(qs.values_list("id", flat=True)))
        self.assertTrue(matched)

    def test_location_products_ordering_by_timestamps_does_not_raise(self):
        qs = LocationProductReference.objects.filter(location=self.location)
        for ordering in ("updated_at", "-created_at"):
            evaluated = list(
                LocationProductReferenceFilter({"ordering": ordering}, queryset=qs).qs,
            )
            self.assertEqual(len(evaluated), qs.count())

    def test_url_location_timestamp_char_filters_do_not_raise(self):
        """`/api/v2/url/` inherits location__created_at/location__updated_at char filters."""
        qs = URL.objects.filter(host=HOST)
        for param in ("location__created_at_contains", "location__updated_at_contains"):
            evaluated = list(URLFilter({param: str(now().year)}, queryset=qs).qs)
            self.assertEqual(len(evaluated), 1)
