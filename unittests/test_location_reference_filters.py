"""
Regression tests for the location-reference API filters.

``LocationFindingReferenceFilter`` and ``LocationProductReferenceFilter`` back the
``/api/v2/location_findings/`` and ``/api/v2/location_products/`` endpoints. Both
declared ``location_type`` and ``location_value`` as if they were direct fields on
the reference (through) model, but those columns live on the related ``Location``
model. Any request that used one of these filters (e.g.
``?location_type_contains=url``) or ordered by them raised::

    django.core.exceptions.FieldError: Cannot resolve keyword 'location_type' into
    field. Choices are: audit_time, auditor, ..., location, location_id, ...

which surfaced as a 500 from the endpoint. The public query-parameter names must be
preserved (existing clients and the UI use ``location_type_*`` / ``location_value_*``)
while resolving to the ``location__location_type`` / ``location__location_value`` path.
"""

from django.utils.timezone import now

from dojo.location.api.filters import LocationFindingReferenceFilter, LocationProductReferenceFilter
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type, User
from unittests.dojo_test_case import DojoTestCase


class TestLocationReferenceFilterFieldResolution(DojoTestCase):

    """Filtering / ordering by location_type and location_value must not raise FieldError."""

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="LocRefFilter PT")
        test_type, _ = Test_Type.objects.get_or_create(name="LocRefFilter Scan")
        cls.product = Product.objects.create(
            name="LocRefFilter Product",
            description="p",
            prod_type=prod_type,
        )
        engagement = Engagement.objects.create(
            name="LocRefFilter Engagement",
            product=cls.product,
            target_start=now(),
            target_end=now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            title="LocRefFilter Test",
            target_start=now(),
            target_end=now(),
        )
        cls.finding = Finding.objects.create(
            test=test,
            title="LocRefFilter Finding",
            description="f",
            severity="High",
            numerical_severity="S0",
            active=True,
            verified=True,
            reporter=User.objects.get(username="admin"),
        )

        cls.url_location = Location.objects.create(
            location_type="URL",
            location_value="https://vuln.example.com/login",
        )
        cls.other_location = Location.objects.create(
            location_type="FilePath",
            location_value="src/app/main.py",
        )
        LocationProductReference.objects.create(
            location=cls.url_location,
            product=cls.product,
            status=ProductLocationStatus.Active,
        )
        LocationProductReference.objects.create(
            location=cls.other_location,
            product=cls.product,
            status=ProductLocationStatus.Active,
        )
        cls.url_finding_ref = LocationFindingReference.objects.create(
            location=cls.url_location,
            finding=cls.finding,
            status=FindingLocationStatus.Active,
        )
        cls.other_finding_ref = LocationFindingReference.objects.create(
            location=cls.other_location,
            finding=cls.finding,
            status=FindingLocationStatus.Active,
        )

    # --- LocationFindingReferenceFilter (backs /api/v2/location_findings/) ---

    def test_finding_ref_location_type_contains_matches(self):
        """This is the exact customer-reported query: location_type_contains=url."""
        result = LocationFindingReferenceFilter(
            {"location_type_contains": "url"},
            queryset=LocationFindingReference.objects.all(),
        )
        self.assertTrue(result.is_valid())
        ids = {ref.id for ref in result.qs}
        self.assertIn(self.url_finding_ref.id, ids)
        self.assertNotIn(self.other_finding_ref.id, ids)

    def test_finding_ref_location_value_contains_matches(self):
        result = LocationFindingReferenceFilter(
            {"location_value_contains": "vuln.example.com"},
            queryset=LocationFindingReference.objects.all(),
        )
        self.assertTrue(result.is_valid())
        ids = {ref.id for ref in result.qs}
        self.assertEqual(ids, {self.url_finding_ref.id})

    def test_finding_ref_location_type_no_match_returns_empty(self):
        """Zero-match edge case: a type nothing uses filters everything out (no error)."""
        result = LocationFindingReferenceFilter(
            {"location_type_contains": "does-not-exist"},
            queryset=LocationFindingReference.objects.all(),
        )
        self.assertTrue(result.is_valid())
        self.assertEqual(list(result.qs), [])

    def test_finding_ref_ordering_by_location_type(self):
        result = LocationFindingReferenceFilter(
            {"ordering": "location_type"},
            queryset=LocationFindingReference.objects.all(),
        )
        self.assertTrue(result.is_valid())
        # Materialize: ordering by a bad field path raises FieldError here.
        self.assertEqual(len(list(result.qs)), 2)

    # --- LocationProductReferenceFilter (backs /api/v2/location_products/) ---

    def test_product_ref_location_type_contains_matches(self):
        result = LocationProductReferenceFilter(
            {"location_type_contains": "url"},
            queryset=LocationProductReference.objects.all(),
        )
        self.assertTrue(result.is_valid())
        location_ids = {ref.location_id for ref in result.qs}
        self.assertIn(self.url_location.id, location_ids)
        self.assertNotIn(self.other_location.id, location_ids)

    def test_product_ref_ordering_by_location_value(self):
        result = LocationProductReferenceFilter(
            {"ordering": "location_value"},
            queryset=LocationProductReference.objects.all(),
        )
        self.assertTrue(result.is_valid())
        self.assertEqual(len(list(result.qs)), 2)
