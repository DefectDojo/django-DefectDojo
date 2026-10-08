"""
Regression test for the prefetch of a reverse one-to-many relation.

``?prefetch=<field>`` resolves the field name through ``getattr`` on a model
instance. For a reverse ForeignKey -- e.g. ``Finding.locations``, which is the
reverse side of ``LocationFindingReference.finding`` (``related_name="locations"``)
-- that attribute is a ``RelatedManager``, exactly like a many-to-many field.

The prefetcher classified only ``ManyToManyDescriptor`` fields as "many". A
reverse FK is exposed as a ``ReverseManyToOneDescriptor`` (which is *not* a
``ManyToManyDescriptor``), so it was mis-classified as a single related object
and the authorization gate then did ``authorized_qs.filter(pk=field_value.pk)``
on the ``RelatedManager``, raising
``AttributeError: 'RelatedManager' object has no attribute 'pk'`` and turning
``GET /api/v2/findings/?prefetch=locations`` into a 500.

These tests pin the corrected behaviour: a reverse one-to-many relation is
treated as "many" and prefetching it returns the related rows without raising.
"""

from types import SimpleNamespace

from crum import impersonate
from django.utils.timezone import now

from dojo.api_v2.prefetch import prefetcher as prefetcher_module
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class PrefetchReverseForeignKeyTest(DojoTestCase):

    """Prefetching ``Finding.locations`` (a reverse FK) must not raise."""

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="PrefetchRevFK PT")
        test_type, _ = Test_Type.objects.get_or_create(name="PrefetchRevFK Scan")

        cls.product = Product.objects.create(
            name="PrefetchRevFK Product",
            description="reverse fk prefetch",
            prod_type=prod_type,
        )
        engagement = Engagement.objects.create(
            name="PrefetchRevFK Engagement",
            product=cls.product,
            target_start=now(),
            target_end=now(),
        )
        cls.admin = Dojo_User.objects.get(username="admin")
        test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=now(),
            target_end=now(),
            lead=cls.admin,
        )
        cls.finding = Finding.objects.create(
            title="PrefetchRevFK Finding",
            test=test,
            reporter=cls.admin,
            severity="Info",
            numerical_severity="S4",
        )

        cls.location = Location.objects.create(
            location_type="URL",
            location_value="https://prefetch-revfk.example.com/",
        )
        LocationProductReference.objects.create(
            location=cls.location,
            product=cls.product,
            status=ProductLocationStatus.Active,
        )
        cls.reference = LocationFindingReference.objects.create(
            location=cls.location,
            finding=cls.finding,
            status=FindingLocationStatus.Active,
        )

    def test_reverse_fk_is_classified_as_many(self):
        """``Finding.locations`` is a reverse FK, so it must be treated as 'many'."""
        prefetcher = prefetcher_module._Prefetcher()
        _value, many = prefetcher.get_field_value(self.finding, "locations")
        self.assertTrue(
            many,
            "reverse one-to-many relation (Finding.locations) must be classified as 'many'",
        )

    def test_prefetch_reverse_fk_does_not_raise(self):
        """Prefetching a reverse FK must not raise AttributeError and must return the row."""
        request = SimpleNamespace(user=self.admin)
        prefetcher = prefetcher_module._Prefetcher(request=request)

        # The Location reference policies resolve the user from the thread-local
        # current user (``discard_user``), not ``request.user``, so set it here.
        with impersonate(self.admin):
            # Must not raise ``AttributeError: 'RelatedManager' object has no attribute 'pk'``.
            prefetcher._prefetch(self.finding, ["locations"])

        data = prefetcher.prefetched_data
        self.assertIn("locations", data)
        self.assertIn(
            self.reference.pk,
            data["locations"],
            "the finding's LocationFindingReference should be present in the prefetch payload",
        )
