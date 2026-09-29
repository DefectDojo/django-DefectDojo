"""
The locations/endpoints ingredient of hash_code must be order-independent.

Two properties are pinned here, for both the locations (V3) and the endpoints (legacy) hash
ingredient:

1. A finding's hash_code does not depend on the order in which the scanner reported its
   locations. Scanners frequently report them from a set, so the order is not meaningful and can
   differ between two imports of the same report.
2. The hash_code stored at import time is the hash_code a recomputation produces after the finding
   was saved. The stored value comes from Finding.get_locations()'s unsaved branch and a
   recomputation (`manage.py dedupe`, reimport, false positive history) uses its saved branch, so
   the two branches have to agree - on ordering, and on the canonical form of each location.
"""

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.tools.locations import LocationData

from .dojo_test_case import DojoTestCase

User = get_user_model()

# "Qualys Scan" hashes ["title", "severity", "endpoints"] and allows a null cwe, so the reported
# locations really are part of the hash_code for this scan type.
SCAN_TYPE = "Qualys Scan"

# deliberately not in sorted order
URLS = [
    "https://zulu.example.com/three",
    "https://alpha.example.com/one",
    "https://mike.example.com/two",
]


class HashCodeLocationOrderingMixin:

    """Assertions shared by the locations (V3) and endpoints (legacy) variants."""

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="hash code ordering")
        self.product, _ = Product.objects.get_or_create(
            name="hash code ordering product", description="test", prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="hash code ordering engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        # a test is needed even for the findings that are never saved: the hash_code fields are
        # resolved from its test type
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=test_type,
            scan_type=SCAN_TYPE,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def import_finding(self, finding):
        """Import a single parsed finding the way a scan import does, and return it saved."""
        importer = DefaultImporter(
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            minimum_severity="Info",
            active=True,
            verified=True,
            sync=True,
            scan_type=SCAN_TYPE,
            engagement=self.engagement,
        )
        importer.create_test(SCAN_TYPE)
        imported = importer.process_findings([finding])
        self.assertEqual(1, len(imported))
        return imported[0]

    def parsed_finding(self, urls, *, title="Insecure thing"):
        finding = Finding(title=title, severity="High", description="whatever", dynamic_finding=True, test=self.test)
        self.attach_locations(finding, urls)
        return finding

    def test_hash_code_is_independent_of_the_reported_order(self):
        """The same locations in a different order must produce the same hash_code."""
        first = self.parsed_finding(URLS).compute_hash_code()
        second = self.parsed_finding(list(reversed(URLS))).compute_hash_code()
        self.assertEqual(first, second)

    def test_hash_code_uses_every_reported_location(self):
        """Guard against the assertion above passing because the locations are ignored entirely."""
        with_locations = self.parsed_finding(URLS).compute_hash_code()
        without_one = self.parsed_finding(URLS[:-1]).compute_hash_code()
        self.assertNotEqual(with_locations, without_one)

    def test_stored_hash_code_survives_recomputation(self):
        """The hash stored on import must equal the hash recomputed from the saved finding."""
        finding = self.import_finding(self.parsed_finding(URLS))
        finding.refresh_from_db()
        self.assertEqual(finding.hash_code, finding.compute_hash_code())

    def test_stored_hash_code_survives_recomputation_for_non_canonical_locations(self):
        """
        Same, for locations a parser did not hand over in canonical form.

        Cleaning rewrites the canonical string form of a location, so a hash taken before cleaning
        does not match the one taken after the cleaned location was saved.
        """
        finding = self.import_finding(self.parsed_finding_with_non_canonical_locations())
        finding.refresh_from_db()
        self.assertEqual(finding.hash_code, finding.compute_hash_code())

    def test_stored_hash_code_is_independent_of_the_reported_order(self):
        """End to end: two imports of the same locations in different orders store the same hash."""
        first = self.import_finding(self.parsed_finding(URLS))
        second = self.import_finding(self.parsed_finding(list(reversed(URLS))))
        self.assertEqual(first.hash_code, second.hash_code)


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestHashCodeLocationOrdering(HashCodeLocationOrderingMixin, DojoTestCase):

    """The locations hash ingredient (V3_FEATURE_LOCATIONS=True)."""

    def attach_locations(self, finding, urls):
        finding.unsaved_locations = [LocationData.url(url=url) for url in urls]

    def parsed_finding_with_non_canonical_locations(self):
        finding = Finding(title="Non canonical", severity="High", description="whatever", dynamic_finding=True)
        # URL.clean() lowercases the protocol and the host
        finding.unsaved_locations = [
            LocationData.url(url="HTTPS://ZULU.example.com/three"),
            LocationData.url(url="HTTPS://ALPHA.example.com/one"),
        ]
        return finding


@override_settings(V3_FEATURE_LOCATIONS=False)
class TestHashCodeEndpointOrdering(HashCodeLocationOrderingMixin, DojoTestCase):

    """The endpoints hash ingredient (legacy, V3_FEATURE_LOCATIONS=False)."""

    def attach_locations(self, finding, urls):
        from dojo.endpoint.models import Endpoint  # noqa: PLC0415 -- import guarded by V3_FEATURE_LOCATIONS

        finding.unsaved_endpoints = [Endpoint.from_uri(url) for url in urls]

    def parsed_finding_with_non_canonical_locations(self):
        from dojo.endpoint.models import Endpoint  # noqa: PLC0415 -- import guarded by V3_FEATURE_LOCATIONS

        finding = Finding(title="Non canonical", severity="High", description="whatever", dynamic_finding=True)
        # Endpoint.clean() strips the leading "/" from the path and the leading "?" from the query
        finding.unsaved_endpoints = [
            Endpoint(protocol="https", host="zulu.example.com", path="/three", query="?b=2"),
            Endpoint(protocol="https", host="alpha.example.com", path="/one", query="?a=1"),
        ]
        return finding
