"""
Tests for host operating system data reported by scanners (issue #16281).

Parsers attach the host OS to a location via LocationAssociationData; the import pipeline stores it on the
LocationFindingReference (`relationship_data["os"]`), so it reflects what each scan reported for each finding/host.

Covers:
- Persisting host OS on new finding refs, per finding
- Reimport semantics: changed OS is updated, missing OS keeps the stored value
- The finding filters (UI helper + API) and the template match helper
"""

from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.filters import filter_location_os_base
from dojo.finding.api.filters import ApiFindingFilter
from dojo.importers.location_manager import LocationManager
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.templatetags.display_tags import host_os_matches
from dojo.tools.locations import LocationAssociationData, LocationData
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3

User = get_user_model()


def _make_test():
    now = timezone.now()
    pt, _ = Product_Type.objects.get_or_create(name="Host OS Test Type")
    product = Product.objects.create(name=f"Host OS Product {Product.objects.count()}", description="test", prod_type=pt)
    eng = Engagement.objects.create(product=product, target_start=now, target_end=now)
    tt, _ = Test_Type.objects.get_or_create(name="Host OS Test")
    return Test.objects.create(engagement=eng, test_type=tt, target_start=now, target_end=now)


def _make_finding(test, title="Host OS Finding"):
    user, _ = User.objects.get_or_create(username="host_os_test_user", defaults={"is_active": True})
    return Finding.objects.create(test=test, title=title, severity="Medium", reporter=user)


def _location(host, os_name=None):
    return LocationData.url(host=host, association=LocationAssociationData.host_os(os_name))


def _import(finding, locations):
    mgr = LocationManager(finding.test.engagement.product)
    mgr.record_locations_for_finding(finding, locations)
    mgr.persist()


def _ref_os(finding, host):
    ref = LocationFindingReference.objects.get(finding=finding, location__url__host=host)
    return ref.relationship_data.get("os")


@skip_unless_v3
class TestPersistHostOs(DojoTestCase):

    def test_host_os_stored_on_finding_ref(self):
        finding = _make_finding(_make_test())

        _import(finding, [_location("win.example.com", "Windows Server 2019"), _location("nos.example.com")])

        self.assertEqual("Windows Server 2019", _ref_os(finding, "win.example.com"))
        self.assertIsNone(_ref_os(finding, "nos.example.com"))

    def test_host_os_is_per_finding_for_shared_location(self):
        test = _make_test()
        finding1 = _make_finding(test, "Finding 1")
        finding2 = _make_finding(test, "Finding 2")

        mgr = LocationManager(test.engagement.product)
        mgr.record_locations_for_finding(finding1, [_location("shared.example.com", "Ubuntu 22.04")])
        mgr.record_locations_for_finding(finding2, [_location("shared.example.com", "Ubuntu 24.04")])
        mgr.persist()

        # One location row, but each finding keeps what was reported alongside it
        self.assertEqual("Ubuntu 22.04", _ref_os(finding1, "shared.example.com"))
        self.assertEqual("Ubuntu 24.04", _ref_os(finding2, "shared.example.com"))

    def test_reimport_updates_changed_host_os(self):
        finding = _make_finding(_make_test())
        _import(finding, [_location("host.example.com", "Ubuntu 22.04")])

        _import(finding, [_location("host.example.com", "Ubuntu 24.04")])

        self.assertEqual("Ubuntu 24.04", _ref_os(finding, "host.example.com"))
        self.assertEqual(1, LocationFindingReference.objects.filter(finding=finding).count())

    def test_reimport_without_host_os_keeps_stored_value(self):
        finding = _make_finding(_make_test())
        _import(finding, [_location("host.example.com", "Windows 11")])

        _import(finding, [_location("host.example.com")])

        self.assertEqual("Windows 11", _ref_os(finding, "host.example.com"))

    def test_reimport_merges_with_other_relationship_data(self):
        finding = _make_finding(_make_test())
        _import(finding, [LocationData.url(
            host="host.example.com",
            association=LocationAssociationData(relationship_data={"file_path": "/srv/app"}),
        )])

        _import(finding, [_location("host.example.com", "Debian 12")])

        ref = LocationFindingReference.objects.get(finding=finding)
        self.assertEqual({"file_path": "/srv/app", "os": "Debian 12"}, ref.relationship_data)

    def test_reimport_with_unchanged_host_os_does_not_update(self):
        finding = _make_finding(_make_test())
        _import(finding, [_location("host.example.com", "Windows 11")])

        with CaptureQueriesContext(connection) as ctx:
            _import(finding, [_location("host.example.com", "Windows 11")])

        ref_table = LocationFindingReference._meta.db_table
        self.assertFalse([
            q["sql"] for q in ctx.captured_queries
            if q["sql"].startswith("UPDATE") and ref_table in q["sql"]
        ])


@skip_unless_v3
class TestHostOsFilter(DojoTestCase):

    def setUp(self):
        test = _make_test()
        self.windows = _make_finding(test, "Windows only")
        self.mixed = _make_finding(test, "Windows and Linux")
        self.linux = _make_finding(test, "Linux only")
        self.unknown = _make_finding(test, "No OS")
        _import(self.windows, [_location("win1.example.com", "Microsoft Windows Server 2019")])
        _import(self.mixed, [
            _location("win1.example.com", "Microsoft Windows Server 2019"),
            _location("win2.example.com", "Windows 10"),
            _location("lin1.example.com", "Ubuntu 22.04"),
        ])
        _import(self.linux, [_location("lin1.example.com", "Ubuntu 22.04")])
        _import(self.unknown, [_location("nos.example.com")])
        self.queryset = Finding.objects.filter(test=test)

    def test_filter_matches_case_insensitive_substring(self):
        qs = filter_location_os_base(self.queryset, "location_os", "windows")

        self.assertCountEqual([self.windows, self.mixed], qs)

    def test_filter_returns_each_finding_once(self):
        # self.mixed has two Windows hosts; the Exists() subquery must not duplicate it
        qs = filter_location_os_base(self.queryset, "location_os", "windows")

        self.assertEqual(2, qs.count())

    def test_filter_combines_host_on_same_location(self):
        qs = filter_location_os_base(self.queryset, "location_os", "ubuntu", host="win1")

        self.assertCountEqual([], qs)

    def test_filter_combines_status_on_same_location(self):
        LocationFindingReference.objects.filter(
            finding=self.linux, location__url__host="lin1.example.com",
        ).update(status=FindingLocationStatus.Mitigated)

        qs = filter_location_os_base(self.queryset, "location_os", "ubuntu", statuses=[FindingLocationStatus.Active])

        self.assertCountEqual([self.mixed], qs)

    def test_api_filter(self):
        api_filter = ApiFindingFilter()

        self.assertCountEqual([self.linux, self.mixed], api_filter.filter_location_os(self.queryset, "location_os", "Ubuntu"))
        self.assertEqual(4, api_filter.filter_location_os(self.queryset, "location_os", "").count())

    def test_template_match_helper(self):
        refs = {ref.location.url.host: ref for ref in LocationFindingReference.objects.filter(finding=self.mixed)}

        self.assertTrue(host_os_matches(refs["win2.example.com"], "WINDOWS"))
        self.assertFalse(host_os_matches(refs["lin1.example.com"], "windows"))
        self.assertFalse(host_os_matches(refs["win2.example.com"], ""))
        self.assertFalse(host_os_matches(LocationFindingReference.objects.get(finding=self.unknown), "windows"))
