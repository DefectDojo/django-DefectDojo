
from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase

from dojo.product_announcements import (
    ErrorPageProductAnnouncement,
    LargeScanSizeProductAnnouncement,
    LongRunningRequestProductAnnouncement,
    ScanTypeProductAnnouncement,
)


class _SessionDict(dict):

    """Minimal session stand-in that supports .get/.pop/[] like Django sessions."""


def _make_request():
    request = HttpRequest()
    request.session = _SessionDict()
    return request


def _make_response(data=None):
    response = HttpResponse()
    response.data = data if data is not None else {}
    return response


class TestProductAnnouncementSessionBanner(SimpleTestCase):

    def test_stores_banner_in_session(self):
        request = _make_request()
        ErrorPageProductAnnouncement(request=request)
        banners = request.session["_product_banners"]
        self.assertEqual(len(banners), 1)
        self.assertEqual(banners[0]["source"], "product_announcement")
        self.assertEqual(banners[0]["style"], "info")
        self.assertIn("Pro comes with support.", banners[0]["message"])
        self.assertIsNone(banners[0]["expanded_html"])

    def test_multiple_announcements_accumulate_in_session(self):
        request = _make_request()
        ErrorPageProductAnnouncement(request=request)
        ErrorPageProductAnnouncement(request=request)
        banners = request.session["_product_banners"]
        self.assertEqual(len(banners), 2)

    def test_banner_message_contains_outreach_link(self):
        request = _make_request()
        ErrorPageProductAnnouncement(request=request)
        message = request.session["_product_banners"][0]["message"]
        self.assertIn("cloud.defectdojo.com", message)
        self.assertIn("Try today for free", message)

    def test_session_error_is_swallowed(self):
        request = HttpRequest()
        request.session = None
        ErrorPageProductAnnouncement(request=request)

    def test_no_settings_guard(self):
        """Product announcements fire without any settings check."""
        request = _make_request()
        ErrorPageProductAnnouncement(request=request)
        self.assertEqual(len(request.session["_product_banners"]), 1)


class TestProductAnnouncementApiPath(SimpleTestCase):

    def test_api_response_gets_pro_key(self):
        response = _make_response(data={})
        ErrorPageProductAnnouncement(response=response)
        self.assertIn("pro", response.data)
        self.assertEqual(len(response.data["pro"]), 1)
        self.assertIn("Pro comes with support.", str(response.data["pro"][0]))

    def test_api_response_appends_to_existing_pro_list(self):
        response = _make_response(data={"pro": ["existing"]})
        ErrorPageProductAnnouncement(response=response)
        self.assertEqual(len(response.data["pro"]), 2)
        self.assertEqual(response.data["pro"][0], "existing")

    def test_api_response_data_dict_gets_pro_key(self):
        data = {}
        LargeScanSizeProductAnnouncement(response_data=data, duration=120.0)
        self.assertIn("pro", data)

    def test_requires_at_least_one_target(self):
        with self.assertRaises(ValueError):
            ErrorPageProductAnnouncement()


class TestErrorPageProductAnnouncement(SimpleTestCase):

    def test_message_content(self):
        request = _make_request()
        ErrorPageProductAnnouncement(request=request)
        message = request.session["_product_banners"][0]["message"]
        self.assertIn("Pro comes with support.", message)

    def test_api_path(self):
        response = _make_response()
        ErrorPageProductAnnouncement(response=response)
        self.assertIn("Pro comes with support.", str(response.data["pro"][0]))


class TestLargeScanSizeProductAnnouncement(SimpleTestCase):

    def test_fires_when_duration_exceeds_threshold(self):
        request = _make_request()
        LargeScanSizeProductAnnouncement(request=request, duration=120.0)
        banners = request.session["_product_banners"]
        self.assertEqual(len(banners), 1)
        self.assertIn("import took about 2 minute(s)", banners[0]["message"])
        self.assertIn("async imports", banners[0]["message"])

    def test_does_not_fire_when_duration_below_threshold(self):
        request = _make_request()
        LargeScanSizeProductAnnouncement(request=request, duration=30.0)
        self.assertEqual(len(request.session.get("_product_banners", [])), 0)

    def test_fires_at_boundary(self):
        request = _make_request()
        LargeScanSizeProductAnnouncement(request=request, duration=60.1)
        self.assertEqual(len(request.session["_product_banners"]), 1)

    def test_does_not_fire_at_exact_threshold(self):
        request = _make_request()
        LargeScanSizeProductAnnouncement(request=request, duration=60.0)
        self.assertEqual(len(request.session.get("_product_banners", [])), 0)


class TestLongRunningRequestProductAnnouncement(SimpleTestCase):

    def test_fires_when_duration_exceeds_threshold(self):
        request = _make_request()
        LongRunningRequestProductAnnouncement(request=request, duration=20.0)
        banners = request.session["_product_banners"]
        self.assertEqual(len(banners), 1)
        self.assertIn("performance tested", banners[0]["message"])

    def test_does_not_fire_when_duration_below_threshold(self):
        request = _make_request()
        LongRunningRequestProductAnnouncement(request=request, duration=10.0)
        self.assertEqual(len(request.session.get("_product_banners", [])), 0)

    def test_does_not_fire_at_exact_threshold(self):
        request = _make_request()
        LongRunningRequestProductAnnouncement(request=request, duration=15.0)
        self.assertEqual(len(request.session.get("_product_banners", [])), 0)


class TestScanTypeProductAnnouncement(SimpleTestCase):

    def test_fires_for_supported_scan_type(self):
        request = _make_request()
        ScanTypeProductAnnouncement(request=request, scan_type="Snyk Scan")
        banners = request.session["_product_banners"]
        self.assertEqual(len(banners), 1)
        self.assertIn("Snyk Scan", banners[0]["message"])
        self.assertIn("no-code connector", banners[0]["message"])

    def test_does_not_fire_for_unsupported_scan_type(self):
        request = _make_request()
        ScanTypeProductAnnouncement(request=request, scan_type="Unknown Scanner")
        self.assertEqual(len(request.session.get("_product_banners", [])), 0)

    def test_does_not_fire_for_none_scan_type(self):
        request = _make_request()
        ScanTypeProductAnnouncement(request=request, scan_type=None)
        self.assertEqual(len(request.session.get("_product_banners", [])), 0)

    def test_all_supported_scan_types_fire(self):
        for scan_type in ScanTypeProductAnnouncement.supported_scan_types:
            request = _make_request()
            ScanTypeProductAnnouncement(request=request, scan_type=scan_type)
            self.assertEqual(
                len(request.session["_product_banners"]), 1,
                f"Expected banner for {scan_type}",
            )

    def test_api_path_for_supported_scan_type(self):
        data = {}
        ScanTypeProductAnnouncement(response_data=data, scan_type="Wiz Scan")
        self.assertIn("pro", data)
        self.assertIn("Wiz Scan", str(data["pro"][0]))


class TestBannerDictSchema(SimpleTestCase):

    """Verify every banner stored in the session has the expected keys."""

    EXPECTED_KEYS = {"source", "message", "style", "url", "link_text", "expanded_html"}

    def test_error_page_banner_has_all_keys(self):
        request = _make_request()
        ErrorPageProductAnnouncement(request=request)
        self.assertEqual(set(request.session["_product_banners"][0].keys()), self.EXPECTED_KEYS)

    def test_large_scan_banner_has_all_keys(self):
        request = _make_request()
        LargeScanSizeProductAnnouncement(request=request, duration=120.0)
        self.assertEqual(set(request.session["_product_banners"][0].keys()), self.EXPECTED_KEYS)

    def test_long_running_banner_has_all_keys(self):
        request = _make_request()
        LongRunningRequestProductAnnouncement(request=request, duration=20.0)
        self.assertEqual(set(request.session["_product_banners"][0].keys()), self.EXPECTED_KEYS)

    def test_scan_type_banner_has_all_keys(self):
        request = _make_request()
        ScanTypeProductAnnouncement(request=request, scan_type="Snyk Scan")
        self.assertEqual(set(request.session["_product_banners"][0].keys()), self.EXPECTED_KEYS)
