import base64

from django.utils import timezone
from parameterized import parameterized

from dojo.importers.default_importer import DefaultImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    User,
)

from .dojo_test_case import DojoTestCase


class TestImportersRequestResponseNone(DojoTestCase):

    """
    Regression: a dynamic-scan request/response pair with a missing (None) request or
    response crashed the whole import.

    A parser emits each request/response pair as {"req": ..., "resp": ...}. When a finding
    has an unequal number of requests and responses -- a request that drew no response, for
    instance -- the parser fills the gap with None (see dojo/tools/burp_suite_dast/parser.py).
    process_request_response_pairs() then called None.encode("utf-8") and died with
    "AttributeError: 'NoneType' object has no attribute 'encode'", which failed the whole
    async import task, not just the one pair. Reported from production on a Burp Suite DAST
    import.

    The sink (process_request_response_pairs) is tested directly rather than through a full
    scan import because it is the common point every dynamic parser feeds, and it is where
    the crash was raised.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product_type, _ = Product_Type.objects.get_or_create(name="request_response_none")
        self.product, _ = Product.objects.get_or_create(
            name="TestImportersRequestResponseNone",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Request Response None",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _importer(self):
        return DefaultImporter(
            close_old_findings=False,
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            active=True,
            verified=False,
            scan_type="Burp Suite DAST Scan",
            engagement=self.engagement,
        )

    @parameterized.expand([
        ("response_missing", "GET / HTTP/1.1", None),
        ("request_missing", None, "HTTP/1.1 200 OK"),
        ("both_missing", None, None),
        ("both_present", "GET / HTTP/1.1", "HTTP/1.1 200 OK"),
    ])
    def test_request_response_pair_with_missing_side_is_stored_not_crashed(self, label, req, resp):
        """A None request or response must be stored as empty base64, never raise AttributeError."""
        importer = self._importer()
        finding = Finding()
        finding.unsaved_req_resp = [{"req": req, "resp": resp}]

        # Before the fix this raised AttributeError on the None side.
        importer.process_request_response_pairs(finding)

        self.assertEqual(
            1, len(importer.pending_burp_rr),
            msg=f"expected exactly one buffered pair, got {len(importer.pending_burp_rr)}",
        )
        stored = importer.pending_burp_rr[0]
        self.assertEqual(
            base64.b64encode((req or "").encode("utf-8")),
            stored.burpRequestBase64,
            msg=f"request base64 mismatch for req={req!r}",
        )
        self.assertEqual(
            base64.b64encode((resp or "").encode("utf-8")),
            stored.burpResponseBase64,
            msg=f"response base64 mismatch for resp={resp!r}",
        )

    def test_mixed_pairs_all_stored(self):
        """A finding carrying several pairs, some with a missing side, stores all of them."""
        importer = self._importer()
        finding = Finding()
        finding.unsaved_req_resp = [
            {"req": "GET /a", "resp": None},
            {"req": None, "resp": "HTTP/1.1 500"},
            {"req": "GET /b", "resp": "HTTP/1.1 200 OK"},
        ]

        importer.process_request_response_pairs(finding)

        self.assertEqual(
            3, len(importer.pending_burp_rr),
            msg=f"expected all three pairs buffered, got {len(importer.pending_burp_rr)}",
        )
