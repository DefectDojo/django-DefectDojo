"""
Query-count baselines for tag inheritance hot paths.

These tests pin the *current* number of SQL queries DefectDojo issues for each
hot path under tag inheritance. They are tripwires: future redesign work
(see /home/valentijn/.claude/plans/tag-inheritance-redesign.md) will reduce
these numbers, and any regression that pushes them back up will fail loudly.

Each test:
  - sets up its fixture *outside* the query-counting block
  - exercises one operation under ``assertNumQueries`` with the pinned baseline
  - asserts a positive correctness check so query tightening cannot smuggle in
    a behavior bug.
"""
from __future__ import annotations

import logging

from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.utils import timezone

from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Endpoint, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tags.inheritance import propagate_tags_on_product_sync
from unittests.dojo_test_case import (
    DojoAPITestCase,
    DojoTestCase,
    get_unit_tests_scans_path,
    versioned_fixtures,
)

logger = logging.getLogger(__name__)


def _make_product_with_findings(name: str, *, n_findings: int, tags: list[str] | None = None) -> Product:
    """
    Create a Product → Engagement → Test → N Findings tree with inheritance enabled.

    Returns the Product. Internal-only: signal-driven inheritance fires during
    creation, but those queries are not counted (we measure operations against
    the already-built fixture).
    """
    if tags is None:
        tags = []
    now = timezone.now()
    user, _ = User.objects.get_or_create(username="tag_perf_user", defaults={"is_active": True})
    pt, _ = Product_Type.objects.get_or_create(name="Tag Perf Type")
    product = Product.objects.create(
        name=name,
        description="perf",
        prod_type=pt,
        enable_product_tag_inheritance=True,
    )
    if tags:
        product.tags.add(*tags)
    eng = Engagement.objects.create(product=product, target_start=now, target_end=now)
    tt, _ = Test_Type.objects.get_or_create(name="Tag Perf Test")
    test = Test.objects.create(engagement=eng, test_type=tt, target_start=now, target_end=now)
    for i in range(n_findings):
        Finding.objects.create(
            test=test,
            title=f"Tag Perf Finding {i}",
            severity="Medium",
            reporter=user,
        )
    return product


def _make_endpoints(product: Product, n: int) -> None:
    """Create N Endpoints attached directly to the product (V2 only)."""
    for i in range(n):
        ep = Endpoint(host=f"perf-{product.id}-{i}.example.com", product=product)
        ep.save()


def _make_locations(product: Product, n: int) -> None:
    """Create N URL Locations attached to the product via LocationManager.persist (V3 only)."""
    # Local imports so the file remains importable when V3_FEATURE_LOCATIONS=False.
    from dojo.importers.location_manager import LocationManager  # noqa: PLC0415
    from dojo.tools.locations import LocationData  # noqa: PLC0415

    finding = Finding.objects.filter(test__engagement__product=product).first()
    if finding is None:
        # _make_product_with_findings should have been called first with n_findings>=1.
        msg = "_make_locations requires the product to have at least one Finding"
        raise RuntimeError(msg)

    loc_data = [
        LocationData(type="url", data={"url": f"https://perf-{product.id}-{i}.example.com"})
        for i in range(n)
    ]
    mgr = LocationManager(product)
    mgr.record_locations_for_finding(finding, loc_data)
    mgr.persist()


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CELERY_TASK_EAGER_PROPAGATES=True,
)
class TagInheritancePerfBaselines(DojoTestCase):

    """
    Pinned query-count baselines for tag inheritance hot paths.

    Celery handling: ``CELERY_TASK_ALWAYS_EAGER=True`` runs all dispatched
    tasks synchronously in the test thread/connection so their queries are
    captured by ``assertNumQueries``. ``CELERY_TASK_EAGER_PROPAGATES`` makes
    eager-mode failures surface as exceptions rather than silently swallowing.
    Product tag tests still call ``propagate_tags_on_product_sync(product)``
    explicitly because the m2m_changed signal dispatches the Celery task
    with ``countdown=5`` — eager mode runs immediately but ``dojo_dispatch_task``
    paths can still skip execution depending on ``we_want_async``. Calling the
    sync entry point directly makes the propagation deterministic.


    TEMPORARY: this test class exists to measure progress as the tag
    inheritance redesign lands across multiple PRs. The exact pinned numbers
    are not important on their own — what matters is that they MOVE in the
    expected direction (downward) as PR #1 (Phase A) and PR #2 (Phase B)
    land. Once the redesign is complete and the numbers have stabilized at
    target levels, this whole file can be deleted or the assertions
    rewritten as loose upper bounds.

    Numbers are *current behavior*. Follow-up PRs reduce them. When a
    redesign lowers a number, lower the pin in the same PR; when something
    accidentally raises it, fix the regression rather than raising the pin.
    """

    @classmethod
    def setUpTestData(cls):
        # Enable system-wide inheritance for every test in this class.
        # Per-product flag is also set in _make_product_with_findings as a
        # belt-and-braces measure (tests should not be flag-coupled).
        from dojo.models import System_Settings  # noqa: PLC0415
        ss = System_Settings.objects.get()
        ss.enable_product_tag_inheritance = True
        ss.save()

        # Warm up ContentType cache for models touched by the propagation
        # paths so first-call ContentType lookups don't count against the
        # measured sections (matches the pattern in test_importers_performance).
        # Without this, the first test in a fresh process to exercise the V3
        # Location path pays a one-time lookup, producing a matrix-dependent
        # off-by-one when CI runs with V3_FEATURE_LOCATIONS true vs false at
        # startup.
        for model in [Endpoint, Engagement, Finding, Location, LocationFindingReference, LocationProductReference, Product, Product_Type, Test, Test_Type]:
            ContentType.objects.get_for_model(model)

    # ------------------------------------------------------------------
    # Helpers shared by V2/V3 variants of the same scenario.
    # ------------------------------------------------------------------

    def _do_product_tag_add_findings(self, name: str, expected: int) -> None:
        product = _make_product_with_findings(name, n_findings=100, tags=["initial"])
        with self.assertNumQueries(expected):
            product.tags.add("perf-added")
            propagate_tags_on_product_sync(product)
        finding = Finding.objects.filter(test__engagement__product=product).first()
        self.assertIn("perf-added", [t.name for t in finding.tags.all()])

    def _do_product_tag_remove_findings(self, name: str, expected: int) -> None:
        product = _make_product_with_findings(name, n_findings=100, tags=["to-remove", "stays"])
        with self.assertNumQueries(expected):
            product.tags.remove("to-remove")
            propagate_tags_on_product_sync(product)
        finding = Finding.objects.filter(test__engagement__product=product).first()
        finding_tag_names = {t.name for t in finding.tags.all()}
        self.assertNotIn("to-remove", finding_tag_names)
        self.assertIn("stays", finding_tag_names)

    def _do_create_one_finding(self, name: str, expected: int) -> None:
        product = _make_product_with_findings(name, n_findings=0, tags=["t1", "t2"])
        engagement = Engagement.objects.filter(product=product).first()
        test = Test.objects.filter(engagement=engagement).first()
        user = User.objects.get(username="tag_perf_user")
        with self.assertNumQueries(expected):
            Finding.objects.create(
                test=test,
                title="single-perf",
                severity="Medium",
                reporter=user,
            )
        # Finding.save() titlecases + truncates the title; look up via test FK.
        finding = Finding.objects.filter(test=test).first()
        self.assertIsNotNone(finding)
        self.assertEqual({"t1", "t2"}, {t.name for t in finding.tags.all()})

    def _do_create_100_findings(self, name: str, expected: int) -> None:
        product = _make_product_with_findings(name, n_findings=0, tags=["t1", "t2"])
        engagement = Engagement.objects.filter(product=product).first()
        test = Test.objects.filter(engagement=engagement).first()
        user = User.objects.get(username="tag_perf_user")
        with self.assertNumQueries(expected):
            for i in range(100):
                Finding.objects.create(
                    test=test,
                    title=f"loop-{i}",
                    severity="Medium",
                    reporter=user,
                )
        self.assertEqual(100, Finding.objects.filter(test=test).count())
        any_finding = Finding.objects.filter(test=test).first()
        self.assertEqual({"t1", "t2"}, {t.name for t in any_finding.tags.all()})

    def _do_finding_add_user_tag(self, name: str, expected: int) -> None:
        product = _make_product_with_findings(name, n_findings=1, tags=["inherited"])
        finding = Finding.objects.filter(test__engagement__product=product).first()
        with self.assertNumQueries(expected):
            finding.tags.add("user-only")
        finding_tag_names = {t.name for t in finding.tags.all()}
        self.assertIn("user-only", finding_tag_names)
        self.assertIn("inherited", finding_tag_names)  # still sticky

    def _do_propagate_sync_only(self, name: str, expected: int, *, with_endpoints: bool, with_locations: bool) -> None:
        """
        Measure `propagate_tags_on_product_sync(product)` in isolation — no tag change.

        Captures the raw sweep cost for a product with a realistic mix of children:
        N findings + (V2) N endpoints or (V3) N locations. Should be roughly idempotent
        (no add/remove to apply) so the number reflects diff-detection overhead.
        """
        product = _make_product_with_findings(name, n_findings=100, tags=["t1", "t2"])
        if with_endpoints:
            _make_endpoints(product, n=100)
        if with_locations:
            _make_locations(product, n=100)
        with self.assertNumQueries(expected):
            propagate_tags_on_product_sync(product)
        finding = Finding.objects.filter(test__engagement__product=product).first()
        self.assertEqual({"t1", "t2"}, {t.name for t in finding.tags.all()})

    def _do_finding_remove_inherited(self, name: str, expected: int) -> None:
        product = _make_product_with_findings(name, n_findings=1, tags=["inherited"])
        finding = Finding.objects.filter(test__engagement__product=product).first()
        with self.assertNumQueries(expected):
            finding.tags.remove("inherited")
        # Sticky re-adds the inherited tag.
        self.assertIn("inherited", {t.name for t in finding.tags.all()})

    # ------------------------------------------------------------------
    # Product tag add / remove (Findings only) - V2 + V3 variants.
    # ------------------------------------------------------------------

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_product_tag_add_propagates_to_100_findings_v2(self):
        self._do_product_tag_add_findings("perf-add-v2", self.EXPECTED_PRODUCT_TAG_ADD_100_V2)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_product_tag_add_propagates_to_100_findings_v3(self):
        self._do_product_tag_add_findings("perf-add-v3", self.EXPECTED_PRODUCT_TAG_ADD_100_V3)

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_product_tag_remove_propagates_to_100_findings_v2(self):
        self._do_product_tag_remove_findings("perf-remove-v2", self.EXPECTED_PRODUCT_TAG_REMOVE_100_V2)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_product_tag_remove_propagates_to_100_findings_v3(self):
        self._do_product_tag_remove_findings("perf-remove-v3", self.EXPECTED_PRODUCT_TAG_REMOVE_100_V3)

    # ------------------------------------------------------------------
    # Child creation under inheritance - V2 + V3 variants.
    # ------------------------------------------------------------------

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_create_one_finding_under_inheritance_v2(self):
        self._do_create_one_finding("perf-create-one-v2", self.EXPECTED_CREATE_ONE_FINDING_V2)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_create_one_finding_under_inheritance_v3(self):
        self._do_create_one_finding("perf-create-one-v3", self.EXPECTED_CREATE_ONE_FINDING_V3)

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_create_100_findings_under_inheritance_v2(self):
        self._do_create_100_findings("perf-create-100-v2", self.EXPECTED_CREATE_100_FINDINGS_V2)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_create_100_findings_under_inheritance_v3(self):
        self._do_create_100_findings("perf-create-100-v3", self.EXPECTED_CREATE_100_FINDINGS_V3)

    # ------------------------------------------------------------------
    # Sticky enforcement on child tag edits - V2 + V3 variants.
    # ------------------------------------------------------------------

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_finding_add_user_tag_sticky_path_v2(self):
        self._do_finding_add_user_tag("perf-sticky-add-v2", self.EXPECTED_FINDING_ADD_USER_TAG_V2)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_finding_add_user_tag_sticky_path_v3(self):
        self._do_finding_add_user_tag("perf-sticky-add-v3", self.EXPECTED_FINDING_ADD_USER_TAG_V3)

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_finding_remove_inherited_tag_sticky_re_adds_v2(self):
        self._do_finding_remove_inherited("perf-sticky-rm-v2", self.EXPECTED_FINDING_REMOVE_INHERITED_V2)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_finding_remove_inherited_tag_sticky_re_adds_v3(self):
        self._do_finding_remove_inherited("perf-sticky-rm-v3", self.EXPECTED_FINDING_REMOVE_INHERITED_V3)

    # ------------------------------------------------------------------
    # propagate_tags_on_product_sync direct invocation (no tag change).
    # Measures the raw sweep cost over a product's children.
    # ------------------------------------------------------------------

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_propagate_tags_on_product_sync_v2(self):
        self._do_propagate_sync_only(
            "perf-sync-v2",
            self.EXPECTED_PROPAGATE_SYNC_V2,
            with_endpoints=True,
            with_locations=False,
        )

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_propagate_tags_on_product_sync_v3(self):
        self._do_propagate_sync_only(
            "perf-sync-v3",
            self.EXPECTED_PROPAGATE_SYNC_V3,
            with_endpoints=False,
            with_locations=True,
        )

    # ------------------------------------------------------------------
    # V2: propagation to Endpoints (skipped under V3_FEATURE_LOCATIONS)
    # ------------------------------------------------------------------

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_product_tag_add_propagates_to_100_endpoints_v2(self):
        """`product.tags.add("x")` then sync -> propagate to 100 Endpoints (V2)."""
        product = _make_product_with_findings("perf-add-eps", n_findings=0, tags=["initial"])
        _make_endpoints(product, n=100)

        with self.assertNumQueries(self.EXPECTED_PRODUCT_TAG_ADD_100_ENDPOINTS):
            product.tags.add("perf-added-ep")
            propagate_tags_on_product_sync(product)

        endpoint = Endpoint.objects.filter(product=product).first()
        self.assertIn("perf-added-ep", [t.name for t in endpoint.tags.all()])

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_product_tag_remove_propagates_to_100_endpoints_v2(self):
        """`product.tags.remove("x")` then sync -> remove from 100 Endpoints (V2)."""
        product = _make_product_with_findings("perf-remove-eps", n_findings=0, tags=["to-remove-ep", "stays-ep"])
        _make_endpoints(product, n=100)

        with self.assertNumQueries(self.EXPECTED_PRODUCT_TAG_REMOVE_100_ENDPOINTS):
            product.tags.remove("to-remove-ep")
            propagate_tags_on_product_sync(product)

        endpoint = Endpoint.objects.filter(product=product).first()
        endpoint_tag_names = {t.name for t in endpoint.tags.all()}
        self.assertNotIn("to-remove-ep", endpoint_tag_names)
        self.assertIn("stays-ep", endpoint_tag_names)

    # ------------------------------------------------------------------
    # V3: propagation to Locations (skipped under V2)
    # ------------------------------------------------------------------

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_product_tag_add_propagates_to_100_locations_v3(self):
        """`product.tags.add("x")` then sync -> propagate to 100 Locations (V3)."""
        # Locations are created against a finding; ensure the product has one.
        product = _make_product_with_findings("perf-add-locs", n_findings=1, tags=["initial"])
        _make_locations(product, n=100)

        with self.assertNumQueries(self.EXPECTED_PRODUCT_TAG_ADD_100_LOCATIONS):
            product.tags.add("perf-added-loc")
            propagate_tags_on_product_sync(product)

        loc = Location.objects.filter(products__product=product).first()
        self.assertIsNotNone(loc)
        self.assertIn("perf-added-loc", [t.name for t in loc.tags.all()])

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_product_tag_remove_propagates_to_100_locations_v3(self):
        """`product.tags.remove("x")` then sync -> remove from 100 Locations (V3)."""
        product = _make_product_with_findings("perf-remove-locs", n_findings=1, tags=["to-remove-loc", "stays-loc"])
        _make_locations(product, n=100)

        with self.assertNumQueries(self.EXPECTED_PRODUCT_TAG_REMOVE_100_LOCATIONS):
            product.tags.remove("to-remove-loc")
            propagate_tags_on_product_sync(product)

        loc = Location.objects.filter(products__product=product).first()
        self.assertIsNotNone(loc)
        location_tag_names = {t.name for t in loc.tags.all()}
        self.assertNotIn("to-remove-loc", location_tag_names)
        self.assertIn("stays-loc", location_tag_names)

    # ------------------------------------------------------------------
    # Pinned baselines (current code; tighten in PR #1 / PR #2)
    # ------------------------------------------------------------------
    # Each scenario pins V2 and V3 separately because the propagation code
    # branches on V3_FEATURE_LOCATIONS. Per-test @override_settings forces
    # the appropriate mode so all variants execute in a single suite run.

    # Findings-only scenarios.
    # Pre-Phase-A V2: 4758 add, 4540 remove. V3: 4759/4541.
    # Phase A bulk-propagate drops these dramatically.
    EXPECTED_PRODUCT_TAG_ADD_100_V2 = 91
    EXPECTED_PRODUCT_TAG_ADD_100_V3 = 91
    EXPECTED_PRODUCT_TAG_REMOVE_100_V2 = 53
    EXPECTED_PRODUCT_TAG_REMOVE_100_V3 = 53

    EXPECTED_CREATE_ONE_FINDING_V2 = 55
    EXPECTED_CREATE_ONE_FINDING_V3 = 55
    EXPECTED_CREATE_100_FINDINGS_V2 = 3124
    EXPECTED_CREATE_100_FINDINGS_V3 = 3124

    EXPECTED_FINDING_ADD_USER_TAG_V2 = 17
    EXPECTED_FINDING_ADD_USER_TAG_V3 = 17
    EXPECTED_FINDING_REMOVE_INHERITED_V2 = 18
    EXPECTED_FINDING_REMOVE_INHERITED_V3 = 18

    # V2 endpoint paths. Pre-Phase-A: 3958 add, 3740 remove.
    EXPECTED_PRODUCT_TAG_ADD_100_ENDPOINTS = 91
    EXPECTED_PRODUCT_TAG_REMOVE_100_ENDPOINTS = 53

    # V3 location paths. Pre-Phase-A: 4532 add, 4307 remove.
    EXPECTED_PRODUCT_TAG_ADD_100_LOCATIONS = 125
    EXPECTED_PRODUCT_TAG_REMOVE_100_LOCATIONS = 75

    # propagate_tags_on_product_sync direct invocation (no tag change).
    # Product with 100 findings + 100 endpoints (V2) or + 100 locations (V3).
    EXPECTED_PROPAGATE_SYNC_V2 = 9
    EXPECTED_PROPAGATE_SYNC_V3 = 18


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CELERY_TASK_EAGER_PROPAGATES=True,
    SECURE_SSL_REDIRECT=False,
)
@versioned_fixtures
class TagInheritanceImportPerfBaselines(DojoAPITestCase):

    """
    Pinned query-count baselines for the importer hot path.

    Real production tag-inheritance cost lives in scan import / reimport: the
    importer creates findings + endpoints/locations, then `_sync_inherited_tags`
    runs per row. Phase A (bulk product-side propagation + post_save gated on
    create) doesn't touch this loop because the importer's hot path is
    creation-driven. Phase B's `tag_inheritance.suppress_tag_inheritance()` context manager
    targets it.

    Two scenarios:
      - First import of a ZAP scan into an inheritance-on product.
      - Reimport of the same scan with no changes (idempotent path).
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        from dojo.models import System_Settings  # noqa: PLC0415
        ss = System_Settings.objects.get()
        ss.enable_product_tag_inheritance = True
        ss.save()

    def setUp(self):
        super().setUp()
        self.login_as_admin()
        self.system_settings(enable_product_tag_inheritance=True)
        self.product = self.create_product("Tag Perf Import Product", tags=["inherit", "these"])
        self.engagement = self.create_engagement("Tag Perf Import Engagement", self.product)
        self.scan_path = get_unit_tests_scans_path("zap") / "dvwa_baseline_dojo.xml"

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_zap_scan_import_v2(self):
        """
        V2: first-time import of a 19-finding ZAP scan with inheritance enabled.

        Captures total query count for: scan parse + finding creation + endpoint
        attachment + per-row inherit_tags signal chain. Production hot path.
        Phase A leaves this number ~unchanged; Phase B's `tag_inheritance.suppress_tag_inheritance()`
        targets it.
        """
        with self.assertNumQueries(self.EXPECTED_ZAP_IMPORT_V2):
            response = self.import_scan_with_params(
                self.scan_path,
                engagement=self.engagement.id,
            )

        test_id = response["test"]
        finding = Finding.objects.filter(test_id=test_id).first()
        self.assertIsNotNone(finding)
        self.assertEqual({"inherit", "these"}, {t.name for t in finding.tags.all()})

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_zap_scan_import_v3(self):
        """V3: first-time import; uses LocationManager for endpoint persistence."""
        with self.assertNumQueries(self.EXPECTED_ZAP_IMPORT_V3):
            response = self.import_scan_with_params(
                self.scan_path,
                engagement=self.engagement.id,
            )

        test_id = response["test"]
        finding = Finding.objects.filter(test_id=test_id).first()
        self.assertIsNotNone(finding)
        self.assertEqual({"inherit", "these"}, {t.name for t in finding.tags.all()})

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_baseline_zap_scan_reimport_no_change_v2(self):
        """V2: reimport same scan; expected to be a near-no-op for tag inheritance."""
        response = self.import_scan_with_params(
            self.scan_path,
            engagement=self.engagement.id,
        )
        test_id = response["test"]

        with self.assertNumQueries(self.EXPECTED_ZAP_REIMPORT_NO_CHANGE_V2):
            self.reimport_scan_with_params(test_id, str(self.scan_path))

        finding = Finding.objects.filter(test_id=test_id).first()
        self.assertEqual({"inherit", "these"}, {t.name for t in finding.tags.all()})

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_baseline_zap_scan_reimport_no_change_v3(self):
        """V3: reimport same scan with no changes."""
        response = self.import_scan_with_params(
            self.scan_path,
            engagement=self.engagement.id,
        )
        test_id = response["test"]

        with self.assertNumQueries(self.EXPECTED_ZAP_REIMPORT_NO_CHANGE_V3):
            self.reimport_scan_with_params(test_id, str(self.scan_path))

        finding = Finding.objects.filter(test_id=test_id).first()
        self.assertEqual({"inherit", "these"}, {t.name for t in finding.tags.all()})

    # Pinned baselines per mode. Each test forces its own V3_FEATURE_LOCATIONS
    # via @override_settings so all four import paths run in a single suite
    # invocation regardless of the ambient `DD_V3_FEATURE_LOCATIONS` env var.
    # Pre-Phase-A: 1461/1319 import, 77/95 reimport.
    # Phase A nudges these slightly downward (post_save gated on created=True
    # avoids re-running inheritance on no-op finding updates during reimport).
    # Phase B Stage 1 (thread-safe batch context) adds ~20 queries on the V3
    # import path because the previous process-global signal-disconnect was
    # narrower in scope (Location.tags.through only). Net-positive trade for
    # eliminating the threading bug; full Phase B reductions land in Stage 2.
    EXPECTED_ZAP_IMPORT_V2 = 420
    EXPECTED_ZAP_IMPORT_V3 = 444
    EXPECTED_ZAP_REIMPORT_NO_CHANGE_V2 = 69
    EXPECTED_ZAP_REIMPORT_NO_CHANGE_V3 = 81
