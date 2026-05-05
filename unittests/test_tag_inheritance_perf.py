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

from django.conf import settings
from django.contrib.auth.models import User
from django.test import override_settings
from django.utils import timezone

from dojo.models import Endpoint, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.product.helpers import propagate_tags_on_product_sync
from unittests.dojo_test_case import DojoTestCase

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

    # ------------------------------------------------------------------
    # Product tag add / remove → propagate to children
    # ------------------------------------------------------------------

    def test_baseline_product_tag_add_propagates_to_100_findings(self):
        """
        `product.tags.add("x")` then sync → propagate to 100 findings.

        Hot path: Product tag toggle in the UI on a product with many
        findings. Today's flow runs `obj.save()` per child. Phase A bulk SQL
        will collapse this dramatically.
        """
        product = _make_product_with_findings("perf-add", n_findings=100, tags=["initial"])

        with self.assertNumQueries(self.EXPECTED_PRODUCT_TAG_ADD_100):
            product.tags.add("perf-added")
            propagate_tags_on_product_sync(product)

        # Correctness: a finding under the product now carries the new tag.
        finding = Finding.objects.filter(test__engagement__product=product).first()
        self.assertIn("perf-added", [t.name for t in finding.tags.all()])

    def test_baseline_product_tag_remove_propagates_to_100_findings(self):
        """`product.tags.remove("x")` then sync → remove from 100 findings."""
        product = _make_product_with_findings("perf-remove", n_findings=100, tags=["to-remove", "stays"])

        with self.assertNumQueries(self.EXPECTED_PRODUCT_TAG_REMOVE_100):
            product.tags.remove("to-remove")
            propagate_tags_on_product_sync(product)

        finding = Finding.objects.filter(test__engagement__product=product).first()
        finding_tag_names = {t.name for t in finding.tags.all()}
        self.assertNotIn("to-remove", finding_tag_names)
        self.assertIn("stays", finding_tag_names)

    # ------------------------------------------------------------------
    # Child creation under inheritance-on product
    # ------------------------------------------------------------------

    def test_baseline_create_one_finding_under_inheritance(self):
        """
        Single Finding.objects.create() on inheritance-on product.

        post_save fires `inherit_tags_on_instance` which calls
        `_manage_inherited_tags` → 2 m2m `.set()` calls per save. This
        baseline pins the per-finding cost. Phase A gates on `created=True`
        so updates stop paying it; Phase B replaces the M2M dance with a
        single JSON column write.
        """
        product = _make_product_with_findings("perf-create-one", n_findings=0, tags=["t1", "t2"])
        engagement = Engagement.objects.filter(product=product).first()
        test = Test.objects.filter(engagement=engagement).first()
        user = User.objects.get(username="tag_perf_user")

        with self.assertNumQueries(self.EXPECTED_CREATE_ONE_FINDING):
            Finding.objects.create(
                test=test,
                title="single-perf",
                severity="Medium",
                reporter=user,
            )

        # Finding.save() titlecases + truncates the title — look up via test FK
        finding = Finding.objects.filter(test=test).first()
        self.assertIsNotNone(finding)
        self.assertEqual({"t1", "t2"}, {t.name for t in finding.tags.all()})

    def test_baseline_create_100_findings_under_inheritance(self):
        """
        100 sequential Finding.objects.create() under inheritance.

        Approximates an importer hot loop. Today every iteration fires
        `_manage_inherited_tags` per finding. After Phase B, wrapping in
        `with tag_inheritance.batch():` should collapse to a single bulk
        sync at exit.
        """
        product = _make_product_with_findings("perf-create-100", n_findings=0, tags=["t1", "t2"])
        engagement = Engagement.objects.filter(product=product).first()
        test = Test.objects.filter(engagement=engagement).first()
        user = User.objects.get(username="tag_perf_user")

        with self.assertNumQueries(self.EXPECTED_CREATE_100_FINDINGS):
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

    # ------------------------------------------------------------------
    # Sticky enforcement on child tag edits
    # ------------------------------------------------------------------

    def test_baseline_finding_add_user_tag_sticky_path(self):
        """
        `finding.tags.add("user-only")` — sticky signal still runs.

        Adding a *non-inherited* tag still fires `m2m_changed` →
        `make_inherited_tags_sticky` → re-checks product tags. Phase B
        moves this work out of the signal entirely.
        """
        product = _make_product_with_findings("perf-sticky-add", n_findings=1, tags=["inherited"])
        finding = Finding.objects.filter(test__engagement__product=product).first()

        with self.assertNumQueries(self.EXPECTED_FINDING_ADD_USER_TAG):
            finding.tags.add("user-only")

        finding_tag_names = {t.name for t in finding.tags.all()}
        self.assertIn("user-only", finding_tag_names)
        self.assertIn("inherited", finding_tag_names)  # still sticky

    def test_baseline_finding_remove_inherited_tag_sticky_re_adds(self):
        """
        `finding.tags.remove("inherited")` — sticky re-adds.

        Most expensive sticky path: signal re-applies inherited tags via
        `inherit_tags` → `_manage_inherited_tags` → 2 M2M `.set()` calls.
        """
        product = _make_product_with_findings("perf-sticky-rm", n_findings=1, tags=["inherited"])
        finding = Finding.objects.filter(test__engagement__product=product).first()

        with self.assertNumQueries(self.EXPECTED_FINDING_REMOVE_INHERITED):
            finding.tags.remove("inherited")

        # Sticky re-adds the inherited tag
        self.assertIn("inherited", {t.name for t in finding.tags.all()})

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

        from dojo.location.models import Location  # noqa: PLC0415
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

        from dojo.location.models import Location  # noqa: PLC0415
        loc = Location.objects.filter(products__product=product).first()
        self.assertIsNotNone(loc)
        location_tag_names = {t.name for t in loc.tags.all()}
        self.assertNotIn("to-remove-loc", location_tag_names)
        self.assertIn("stays-loc", location_tag_names)

    # ------------------------------------------------------------------
    # Pinned baselines (current code; tighten in PR #1 / PR #2)
    # ------------------------------------------------------------------
    # Calibrated against current implementation. If a redesign lowers a
    # number, lower the pin in the same PR. If a regression raises it, fix
    # the regression. NEVER raise a pin without justification.

    # Calibrated against current `dev` branch behavior.
    # Tighten as PR #1 (Phase A) and PR #2 (Phase B) land.
    # Some hot paths execute slightly different code under V2 vs V3
    # (V3 walks an extra Location queryset; V2 walks an Endpoint queryset).
    # Use ``_pin(v2=..., v3=...)`` to select the appropriate baseline.
    @staticmethod
    def _pin(*, v2: int, v3: int) -> int:
        return v3 if settings.V3_FEATURE_LOCATIONS else v2

    @property
    def EXPECTED_PRODUCT_TAG_ADD_100(self) -> int:
        return self._pin(v2=4758, v3=4759)

    @property
    def EXPECTED_PRODUCT_TAG_REMOVE_100(self) -> int:
        return self._pin(v2=4540, v3=4541)

    EXPECTED_CREATE_ONE_FINDING = 64
    EXPECTED_CREATE_100_FINDINGS = 4025
    EXPECTED_FINDING_ADD_USER_TAG = 17
    EXPECTED_FINDING_REMOVE_INHERITED = 44

    # V2 endpoint paths (only run when V3_FEATURE_LOCATIONS=False)
    EXPECTED_PRODUCT_TAG_ADD_100_ENDPOINTS = 3958
    EXPECTED_PRODUCT_TAG_REMOVE_100_ENDPOINTS = 3740

    # V3 location paths (only run when V3_FEATURE_LOCATIONS=True)
    EXPECTED_PRODUCT_TAG_ADD_100_LOCATIONS = 4532
    EXPECTED_PRODUCT_TAG_REMOVE_100_LOCATIONS = 4307
