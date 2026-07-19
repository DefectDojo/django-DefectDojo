"""
Expand / include / sub-resource RBAC sweep for API v3 (OS6, §11).

Ports the *intent* of ``unittests/test_apiv2_prefetch_rbac.py`` to the v3 ref / expand / include /
sub-resource surface. The v2 test pinned that ``?prefetch=`` could not reach objects outside the
caller's authorized querysets; this file pins the equivalent guarantee for v3's replacements:

  A user must NEVER see an **expanded** object, an **included** count, a **denormalized parent
  ref**, or a **sub-resource** row that was drawn from outside their authorized querysets.

The v3 design makes this structurally simpler than v2: every projection (slim refs, ``?expand=``
select/prefetch, ``?include=counts`` aggregate, and the ``/{id}/<sub>`` routes) is computed over
``get_authorized_findings(Permissions.Finding_View, user=request.user)`` -- so a finding the caller
cannot see never enters the pipeline, and nothing reachable *from* an authorized finding (its parent
hierarchy, reporter, locations, notes) can therefore belong to another product. These tests build a
two-product world, authorize a non-superuser on exactly one product, and assert the other product's
data never leaks through any v3 projection.

Setup mirrors the OSS authorization model used by the other v3 RBAC tests
(``test_apiv3_products.py`` / ``test_apiv3_subresources.py``): membership via the legacy
``product.authorized_users`` M2M, which the auth-filter plugin resolves into the finding queryset.
"""
from __future__ import annotations

import datetime

from dojo.location.models import Location, LocationFindingReference
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Notes,
    Product,
    Product_Type,
    Test,
    Test_Type,
)

from .base import ApiV3TestCase

_NUMERICAL = {"Critical": "S0", "High": "S1", "Medium": "S2", "Low": "S3", "Info": "S4"}


class _TwoProductWorld(ApiV3TestCase):

    """
    Build two isolated products (A authorized to ``member``, B not) with a known finding multiset,
    so leakage assertions can name exact counts and identify B's objects by their distinctive data.
    """

    def setUp(self):
        super().setUp()
        self.prod_type = Product_Type.objects.create(name="v3-rbac-pt")
        self.test_type = Test_Type.objects.create(name="v3-rbac-tt")

        # A non-superuser member authorized on product A only (authorized_users targets Dojo_User).
        self.member = Dojo_User.objects.create_user(username="v3_expand_member", password="x")  # noqa: S106
        # A distinctive reporter for product B's findings -- if this user ever appears in an
        # expanded/denormalized ref seen by the member, a user-enumeration leak has occurred (the
        # v2 sub-vector 4a case).
        self.reporter_b = Dojo_User.objects.create_user(username="v3_secret_reporter_b", password="x")  # noqa: S106

        self.product_a, self.test_a = self._make_product("v3-rbac-product-A")
        self.product_b, self.test_b = self._make_product("v3-rbac-product-B")
        self.product_a.authorized_users.add(self.member)

        # Product A: 2 Critical + 1 High, reported by admin. Product B: 3 Low + 1 Medium, reported
        # by the secret reporter. Distinct multisets make count-isolation assertions unambiguous.
        self.findings_a = self._make_findings(self.test_a, ["Critical", "Critical", "High"], self.admin)
        self.findings_b = self._make_findings(self.test_b, ["Low", "Low", "Low", "Medium"], self.reporter_b)

    def _make_product(self, name: str) -> tuple[Product, Test]:
        product = Product.objects.create(name=name, description="x", prod_type=self.prod_type, sla_configuration_id=1)
        engagement = Engagement.objects.create(
            product=product, name=f"{name}-eng",
            target_start=datetime.date(2026, 1, 1), target_end=datetime.date(2026, 1, 2),
        )
        test = Test.objects.create(
            engagement=engagement, test_type=self.test_type,
            target_start=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2026, 1, 2, tzinfo=datetime.UTC), lead=self.admin,
        )
        return product, test

    def _make_findings(self, test: Test, severities: list[str], reporter: Dojo_User) -> list[Finding]:
        findings = Finding.objects.bulk_create([
            Finding(
                title=f"{test.engagement.product.name} f{i} {sev}",
                severity=sev, numerical_severity=_NUMERICAL[sev], description="x",
                test=test, reporter=reporter, active=True, verified=False,
            )
            for i, sev in enumerate(severities)
        ])
        return list(findings)

    def member_client(self):
        return self.token_client(user=self.member)


class TestApiV3ExpandRbacPositive(_TwoProductWorld):

    """A user authorized on the finding's product CAN expand its relations (the positive case)."""

    def test_authorized_member_can_expand_test_engagement(self):
        finding = self.findings_a[0]
        detail = self.get_json(
            f"findings/{finding.id}", client=self.member_client(), data={"expand": "test.engagement"},
        )
        # test ref swapped for the test slim, engagement inlined inside it, all belonging to product A.
        self.assertIn("engagement", detail["test"])
        self.assertEqual(self.test_a.engagement.id, detail["test"]["engagement"]["id"])
        self.assertEqual(self.product_a.id, detail["test"]["engagement"]["product"]["id"])

    def test_authorized_member_list_expands_only_own_product(self):
        body = self.get_json(
            "findings", client=self.member_client(),
            data={"expand": "test.engagement,product,product_type", "limit": 250},
        )
        self.assertEqual(len(self.findings_a), body["count"])
        for row in body["results"]:
            # Denormalized parent refs AND expanded objects must all be product A.
            self.assertEqual(self.product_a.id, row["product"]["id"])
            self.assertEqual(self.product_a.id, row["test"]["engagement"]["product"]["id"])

    def test_authorized_member_include_counts_reflects_own_product(self):
        body = self.get_json("findings", client=self.member_client(), data={"include": "counts"})
        counts = body["meta"]["counts"]
        self.assertEqual(len(self.findings_a), counts["total"])
        self.assertEqual(2, counts["severity"]["Critical"])
        self.assertEqual(1, counts["severity"]["High"])


class TestApiV3ExpandRbacCrossProduct(_TwoProductWorld):

    """Product B's data must never leak into the member's list / detail / expand / filter."""

    def test_list_never_includes_other_product_rows(self):
        body = self.get_json("findings", client=self.member_client(), data={"limit": 250})
        seen_products = {row["product"]["id"] for row in body["results"]}
        self.assertEqual({self.product_a.id}, seen_products)
        self.assertNotIn(self.product_b.id, seen_products)

    def test_detail_of_other_product_finding_is_404_no_expansion(self):
        # Even asking to expand cannot coerce disclosure of an unauthorized finding (§4.10 404).
        self.get_json(
            f"findings/{self.findings_b[0].id}", client=self.member_client(),
            data={"expand": "test.engagement"}, expected=404,
        )

    def test_filter_by_other_product_returns_empty(self):
        # A filter naming product B must still be intersected with the authorized queryset -> empty.
        body = self.get_json("findings", client=self.member_client(), data={"product": self.product_b.id})
        self.assertEqual(0, body["count"])
        self.assertEqual([], body["results"])

    def test_expand_reporter_never_enumerates_other_product_users(self):
        # The v2 sub-vector 4a analogue: expanding reporter must not surface a user attached only to
        # findings the caller cannot see. Product B's secret reporter must never appear.
        body = self.get_json(
            "findings", client=self.member_client(), data={"expand": "reporter", "limit": 250},
        )
        # expand=reporter swaps the ref for the full UserSlim (keyed by `username`, §4.5).
        reporter_names = {row["reporter"]["username"] for row in body["results"] if row["reporter"]}
        self.assertNotIn(self.reporter_b.username, reporter_names)
        self.assertEqual({self.admin.username}, reporter_names)

    def test_include_counts_never_counts_other_product(self):
        body = self.get_json("findings", client=self.member_client(), data={"include": "counts"})
        counts = body["meta"]["counts"]
        # Product B's 3 Low + 1 Medium must not inflate the member's aggregate.
        self.assertEqual(0, counts["severity"]["Low"])
        self.assertEqual(0, counts["severity"]["Medium"])
        self.assertEqual(len(self.findings_a), counts["total"])

    def test_superuser_counts_exceed_member_counts(self):
        # Sanity contrast: the admin (who can see both products) counts strictly more than the member,
        # proving the member's lower number is authorization, not an empty database.
        admin_counts = self.get_json("findings", data={"include": "counts"})["meta"]["counts"]
        member_counts = self.get_json(
            "findings", client=self.member_client(), data={"include": "counts"},
        )["meta"]["counts"]
        self.assertGreater(admin_counts["total"], member_counts["total"])


class TestApiV3SubResourceRbacInheritance(_TwoProductWorld):

    """
    Sub-resource rows (locations, notes) are drawn from the parent's own managers; an unauthorized
    parent is a 404 so no row from another product can ever be read (parent-inherited authorization).
    """

    def setUp(self):
        super().setUp()
        self.finding_a = self.findings_a[0]
        self.finding_b = self.findings_b[0]
        # A location edge + a note on a finding in EACH product.
        for finding, marker in ((self.finding_a, "a"), (self.finding_b, "b")):
            location = Location.objects.create(location_type="url", location_value=f"https://example.com/{marker}")
            LocationFindingReference.objects.create(location=location, finding=finding, status="Active")
            note = Notes.objects.create(entry=f"note-{marker}", author=self.admin)
            finding.notes.add(note)

    def test_locations_subresource_authorized_parent_ok(self):
        body = self.get_json(f"findings/{self.finding_a.id}/locations", client=self.member_client())
        self.assertEqual(1, body["count"])
        self.assertEqual("https://example.com/a", body["results"][0]["location"]["name"])

    def test_locations_subresource_unauthorized_parent_is_404(self):
        self.get_json(f"findings/{self.finding_b.id}/locations", client=self.member_client(), expected=404)

    def test_notes_subresource_authorized_parent_ok(self):
        body = self.get_json(f"findings/{self.finding_a.id}/notes", client=self.member_client())
        self.assertIn("note-a", [n["entry"] for n in body["results"]])

    def test_notes_subresource_unauthorized_parent_is_404(self):
        self.get_json(f"findings/{self.finding_b.id}/notes", client=self.member_client(), expected=404)

    def test_note_create_on_unauthorized_parent_is_404(self):
        # Write attempts on an unseen parent are 404 too (never leak existence, never mutate).
        response = self.member_client().post(
            self.v3_url(f"findings/{self.finding_b.id}/notes"), {"entry": "x"}, format="json",
        )
        self.assertEqual(404, response.status_code, response.content[:300])

    def test_expand_locations_on_unauthorized_finding_is_404(self):
        # expand=locations edge rows must not disclose another product's location edges either.
        self.get_json(
            f"findings/{self.finding_b.id}", client=self.member_client(),
            data={"expand": "locations"}, expected=404,
        )
