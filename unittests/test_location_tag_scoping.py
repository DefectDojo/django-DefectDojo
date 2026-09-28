from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.authorization.roles_permissions import Roles
from dojo.location.status import ProductLocationStatus
from dojo.models import (
    Dojo_User,
    Product,
    Product_Member,
    Product_Type,
    Role,
    System_Settings,
    User,
)
from dojo.tags.inheritance import apply_inherited_tags_for_locations
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3

FOREIGN = "tagscope-foreign.example.test"
OWN = "tagscope-own.example.test"
BOTH_MINE = "tagscope-both-mine.example.test"
INHERIT = "tagscope-inherit.example.test"

FOREIGN_TAG = "foreignsecret"
OWN_TAG = "myowntag"
INHERITED_TAG = "inheritedsecret"


@skip_unless_v3
class LocationTagScopingTest(DojoTestCase):

    """
    A Location row is deduplicated globally and carries one tag set for every product that
    references it. The tag set must only be served to a caller authorized for every product
    on the row, and the tag filters must not match on a set the body withholds.
    """

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="TagScope PT")
        reader = Role.objects.get(id=Roles.Reader)

        def product(name, **kwargs):
            return Product.objects.create(name=name, description=name, prod_type=prod_type, **kwargs)

        cls.mine = product("TagScope Mine")
        cls.also_mine = product("TagScope Also Mine")
        cls.theirs = product("TagScope Theirs")
        cls.theirs_inheriting = product(
            "TagScope Theirs Inheriting", enable_product_tag_inheritance=True,
        )
        cls.theirs_inheriting.tags.set([INHERITED_TAG])

        cls.alice = User.objects.create_user(
            username="tagscope_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        alice = Dojo_User.objects.get(pk=cls.alice.pk)
        for owned in (cls.mine, cls.also_mine):
            Product_Member.objects.create(user=cls.alice, product=owned, role=reader)
            owned.authorized_users.add(alice)

        def location(host, *products):
            loc = URL.get_or_create_from_values(protocol="https", host=host, path="x").location
            for prod in products:
                loc.associate_with_product(prod, status=ProductLocationStatus.Active)
            return loc

        # Shared with a product Alice cannot see: the tag set is not hers to read.
        cls.foreign = location(FOREIGN, cls.mine, cls.theirs)
        cls.foreign.tags.set([FOREIGN_TAG])

        # Only Alice's product references it.
        cls.own = location(OWN, cls.mine)
        cls.own.tags.set([OWN_TAG])

        # Shared, but only between two products Alice holds: still hers to read.
        cls.both_mine = location(BOTH_MINE, cls.mine, cls.also_mine)
        cls.both_mine.tags.set([OWN_TAG])

        # Product tag inheritance writes the union of contributing products' tags here.
        cls.inherit = location(INHERIT, cls.mine, cls.theirs_inheriting)
        apply_inherited_tags_for_locations([cls.inherit], product=cls.theirs_inheriting)

        cls.admin = User.objects.create_superuser(
            username="tagscope_admin",
            email="tagscope_admin@example.test",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        cls.alice_token = Token.objects.get_or_create(user=cls.alice)[0].key
        cls.admin_token = Token.objects.get_or_create(user=cls.admin)[0].key

    def setUp(self):
        super().setUp()
        settings = System_Settings.objects.get(no_cache=True)
        settings.enable_product_tag_inheritance = False
        settings.save()

    def _client(self, token):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        return client

    def _get(self, url, token=None):
        response = self._client(token or self.alice_token).get(url, format="json")
        self.assertEqual(response.status_code, 200, response.content[:300])
        return response.json()

    def _endpoint_tags(self, token=None):
        return {
            row["host"]: row["tags"]
            for row in self._get("/api/v2/endpoints/", token)["results"]
        }

    def _location_row(self, host, token=None):
        return next(
            row for row in self._get("/api/v2/location/", token)["results"]
            if host in row["location_value"]
        )

    def _hosts(self, query, token=None):
        return {row["host"] for row in self._get(f"/api/v2/endpoints/?{query}", token)["results"]}

    def test_premise_each_url_is_one_shared_row(self):
        self.assertEqual({p.name for p in self.foreign.all_related_products()},
                         {self.mine.name, self.theirs.name})
        names = {p["name"] for p in self._get("/api/v2/products/")["results"]}
        self.assertNotIn(self.theirs.name, names)

    def test_endpoint_body_withholds_a_foreign_products_tags(self):
        self.assertEqual(self._endpoint_tags()[FOREIGN], [])

    def test_endpoint_body_withholds_inherited_foreign_product_tags(self):
        self.assertEqual(self._endpoint_tags()[INHERIT], [])

    def test_endpoint_body_still_serves_an_unshared_rows_tags(self):
        self.assertEqual(self._endpoint_tags()[OWN], [OWN_TAG])

    def test_endpoint_body_still_serves_a_row_shared_only_within_my_products(self):
        self.assertEqual(self._endpoint_tags()[BOTH_MINE], [OWN_TAG])

    def test_endpoint_body_still_complete_for_a_superuser(self):
        self.assertEqual(self._endpoint_tags(self.admin_token)[FOREIGN], [FOREIGN_TAG])

    def test_endpoint_filters_do_not_match_a_foreign_tag(self):
        for query in (
            f"tag={FOREIGN_TAG[:12]}",
            f"tags={FOREIGN_TAG}",
            f"tags__and={FOREIGN_TAG}",
            f"tag={INHERITED_TAG[:12]}",
        ):
            self.assertEqual(self._hosts(query), set(), query)

    def test_endpoint_negated_filters_treat_a_foreign_tag_set_as_empty(self):
        self.assertIn(FOREIGN, self._hosts(f"not_tag={FOREIGN_TAG[:12]}"))
        self.assertNotIn(FOREIGN, self._hosts("has_tags=true"))

    def test_endpoint_filters_still_match_my_own_tags(self):
        self.assertEqual(self._hosts(f"tag={OWN_TAG}"), {OWN, BOTH_MINE})
        self.assertEqual(self._hosts(f"tags={OWN_TAG}"), {OWN, BOTH_MINE})
        self.assertEqual(self._hosts(f"tags__and={OWN_TAG}"), {OWN, BOTH_MINE})
        self.assertEqual(self._hosts("has_tags=true"), {OWN, BOTH_MINE})

    def test_location_body_withholds_tags_and_inherited_tags(self):
        foreign = self._location_row(FOREIGN)
        self.assertEqual(foreign["tags"], [])
        inherit = self._location_row(INHERIT)
        self.assertEqual(inherit["tags"], [])
        self.assertEqual(inherit["inherited_tags"], [])

    def test_location_body_still_serves_my_own_tags(self):
        self.assertEqual(self._location_row(OWN)["tags"], [OWN_TAG])

    def test_location_body_still_complete_for_a_superuser(self):
        self.assertEqual(
            self._location_row(INHERIT, self.admin_token)["inherited_tags"], [INHERITED_TAG],
        )

    def test_location_filters_do_not_match_a_foreign_tag(self):
        for query in (
            f"tags__name_exact={FOREIGN_TAG}",
            f"tags__name_contains={FOREIGN_TAG[:12]}",
            f"tags__name_starts_with={FOREIGN_TAG[:9]}",
            f"tags__name_ends_with={FOREIGN_TAG[-4:]}",
            f"tags__name_includes={FOREIGN_TAG}",
            f"tags__name_exact={INHERITED_TAG}",
        ):
            self.assertEqual(self._get(f"/api/v2/location/?{query}")["count"], 0, query)

    def test_location_filters_still_match_my_own_tags(self):
        for query in (
            f"tags__name_exact={OWN_TAG}",
            f"tags__name_contains={OWN_TAG[:12]}",
            f"tags__name_includes={OWN_TAG}",
        ):
            self.assertEqual(self._get(f"/api/v2/location/?{query}")["count"], 2, query)
