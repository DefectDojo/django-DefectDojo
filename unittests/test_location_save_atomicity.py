from django.urls import reverse

from dojo.authorization.roles_permissions import Roles
from dojo.location.models import Location, LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import (
    Dojo_User,
    Product,
    Product_Member,
    Product_Type,
    Role,
    User,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3


@skip_unless_v3
class LocationSaveAtomicityTest(DojoTestCase):

    """
    A save that fails validation must leave no part of itself behind.

    AbstractLocation.pre_save_logic() writes the parent Location row, and the base model
    runs it before full_clean(). A rejected endpoint rename told the user the edit failed
    while the Location row kept the new value, so the row summarised a URL it did not store.
    """

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="LOC-Atomic PT")

        cls.product_a = Product.objects.create(name="LOC-Atomic Product A", description="A", prod_type=prod_type)
        cls.product_b = Product.objects.create(name="LOC-Atomic Product B", description="B", prod_type=prod_type)

        # Legacy authorization is membership-based via authorized_users, so mirror the
        # Product_Member row onto that M2M.
        cls.alice = User.objects.create_user(
            username="loc_atomic_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        Product_Member.objects.create(
            user=cls.alice, product=cls.product_a, role=Role.objects.get(id=Roles.Writer),
        )
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        cls.own_url = "https://own.example.test/mine"
        cls.taken_url = "https://taken.example.test/admin"
        cls.location_a = cls.associate(cls.own_url, cls.product_a)
        cls.location_b = cls.associate(cls.taken_url, cls.product_b)

    @classmethod
    def associate(cls, value, product):
        location = URL.create_location_from_value(value).location
        LocationProductReference.objects.create(
            location=location, product=product, status=ProductLocationStatus.Active,
        )
        return location

    def setUp(self):
        super().setUp()
        self.client.force_login(self.alice)

    def rename(self, location, host, path):
        return self.client.post(
            reverse("edit_endpoint", kwargs={"location_id": location.id}),
            {"protocol": "https", "host": host, "path": path,
             "port": "", "user_info": "", "query": "", "fragment": "", "tags": ""},
        )

    def test_rejected_rename_leaves_both_rows_unchanged(self):
        response = self.rename(self.location_a, "taken.example.test", "admin")
        self.assertEqual(302, response.status_code)

        self.assertEqual(self.own_url, str(URL.objects.get(pk=self.location_a.url.pk)))
        self.assertEqual(self.own_url, Location.objects.get(pk=self.location_a.pk).location_value)
        self.assertEqual(self.taken_url, Location.objects.get(pk=self.location_b.pk).location_value)

    def test_accepted_rename_updates_both_rows(self):
        self.rename(self.location_a, "renamed.example.test", "ok")

        renamed = "https://renamed.example.test/ok"
        self.assertEqual(renamed, str(URL.objects.get(pk=self.location_a.url.pk)))
        self.assertEqual(renamed, Location.objects.get(pk=self.location_a.pk).location_value)
