"""
Regression tests for per-product scoping of metadata and tags on a shared Location.

A Location row is deduplicated globally and referenced by every product that uses that
URL, so authorization for it succeeds for any one of those products. Metadata on that row
still belongs to the product that wrote it: a member of one product must not see, change
or remove another product's entries, and must not discard the tags another product set.
"""
from importlib import import_module

from django.apps import apps
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from dojo.authorization.models import Product_Member, Role
from dojo.endpoint.utils import endpoint_meta_import
from dojo.location.models import Location
from dojo.models import Dojo_User, DojoMeta, Product, Product_Type
from dojo.url.models import URL
from dojo.url.ui.forms import URLForm

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_permissions_audit import LegacyAuthMirrorMixin

PASSWORD = "testTEST1234!@#$"
HOST = "shared-location.example.test"
CSV = (
    "hostname,owner,slack_channel\n"
    f"{HOST},src-owner,#src-channel\n"
)


@skip_unless_v3
class TestSharedLocationMetaScoping(LegacyAuthMirrorMixin, DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.pt_src = Product_Type.objects.create(name="Shared Loc SRC PT")
        cls.pt_outside = Product_Type.objects.create(name="Shared Loc OUTSIDE PT")
        cls.product_src = Product.objects.create(
            name="Shared Loc Src Product", description="src", prod_type=cls.pt_src,
        )
        cls.product_outside = Product.objects.create(
            name="Shared Loc Outside Product", description="out", prod_type=cls.pt_outside,
        )
        cls.user = Dojo_User.objects.create_user(
            username="shared_loc_user", password=PASSWORD, is_active=True,
        )
        # Membership on the source product only; no membership on product_outside.
        Product_Member.objects.create(
            product=cls.product_src, user=cls.user, role=Role.objects.get(name="Owner"),
        )

        # One deduplicated Location, referenced by both products.
        cls.location = URL.get_or_create_from_values(
            protocol="https", host=HOST, path="admin",
        ).location
        cls.location.associate_with_product(cls.product_src)
        cls.location.associate_with_product(cls.product_outside)

        cls.outside_meta = DojoMeta.objects.create(
            location=cls.location, location_product=cls.product_outside,
            name="owner", value="outside-team",
        )
        cls.location.tags = ["outside-tag"]
        cls.location.save()

    def _meta(self, product):
        return dict(
            DojoMeta.objects.filter(location=self.location, location_product=product)
            .values_list("name", "value"),
        )

    def _tags(self):
        self.location.refresh_from_db()
        return {tag.name for tag in self.location.tags.all()}

    def _import_for_src(self):
        endpoint_meta_import(
            SimpleUploadedFile("meta.csv", CSV.encode(), content_type="text/csv"),
            self.product_src,
            create_endpoints=False,
            create_tags=True,
            create_meta=True,
            origin="API",
            object_class=Location,
        )

    def test_import_keeps_the_other_products_metadata(self):
        self._import_for_src()
        self.assertEqual(self._meta(self.product_outside), {"owner": "outside-team"})
        self.assertEqual(
            self._meta(self.product_src),
            {"owner": "src-owner", "slack_channel": "#src-channel"},
        )

    def test_import_does_not_write_tags_on_a_shared_location(self):
        self._import_for_src()
        self.assertEqual(self._tags(), {"outside-tag"})

    def test_import_still_writes_tags_when_the_location_is_not_shared(self):
        self.location.products.filter(product=self.product_outside).delete()
        self._import_for_src()
        self.assertIn("owner:src-owner", self._tags())

    def test_meta_data_form_hides_the_other_products_metadata(self):
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("edit_endpoint_meta_data", args=(self.location.id,)),
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "outside-team")

    def test_meta_data_form_cannot_change_the_other_products_metadata(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("edit_endpoint_meta_data", args=(self.location.id,)),
            {
                "form-TOTAL_FORMS": "1",
                "form-INITIAL_FORMS": "1",
                "form-MIN_NUM_FORMS": "0",
                "form-MAX_NUM_FORMS": "1000",
                "form-0-id": str(self.outside_meta.id),
                "form-0-name": "owner",
                "form-0-value": "changed",
                "form-0-DELETE": "on",
            },
        )
        self.assertIn(response.status_code, (200, 302))
        self.assertTrue(
            DojoMeta.objects.filter(id=self.outside_meta.id, value="outside-team").exists(),
            "the other product's metadata row was modified or deleted",
        )

    def test_endpoint_view_hides_the_other_products_metadata(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("view_endpoint", args=(self.location.id,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "outside-team")

    def test_backfill_copies_an_unscoped_row_to_every_product_on_the_location(self):
        migration = import_module("dojo.db_migrations.0289_dojometa_location_product")
        DojoMeta.objects.create(location=self.location, name="legacy", value="from-endpoints")
        migration.scope_location_meta_to_products(apps, None)
        self.assertEqual(self._meta(self.product_src).get("legacy"), "from-endpoints")
        self.assertEqual(self._meta(self.product_outside).get("legacy"), "from-endpoints")
        self.assertFalse(
            DojoMeta.objects.filter(location=self.location, location_product__isnull=True).exists(),
        )

    def test_adding_an_endpoint_does_not_clear_the_shared_tags(self):
        form = URLForm(data={
            "protocol": "https", "user_info": "", "host": HOST, "port": "",
            "path": "admin", "query": "", "fragment": "", "tags": "src-tag",
        })
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.assertEqual(self._tags(), {"outside-tag", "src-tag"})
