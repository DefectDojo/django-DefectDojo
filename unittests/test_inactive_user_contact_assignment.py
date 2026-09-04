from crum import impersonate
from django.test import override_settings
from django.urls import reverse
from rest_framework import serializers

from dojo.authorization.serializer_guards import CONTACT_FIELDS, ActiveUserContactGuardMixin
from dojo.models import Dojo_User, Product, Product_Type, User
from dojo.product.ui.forms import ProductForm
from unittests.dojo_test_case import DojoAPITestCase, DojoTestCase, versioned_fixtures


@override_settings(SECURE_SSL_REDIRECT=False)
@versioned_fixtures
class InactiveUserContactAssignmentTest(DojoAPITestCase):

    """
    An inactive account is a historical reference, so it cannot be picked up as a
    new contact. Every assignment that already exists keeps working, including a
    payload that echoes it back, which is what a full PUT and the Vue form's PATCH
    both do.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="IUC PT")
        cls.product = Product.objects.create(
            name="IUC Product",
            description="product for inactive-contact tests",
            prod_type=cls.prod_type,
        )
        cls.active_user = Dojo_User.objects.get(
            pk=User.objects.create_user(
                username="iuc_active",
                password="not-a-real-secret",  # noqa: S106 - test fixture user
                is_active=True,
            ).pk,
        )
        cls.inactive_user = Dojo_User.objects.get(
            pk=User.objects.create_user(
                username="iuc_inactive",
                password="not-a-real-secret",  # noqa: S106 - test fixture user
                is_active=False,
            ).pk,
        )
        cls.product_url = reverse("product-detail", args=[cls.product.id])
        cls.product_list_url = reverse("product-list")
        cls.asset_url = reverse("asset-detail", args=[cls.product.id])

    def setUp(self):
        super().setUp()
        self.login_as_admin()
        # setUpTestData runs once; each test starts from a clean row.
        Product.objects.filter(pk=self.product.pk).update(
            product_manager=None, technical_contact=None, team_manager=None,
        )

    def _patch(self, url, payload):
        return self.client.patch(url, payload, format="json")

    def test_product_rejects_inactive_product_manager(self):
        response = self._patch(self.product_url, {"product_manager": self.inactive_user.pk})
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertIn("product_manager", response.json())
        self.assertIn("iuc_inactive", str(response.json()["product_manager"]))
        self.product.refresh_from_db()
        self.assertIsNone(self.product.product_manager_id)

    def test_product_rejects_inactive_technical_contact(self):
        response = self._patch(self.product_url, {"technical_contact": self.inactive_user.pk})
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertIn("technical_contact", response.json())

    def test_product_rejects_inactive_team_manager(self):
        response = self._patch(self.product_url, {"team_manager": self.inactive_user.pk})
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertIn("team_manager", response.json())

    def test_product_accepts_active_contacts(self):
        response = self._patch(self.product_url, {
            "product_manager": self.active_user.pk,
            "technical_contact": self.active_user.pk,
            "team_manager": self.active_user.pk,
        })
        self.assertEqual(200, response.status_code, response.content[:400])
        self.product.refresh_from_db()
        self.assertEqual(self.active_user.pk, self.product.product_manager_id)

    def test_product_create_rejects_inactive_contact(self):
        response = self.client.post(self.product_list_url, {
            "name": "IUC Created Product",
            "description": "created with an inactive contact",
            "prod_type": self.prod_type.pk,
            "product_manager": self.inactive_user.pk,
        }, format="json")
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertFalse(Product.objects.filter(name="IUC Created Product").exists())

    def test_product_replaying_an_existing_inactive_contact_is_allowed(self):
        # The assignment predates the deactivation. A payload that echoes it is not
        # a new assignment, and rejecting it would orphan a historical reference.
        Product.objects.filter(pk=self.product.pk).update(product_manager=self.inactive_user)
        response = self._patch(self.product_url, {"product_manager": self.inactive_user.pk})
        self.assertEqual(200, response.status_code, response.content[:400])
        self.product.refresh_from_db()
        self.assertEqual(self.inactive_user.pk, self.product.product_manager_id)

    def test_product_can_clear_an_inactive_contact(self):
        Product.objects.filter(pk=self.product.pk).update(product_manager=self.inactive_user)
        response = self._patch(self.product_url, {"product_manager": None})
        self.assertEqual(200, response.status_code, response.content[:400])
        self.product.refresh_from_db()
        self.assertIsNone(self.product.product_manager_id)

    def test_product_cannot_swap_one_inactive_contact_for_another_field(self):
        # Holding an inactive user on product_manager does not license the same user
        # on a different field: that is a new assignment.
        Product.objects.filter(pk=self.product.pk).update(product_manager=self.inactive_user)
        response = self._patch(self.product_url, {"team_manager": self.inactive_user.pk})
        self.assertEqual(400, response.status_code, response.content[:400])

    def test_asset_rejects_inactive_asset_manager(self):
        response = self._patch(self.asset_url, {"asset_managers": self.inactive_user.pk})
        self.assertEqual(400, response.status_code, response.content[:400])
        # Keyed by the name the client sent, not by the underlying model field.
        self.assertIn("asset_managers", response.json())

    def test_asset_rejects_inactive_technical_contact(self):
        response = self._patch(self.asset_url, {"technical_contact": self.inactive_user.pk})
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertIn("technical_contact", response.json())

    def test_asset_replaying_an_existing_inactive_asset_manager_is_allowed(self):
        Product.objects.filter(pk=self.product.pk).update(product_manager=self.inactive_user)
        response = self._patch(self.asset_url, {"asset_managers": self.inactive_user.pk})
        self.assertEqual(200, response.status_code, response.content[:400])

    def test_asset_accepts_active_asset_manager(self):
        response = self._patch(self.asset_url, {"asset_managers": self.active_user.pk})
        self.assertEqual(200, response.status_code, response.content[:400])
        self.product.refresh_from_db()
        self.assertEqual(self.active_user.pk, self.product.product_manager_id)

    def test_deactivating_a_user_leaves_the_assignment_in_place(self):
        response = self._patch(self.product_url, {"product_manager": self.active_user.pk})
        self.assertEqual(200, response.status_code, response.content[:400])

        User.objects.filter(pk=self.active_user.pk).update(is_active=False)

        self.product.refresh_from_db()
        self.assertEqual(self.active_user.pk, self.product.product_manager_id)

        # The historical reference still reads back over the API.
        read = self.client.get(self.product_url)
        self.assertEqual(200, read.status_code, read.content[:400])
        self.assertEqual(self.active_user.pk, read.json()["product_manager"])

    def test_an_unrelated_edit_still_works(self):
        response = self._patch(self.product_url, {"description": "edited"})
        self.assertEqual(200, response.status_code, response.content[:400])


def _all_model_serializers():
    found, stack = set(), [serializers.ModelSerializer]
    while stack:
        for sub in stack.pop().__subclasses__():
            if sub not in found:
                found.add(sub)
                stack.append(sub)
    return found


def _writable_contact_fields(ser):
    """The contact fields this serializer class writes, by model field name."""
    meta = getattr(ser, "Meta", None)
    if getattr(meta, "model", None) is not Product:
        return set()

    writable = set()

    # A declared field can rename the column, which is how AssetSerializer reaches
    # product_manager under the name asset_managers.
    declared_sources = set()
    for name, field in ser._declared_fields.items():
        source = field.source or name
        declared_sources.add(source)
        if source in CONTACT_FIELDS and not field.read_only:
            writable.add(source)

    declared_meta = getattr(meta, "fields", None)
    excluded = tuple(getattr(meta, "exclude", ()) or ())
    read_only = tuple(getattr(meta, "read_only_fields", ()) or ())
    for model_field in CONTACT_FIELDS:
        if model_field in declared_sources or model_field in excluded or model_field in read_only:
            continue
        if declared_meta is None or declared_meta == "__all__" or model_field in declared_meta:
            writable.add(model_field)
    return writable


class ContactGuardCoverageTest(DojoAPITestCase):

    def test_every_serializer_writing_a_contact_field_carries_the_guard(self):
        """
        Fails on a newly added serializer that forgets the guard, rather than
        leaving a gap for a support report to find. A serializer that only reads
        these fields declares them read_only and is skipped.
        """
        reverse("asset-detail", args=[1])  # force the URLconf, and so every viewset module, to load

        unguarded = []
        for ser in _all_model_serializers():
            fields = _writable_contact_fields(ser)
            if fields and not issubclass(ser, ActiveUserContactGuardMixin):
                unguarded.append(f"{ser.__module__}.{ser.__name__} writes {sorted(fields)}")

        self.assertEqual(
            [], sorted(unguarded),
            "these serializers write a contact field without the active-user guard; "
            "add ActiveUserContactGuardMixin, exclude the field, or mark it read_only",
        )


@versioned_fixtures
class ProductFormInactiveContactTest(DojoTestCase):

    """
    The edit form's dropdowns list active users only, which is the rule this story
    is about. But a form whose queryset excludes the instance's own value renders
    it unselected and saves None, so opening and saving an untouched asset deletes
    the contact. The current value stays selectable; nothing else joins the list.
    """

    fixtures = ["dojo_testdata.json"]

    def run(self, result=None):
        # ProductForm.__init__ narrows prod_type through get_authorized_product_types,
        # which reads the acting user from crum. Without a user, Pro's registered auth
        # filter returns nothing and every form in this class fails on prod_type.
        with impersonate(self.get_test_admin()):
            super().run(result)

    def setUp(self):
        super().setUp()
        self.prod_type = Product_Type.objects.create(name="IUC Form PT")
        self.inactive_user = Dojo_User.objects.get(
            pk=User.objects.create_user(
                username="iuc_form_inactive",
                password="not-a-real-secret",  # noqa: S106 - test fixture user
                is_active=False,
            ).pk,
        )
        self.product = Product.objects.create(
            name="IUC Form Product",
            description="product for form tests",
            prod_type=self.prod_type,
            technical_contact=self.inactive_user,
        )

    def _post_data(self, **overrides):
        data = {
            "name": self.product.name,
            "description": self.product.description,
            "prod_type": self.prod_type.pk,
            "sla_configuration": self.product.sla_configuration_id,
            "technical_contact": self.inactive_user.pk,
        }
        data.update(overrides)
        return data

    def test_current_inactive_contact_stays_in_the_queryset(self):
        form = ProductForm(instance=self.product)
        self.assertIn(
            self.inactive_user.pk,
            form.fields["technical_contact"].queryset.values_list("pk", flat=True),
        )

    def test_saving_an_untouched_form_keeps_the_inactive_contact(self):
        form = ProductForm(data=self._post_data(), instance=self.product)
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.product.refresh_from_db()
        self.assertEqual(self.inactive_user.pk, self.product.technical_contact_id)

    def test_a_different_inactive_user_is_still_refused(self):
        other = Dojo_User.objects.get(
            pk=User.objects.create_user(
                username="iuc_form_other",
                password="not-a-real-secret",  # noqa: S106 - test fixture user
                is_active=False,
            ).pk,
        )
        form = ProductForm(data=self._post_data(technical_contact=other.pk), instance=self.product)
        self.assertFalse(form.is_valid())
        self.assertIn("technical_contact", form.errors)

    def test_an_inactive_user_is_refused_on_a_new_product(self):
        form = ProductForm(data={
            "name": "IUC Form New",
            "description": "new",
            "prod_type": self.prod_type.pk,
            "technical_contact": self.inactive_user.pk,
        })
        self.assertFalse(form.is_valid())
        self.assertIn("technical_contact", form.errors)
