"""
The classic confirm() dialogs build a JavaScript string literal inside an HTML
``onclick`` attribute. The HTML parser decodes character references in an
attribute value before the handler is compiled, so HTML escaping alone lets a
stored apostrophe close the literal and run the rest of the name as script.

These tests render the pages with hostile Product / Product Type names and
assert the confirm() argument stays one unbroken string literal after the
browser's HTML decode step.
"""
import html
import re

from django.urls import reverse

from dojo.models import Dojo_User, Product, Product_Type
from unittests.dojo_test_case import DojoTestCase

BREAKOUT_NAMES = [
    "'+alert(1)+'",
    "');alert(1);('",
    "\\'+alert(1)+\\'",
    "O'Brien",
]

ONCLICK = re.compile(r'name="(?P<anchor>\w+)"[^>]*?onclick="(?P<handler>[^"]*)"', re.DOTALL)
CONFIRM_CALL = re.compile(r"^if \(confirm\('(?P<literal>[^']*)'\)\) \{ .*? \} return false;$")


class ConfirmDialogEscapingTestCase(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.staff = Dojo_User.objects.create(username="confirm_js_staff", is_staff=True)
        cls.member = Dojo_User.objects.create(username="confirm_js_member", is_active=True)
        cls.product_type = Product_Type.objects.create(name="confirm_js_pt")
        cls.product = Product.objects.create(
            name="confirm_js_product", description="x", prod_type=cls.product_type,
        )
        cls.product_type.authorized_users.add(cls.member)
        cls.product.authorized_users.add(cls.member)

    def assert_handler_intact(self, body, anchor_name, hostile_name):
        """The decoded handler must still be one confirm() call over one string literal."""
        handlers = [
            m.group("handler") for m in ONCLICK.finditer(body)
            if m.group("anchor") == anchor_name
        ]
        self.assertTrue(handlers, f"no {anchor_name} onclick rendered")
        for handler in handlers:
            decoded = html.unescape(handler)
            self.assertIsNotNone(
                CONFIRM_CALL.match(decoded),
                f"{anchor_name} handler broke out of the string literal for "
                f"{hostile_name!r}: {decoded}",
            )

    def test_view_user_product_type_revoke_dialog(self):
        self.client.force_login(self.staff)
        url = reverse("view_user", args=(self.member.id,))
        for name in BREAKOUT_NAMES:
            with self.subTest(name=name):
                Product_Type.objects.filter(pk=self.product_type.pk).update(name=name)
                body = self.client.get(url).content.decode()
                self.assert_handler_intact(body, "revokeProductType", name)

    def test_view_user_product_revoke_dialog(self):
        self.client.force_login(self.staff)
        url = reverse("view_user", args=(self.member.id,))
        for name in BREAKOUT_NAMES:
            with self.subTest(name=name):
                Product.objects.filter(pk=self.product.pk).update(name=name)
                body = self.client.get(url).content.decode()
                self.assert_handler_intact(body, "revokeProduct", name)

    def test_authorized_user_removal_dialogs_still_render(self):
        """The same refactor touches these two pages, so guard the render."""
        self.client.force_login(self.staff)
        for url_name, arg in (
            ("view_product", self.product.id),
            ("view_product_type", self.product_type.id),
        ):
            with self.subTest(page=url_name):
                body = self.client.get(reverse(url_name, args=(arg,))).content.decode()
                self.assert_handler_intact(body, "removeAuthorizedUser", "n/a")
