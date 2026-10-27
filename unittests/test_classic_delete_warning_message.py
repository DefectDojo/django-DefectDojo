"""
Regression tests: a Classic UI delete blocked by dependent rows warns with a sentence, not a tuple repr.

The user, environment and product attribute delete views put ``str(err)`` of a ``RestrictedError`` in their
warning. That is a Python tuple repr naming every referencing row, so a user referenced by many findings got a
very long banner listing them. The warning now counts them and names their kinds, the same sentence the API
answers a blocked delete with.
"""

from unittest.mock import patch

from django.contrib.messages import get_messages
from django.db.models.deletion import RestrictedError
from django.test import override_settings
from django.urls import reverse

from dojo.models import Development_Environment, Dojo_User, Finding, Product_Platform
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

BLOCKED = "It cannot be deleted while 2 other records still refer to it. Records that refer to it: finding."


def _blocked():
    return RestrictedError(
        "Cannot delete some instances of model 'X'",
        {Finding(id=1, title="secret finding one"), Finding(id=2, title="secret finding two")},
    )


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class ClassicDeleteWarningMessageTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.client.force_login(Dojo_User.objects.get(username="admin"))

    def _warning(self, response):
        warnings = [str(m) for m in get_messages(response.wsgi_request) if m.level_tag == "warning"]
        self.assertEqual(1, len(warnings), warnings)
        self.assertNotIn("secret", warnings[0])
        self.assertNotIn("<Finding", warnings[0])
        return warnings[0]

    def test_a_blocked_user_delete(self):
        user = Dojo_User.objects.create(username="blocked-user-for-delete")
        with patch.object(Dojo_User, "delete", side_effect=_blocked()):
            response = self.client.post(reverse("delete_user", args=(user.id,)), {"id": user.id})
        self.assertEqual(f"User cannot be deleted: {BLOCKED}", self._warning(response))

    def test_a_blocked_environment_delete(self):
        environment = Development_Environment.objects.create(name="Blocked Environment")
        with patch.object(Development_Environment, "delete", side_effect=_blocked()):
            response = self.client.post(
                reverse("edit_dev_env", args=(environment.id,)), {"delete_dev_env": "1", "id": environment.id},
            )
        self.assertEqual(f"Environment cannot be deleted: {BLOCKED}", self._warning(response))

    def test_a_blocked_product_attribute_delete(self):
        platform = Product_Platform.objects.create(name="Blocked Platform")
        with patch.object(Product_Platform, "delete", side_effect=_blocked()):
            response = self.client.post(
                reverse("edit_product_platform", args=(platform.id,)), {"delete_product_platform": "1"},
            )
        self.assertEqual(f"Platform cannot be deleted: {BLOCKED}", self._warning(response))
