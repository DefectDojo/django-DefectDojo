"""A user's action history must show that user's own record, not every row they are named on."""
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.utils.timezone import now

from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase

# Finding.save() title-cases the title, so the description carries the sentinel.
FOREIGN_DESCRIPTION = "user-history-foreign-finding-description"


@override_settings(ENABLE_AUDITLOG=True)
class UserHistoryScopeTest(DojoTestCase):

    def setUp(self):
        self.victim = Dojo_User.objects.create(username="user_history_victim", is_staff=False)
        self.victim.set_password("pw")
        self.victim.save()

        prod_type = Product_Type.objects.create(name="user-history-pt")
        product = Product.objects.create(name="user-history-prod", prod_type=prod_type, description="p")
        engagement = Engagement.objects.create(
            name="user-history-eng", product=product, target_start=now(), target_end=now(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="user-history-tt")
        test = Test.objects.create(
            title="user-history-test", engagement=engagement, test_type=test_type,
            target_start=now(), target_end=now(),
        )
        Finding.objects.create(
            title="user history foreign finding", test=test, reporter=self.victim,
            severity="High", description=FOREIGN_DESCRIPTION,
        )

        self.caller = Dojo_User.objects.create(username="user_history_caller", is_staff=False, is_superuser=False)
        self.caller.set_password("pw")
        self.caller.save()
        self.caller.user_permissions.add(
            Permission.objects.get(codename="view_user", content_type__app_label="auth"),
        )

    def _history(self):
        content_type_id = ContentType.objects.get_for_model(self.victim).id
        self.client.force_login(self.caller)
        response = self.client.get(f"/history/{content_type_id}/{self.victim.id}")
        self.client.logout()
        return response

    def test_rows_the_caller_has_no_access_to_are_not_served(self):
        response = self._history()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(FOREIGN_DESCRIPTION, response.content.decode())

    def test_the_users_own_record_is_still_served(self):
        self.victim.first_name = "user-history-renamed"
        self.victim.save()

        response = self._history()
        self.assertEqual(response.status_code, 200)
        self.assertIn("user-history-renamed", response.content.decode())
