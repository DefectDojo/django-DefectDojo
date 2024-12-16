import datetime
import logging
from unittest.mock import patch
from unittest import skip

from auditlog.context import set_actor
from crum import impersonate
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

import dojo.notifications.helper as notifications_helper
from dojo import __version__ as dd_version
from dojo.models import (
    DEFAULT_NOTIFICATION,
    Alerts,
    Dojo_User,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Notification_Webhooks,
    Notifications,
    Product,
    Product_Type,
    System_Settings,
    Test,
    Test_Type,
    User,
    get_current_datetime,
)
from dojo.notifications.helper import (
    create_notification,
    send_alert_notification,
    send_webhooks_notification,
    webhook_reactivation,
    webhook_status_cleanup,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestNotifications(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_merge_notifications_list(self):
        global_personal_notifications = Notifications(user=User.objects.get(username="admin"))
        personal_product_notifications = Notifications(user=User.objects.get(username="admin"), product=Product.objects.all()[0])

        global_personal_notifications.product_added = []
        global_personal_notifications.test_added = ''
        global_personal_notifications.scan_added = None
        global_personal_notifications.other = []

        global_personal_notifications.save()  # we have to save it and retrieve it because only then the fields get turned into lists...

        global_personal_notifications = Notifications.objects.get(id=global_personal_notifications.id)

        # print(vars(global_personal_notifications))

        personal_product_notifications.product_added = []
        personal_product_notifications.test_added = []
        personal_product_notifications.scan_added = None

        personal_product_notifications.save()

        personal_product_notifications = Notifications.objects.get(id=personal_product_notifications.id)

        merged_notifications = Notifications.merge_notifications_list([global_personal_notifications, personal_product_notifications])

        self.assertEqual("alert" in merged_notifications.product_added, False)
        self.assertEqual("mail" in merged_notifications.product_added, False)
        self.assertEqual("slack" in merged_notifications.product_added, False)
        self.assertEqual(len(merged_notifications.product_added), 0)

        self.assertEqual("alert" in merged_notifications.test_added, False)
        self.assertEqual("mail" in merged_notifications.test_added, False)
        self.assertEqual("slack" in merged_notifications.test_added, False)
        self.assertEqual(len(merged_notifications.test_added), 0)

        self.assertEqual("alert" in merged_notifications.scan_added, False)
        self.assertEqual("mail" in merged_notifications.scan_added, False)
        self.assertEqual("slack" in merged_notifications.scan_added, False)
        self.assertEqual(len(merged_notifications.scan_added), 0)

        self.assertEqual("alert" in merged_notifications.other, False)
        self.assertEqual("mail" in merged_notifications.other, False)
        self.assertEqual('slack' in merged_notifications.other, False)  # default alert from global
        self.assertEqual(len(merged_notifications.other), 1)
        self.assertEqual(merged_notifications.other, {''})
        # TODO: add unittest by default new settings

    @patch("dojo.notifications.helper.send_alert_notification", wraps=send_alert_notification)
    def test_notifications_system_level_trump(self, mock):
        notif_user, _ = Notifications.objects.get_or_create(user=User.objects.get(username="admin"))
        notif_system, _ = Notifications.objects.get_or_create(user=None, template=False)

        last_count = mock.call_count
        with self.subTest("user off, system off"):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count)

        last_count = mock.call_count
        with self.subTest("user off, system on"):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 1)

        # Small note for this test-cast: Trump works only in positive direction - system is not able to disable some kind of notification if user enabled it
        last_count = mock.call_count
        with self.subTest("user on, system off"):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 1)

        last_count = mock.call_count
        with self.subTest("user on, system on"):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 1)
        last_count = mock.call_count

    @patch("dojo.notifications.helper.send_alert_notification", wraps=send_alert_notification)
    def test_non_default_other_notifications(self, mock):
        notif_user, _ = Notifications.objects.get_or_create(user=User.objects.get(username="admin"))
        notif_system, _ = Notifications.objects.get_or_create(user=None, template=False)

        last_count = mock.call_count
        with self.subTest("do not notify other"):
            notif_user.other = ()  # no alert
            notif_user.save()
            create_notification(event="dummy_bar_event", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count)

        last_count = mock.call_count
        with self.subTest("notify other"):
            notif_user.other = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            create_notification(event="dummy_foo_event", title="title_for_dummy_foo_event", description="description_for_dummy_foo_event", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 1)
            self.assertEqual(mock.call_args_list[0].args[0], "dummy_foo_event")
            alert = Alerts.objects.get(title="title_for_dummy_foo_event")
            self.assertEqual(alert.source, "Dummy Foo Event")

        last_count = mock.call_count
        with self.subTest("user off, system off"):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 0)

        last_count = mock.call_count
        with self.subTest("user off, system on"):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 1)

        # Small note for this test-cast: Trump works only in positive direction - system is not able to disable some kind of notification if user enabled it
        last_count = mock.call_count
        with self.subTest("user on, system off"):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 1)

        last_count = mock.call_count
        with self.subTest("user on, system on"):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=["admin"])
            self.assertEqual(mock.call_count, last_count + 1)


class TestNotificationTriggers(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.notification_tester = Dojo_User.objects.get(username="admin")

    @patch("dojo.notifications.helper.process_notifications")
    def test_product_types(self, mock):

        last_count = mock.call_count
        with self.subTest("product_type_added"):
            with set_actor(self.notification_tester):
                prod_type = Product_Type.objects.create(name="notif prod type")
            self.assertEqual(mock.call_count, last_count + 4)
            self.assertEqual(mock.call_args_list[-1].args[0], "product_type_added")
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/product/type/{prod_type.id}")

        last_count = mock.call_count
        with self.subTest("product_type_deleted"):
            with set_actor(self.notification_tester):
                prod_type.delete()
            self.assertEqual(mock.call_count, last_count + 1)
            self.assertEqual(mock.call_args_list[-1].args[0], "product_type_deleted")
            self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The product type "notif prod type" was deleted by admin')
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], "/product/type")

    @patch("dojo.notifications.helper.process_notifications")
    def test_products(self, mock):

        last_count = mock.call_count
        with self.subTest("product_added"):
            with set_actor(self.notification_tester):
                prod_type = Product_Type.objects.first()
                prod, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name")
            self.assertEqual(mock.call_count, last_count + 5)
            self.assertEqual(mock.call_args_list[-1].args[0], "product_added")
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/product/{prod.id}")

        last_count = mock.call_count
        with self.subTest("product_deleted"):
            with set_actor(self.notification_tester):
                prod.delete()
            self.assertEqual(mock.call_count, last_count + 2)
            self.assertEqual(mock.call_args_list[-1].args[0], "product_deleted")
            self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The product "prod name" was deleted by admin')
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], "/product")

    @patch("dojo.notifications.helper.process_notifications")
    def test_engagements(self, mock):

        last_count = mock.call_count
        with self.subTest("engagement_added"):
            with set_actor(self.notification_tester):
                prod = Product.objects.first()
                eng = Engagement.objects.create(product=prod, target_start=timezone.now(), target_end=timezone.now())
            self.assertEqual(mock.call_count, last_count + 5)
            self.assertEqual(mock.call_args_list[-1].args[0], "engagement_added")
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/engagement/{eng.id}")

        last_count = mock.call_count
        with self.subTest("close_engagement"):
            with set_actor(self.notification_tester):
                eng.status = "Completed"
                eng.save()
            self.assertEqual(mock.call_count, last_count + 5)
            self.assertEqual(mock.call_args_list[-1].args[0], "engagement_closed")
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/engagement/{eng.id}/finding/all")

        last_count = mock.call_count
        with self.subTest("reopen_engagement"):
            with set_actor(self.notification_tester):
                eng.status = "In Progress"
                eng.save()
            self.assertEqual(mock.call_count, last_count + 5)
            self.assertEqual(mock.call_args_list[-1].args[0], "engagement_reopened")
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/engagement/{eng.id}")

        eng.status = "Not Started"
        eng.save()
        last_count = mock.call_count
        with self.subTest("no reopen_engagement from not started"):
            with set_actor(self.notification_tester):
                eng.status = "In Progress"
                eng.save()
            self.assertEqual(mock.call_count, last_count)

        prod_type = Product_Type.objects.first()
        prod1, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name 1")
        _ = Engagement.objects.create(product=prod1, target_start=timezone.now(), target_end=timezone.now(), lead=User.objects.get(username="admin"))
        prod2, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name 2")
        eng2 = Engagement.objects.create(product=prod2, name="Testing engagement", target_start=timezone.now(), target_end=timezone.now(), lead=User.objects.get(username="admin"))

        with self.subTest("engagement_deleted by product"):  # in case of product removal, we are not notifying about removal
            with set_actor(self.notification_tester):
                prod1.delete()
            for call in mock.call_args_list:
                self.assertNotEqual(call.args[0], "engagement_deleted")

        last_count = mock.call_count
        with self.subTest("engagement_deleted itself"):
            with set_actor(self.notification_tester):
                eng2.delete()
            self.assertEqual(mock.call_count, last_count + 1)
            self.assertEqual(mock.call_args_list[-1].args[0], "engagement_deleted")
            self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The engagement "Testing engagement" was deleted by admin')
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/product/{prod2.id}")

    @patch("dojo.notifications.helper.process_notifications")
    def test_endpoints(self, mock):
        prod_type = Product_Type.objects.first()
        prod1, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name 1")
        Endpoint.objects.get_or_create(product=prod1, host="host1")
        prod2, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name 2")
        endpoint2, _ = Endpoint.objects.get_or_create(product=prod2, host="host2")

        with self.subTest("endpoint_deleted by product"):  # in case of product removal, we are not notifying about removal
            with set_actor(self.notification_tester):
                prod1.delete()
            for call in mock.call_args_list:
                self.assertNotEqual(call.args[0], "endpoint_deleted")

        last_count = mock.call_count
        with self.subTest("endpoint_deleted itself"):
            with set_actor(self.notification_tester):
                endpoint2.delete()
            self.assertEqual(mock.call_count, last_count + 2)
            self.assertEqual(mock.call_args_list[-1].args[0], "endpoint_deleted")
            self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The endpoint "host2" was deleted by admin')
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], "/endpoint")

    @patch("dojo.notifications.helper.process_notifications")
    def test_tests(self, mock):
        prod_type = Product_Type.objects.first()
        prod, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name")
        eng1 = Engagement.objects.create(product=prod, target_start=timezone.now(), target_end=timezone.now(), lead=User.objects.get(username="admin"))
        Test.objects.create(engagement=eng1, target_start=timezone.now(), target_end=timezone.now(), test_type_id=Test_Type.objects.first().id)
        eng2 = Engagement.objects.create(product=prod, target_start=timezone.now(), target_end=timezone.now(), lead=User.objects.get(username="admin"))
        test2 = Test.objects.create(engagement=eng2, target_start=timezone.now(), target_end=timezone.now(), test_type_id=Test_Type.objects.first().id)

        with self.subTest("test_deleted by engagement"):  # in case of engagement removal, we are not notifying about removal
            with set_actor(self.notification_tester):
                eng1.delete()
            for call in mock.call_args_list:
                self.assertNotEqual(call.args[0], "test_deleted")

        last_count = mock.call_count
        with self.subTest("test_deleted itself"):
            with set_actor(self.notification_tester):
                test2.delete()
            self.assertEqual(mock.call_count, last_count + 1)
            self.assertEqual(mock.call_args_list[-1].args[0], "test_deleted")
            self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The test "Acunetix Scan" was deleted by admin')
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/engagement/{eng2.id}")

    @patch("dojo.notifications.helper.process_notifications")
    def test_finding_groups(self, mock):
        prod_type = Product_Type.objects.first()
        prod, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name")
        eng, _ = Engagement.objects.get_or_create(product=prod, target_start=timezone.now(), target_end=timezone.now(), lead=User.objects.get(username="admin"))
        test1, _ = Test.objects.get_or_create(engagement=eng, target_start=timezone.now(), target_end=timezone.now(), test_type_id=Test_Type.objects.first().id)
        Finding_Group.objects.get_or_create(test=test1, creator=User.objects.get(username="admin"))
        test2, _ = Test.objects.get_or_create(engagement=eng, target_start=timezone.now(), target_end=timezone.now(), test_type_id=Test_Type.objects.first().id)
        fg2, _ = Finding_Group.objects.get_or_create(test=test2, name="fg test", creator=User.objects.get(username="admin"))

        with self.subTest("test_deleted by engagement"):  # in case of engagement removal, we are not notifying about removal
            with set_actor(self.notification_tester):
                test1.delete()
            for call in mock.call_args_list:
                self.assertNotEqual(call.args[0], "finding_group_deleted")

        last_count = mock.call_count
        with self.subTest("test_deleted itself"):
            with set_actor(self.notification_tester):
                fg2.delete()
            self.assertEqual(mock.call_count, last_count + 5)
            self.assertEqual(mock.call_args_list[-1].args[0], "finding_group_deleted")
            self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The finding group "fg test" was deleted by admin')
            self.assertEqual(mock.call_args_list[-1].kwargs["url"], f"/test/{test2.id}")

    @patch("dojo.notifications.helper.process_notifications")
    @override_settings(ENABLE_AUDITLOG=True)
    def test_auditlog_on(self, mock):
        prod_type = Product_Type.objects.create(name="notif prod type")
        with set_actor(self.notification_tester):
            prod_type.delete()
        self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The product type "notif prod type" was deleted by admin')

    @patch("dojo.notifications.helper.process_notifications")
    @override_settings(ENABLE_AUDITLOG=False)
    def test_auditlog_off(self, mock):
        prod_type = Product_Type.objects.create(name="notif prod type")
        with set_actor(self.notification_tester):
            prod_type.delete()
        self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The product type "notif prod type" was deleted')


class TestNotificationTriggersApi(APITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    @patch("dojo.notifications.helper.process_notifications")
    @override_settings(ENABLE_AUDITLOG=True)
    def test_auditlog_on(self, mock):
        prod_type = Product_Type.objects.create(name="notif prod type API")
        self.client.delete(reverse("product_type-detail", args=(prod_type.pk,)), format="json")
        self.assertEqual(mock.call_args_list[-1].kwargs["description"], 'The product type "notif prod type API" was deleted by admin')


class TestNotificationWebhooks(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def run(self, result=None):
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.save()

        # unit tests are running without any user, which will result in actions like dedupe happening in the celery process
        # this doesn't work in unittests as unittests are using an in memory sqlite database and celery can't see the data
        # so we're running the test under the admin user context and set block_execution to True
        with impersonate(testuser):
            super().run(result)

    def setUp(self):
        self.sys_wh = Notification_Webhooks.objects.filter(owner=None).first()
        self.url_base = "http://webhook.endpoint:8080"

    def test_missing_system_webhook(self):
        # test data contains 2 entries but we need to test missing definition
        Notification_Webhooks.objects.all().delete()
        with self.assertLogs("dojo.notifications.helper", level="INFO") as cm:
            send_webhooks_notification(event="dummy")
        self.assertIn("URLs for Webhooks not configured: skipping system notification", cm.output[0])

    def test_missing_personal_webhook(self):
        # test data contains 2 entries but we need to test missing definition
        Notification_Webhooks.objects.all().delete()
        with self.assertLogs("dojo.notifications.helper", level="INFO") as cm:
            send_webhooks_notification(event="dummy", user=Dojo_User.objects.get(username="admin"))
        self.assertIn("URLs for Webhooks not configured for user '(admin)': skipping user notification", cm.output[0])

    def test_system_webhook_inactive(self):
        self.sys_wh.status = Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT
        self.sys_wh.save()
        with self.assertLogs("dojo.notifications.helper", level="INFO") as cm:
            send_webhooks_notification(event="dummy")
        self.assertIn("URL for Webhook 'My webhook endpoint' is not active: Permanently inactive (inactive_permanent)", cm.output[0])

    @skip("no inactive_temporary")
    def test_system_webhook_sucessful(self):
        with self.assertLogs("dojo.notifications.helper", level="DEBUG") as cm:
            send_webhooks_notification(event="dummy")
        self.assertIn("Message sent to endpoint 'My webhook endpoint' successfully.", cm.output[-1])

        updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
        self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_ACTIVE)
        self.assertIsNone(updated_wh.first_error)
        self.assertIsNone(updated_wh.last_error)

    @skip("no webhook_4xx")
    def test_system_webhook_4xx(self):
        self.sys_wh.url = f"{self.url_base}/status/400"
        self.sys_wh.save()

        with self.assertLogs("dojo.notifications.helper", level="ERROR") as cm:
            send_webhooks_notification(event="dummy", title="Dummy event")
        self.assertIn("Error when sending message to Webhooks 'My webhook endpoint' (status: 400)", cm.output[-1])

        updated_wh = Notification_Webhooks.objects.all().filter(owner=None).first()
        self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT)
        self.assertIsNotNone(updated_wh.first_error)
        self.assertEqual(updated_wh.first_error, updated_wh.last_error)

    @skip("no webhook_first_5xx")
    def test_system_webhook_first_5xx(self):
        self.sys_wh.url = f"{self.url_base}/status/500"
        self.sys_wh.save()

        with self.assertLogs("dojo.notifications.helper", level="ERROR") as cm:
            send_webhooks_notification(event="dummy", title="Dummy event")

        updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
        self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_INACTIVE_TMP)
        self.assertIsNotNone(updated_wh.first_error)
        self.assertEqual(updated_wh.first_error, updated_wh.last_error)
        self.assertEqual("Response status code: 500", updated_wh.note)
        self.assertIn("Error when sending message to Webhooks 'My webhook endpoint' (status: 500)", cm.output[-1])

    @skip("no 5xx_within_one_day")
    def test_system_webhook_second_5xx_within_one_day(self):
        ten_mins_ago = get_current_datetime() - datetime.timedelta(minutes=10)
        self.sys_wh.url = f"{self.url_base}/status/500"
        self.sys_wh.status = Notification_Webhooks.Status.STATUS_ACTIVE_TMP
        self.sys_wh.first_error = ten_mins_ago
        self.sys_wh.last_error = ten_mins_ago
        self.sys_wh.save()

        with self.assertLogs("dojo.notifications.helper", level="ERROR") as cm:
            send_webhooks_notification(event="dummy", title="Dummy event")

        updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
        self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_INACTIVE_TMP)
        self.assertEqual(updated_wh.first_error, ten_mins_ago)
        self.assertGreater(updated_wh.last_error, ten_mins_ago)
        self.assertEqual("Response status code: 500", updated_wh.note)
        self.assertIn("Error when sending message to Webhooks 'My webhook endpoint' (status: 500)", cm.output[-1])

    @skip("no 5xx_after_more_then_day")
    def test_system_webhook_third_5xx_after_more_then_day(self):
        now = get_current_datetime()
        day_ago = now - datetime.timedelta(hours=24, minutes=10)
        ten_minutes_ago = now - datetime.timedelta(minutes=10)
        self.sys_wh.url = f"{self.url_base}/status/500"
        self.sys_wh.status = Notification_Webhooks.Status.STATUS_ACTIVE_TMP
        self.sys_wh.first_error = day_ago
        self.sys_wh.last_error = ten_minutes_ago
        self.sys_wh.save()

        with self.assertLogs("dojo.notifications.helper", level="ERROR") as cm:
            send_webhooks_notification(event="dummy", title="Dummy event")

        updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
        self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT)
        self.assertEqual(updated_wh.first_error, day_ago)
        self.assertGreater(updated_wh.last_error, ten_minutes_ago)
        self.assertEqual("Response status code: 500", updated_wh.note)
        self.assertIn("Error when sending message to Webhooks 'My webhook endpoint' (status: 500)", cm.output[-1])

    def test_webhook_reactivation(self):
        with self.subTest("active"):
            wh = Notification_Webhooks.objects.filter(owner=None).first()
            webhook_reactivation(endpoint_id=wh.pk)

            updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
            self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_ACTIVE)
            self.assertIsNone(updated_wh.first_error)
            self.assertIsNone(updated_wh.last_error)
            self.assertIsNone(updated_wh.note)

        with self.subTest("inactive"):
            now = get_current_datetime()
            wh = Notification_Webhooks.objects.filter(owner=None).first()
            wh.status = Notification_Webhooks.Status.STATUS_INACTIVE_TMP
            wh.first_error = now
            wh.last_error = now
            wh.note = "Response status code: 418"
            wh.save()

            with self.assertLogs("dojo.notifications.helper", level="DEBUG") as cm:
                webhook_reactivation(endpoint_id=wh.pk)

            updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
            self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_ACTIVE_TMP)
            self.assertIsNotNone(updated_wh.first_error)
            self.assertEqual(updated_wh.first_error, updated_wh.last_error)
            self.assertEqual(updated_wh.note, "Response status code: 418")
            self.assertIn("Webhook endpoint 'My webhook endpoint' reactivated to 'active_tmp'", cm.output[-1])

    def test_webhook_status_cleanup(self):
        with self.subTest("active"):
            webhook_status_cleanup()

            updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
            self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_ACTIVE)
            self.assertIsNone(updated_wh.first_error)
            self.assertIsNone(updated_wh.last_error)
            self.assertIsNone(updated_wh.note)

        with self.subTest("active_tmp_new"):
            now = get_current_datetime()
            wh = Notification_Webhooks.objects.filter(owner=None).first()
            wh.status = Notification_Webhooks.Status.STATUS_ACTIVE_TMP
            wh.first_error = now
            wh.last_error = now
            wh.note = "Response status code: 503"
            wh.save()

            webhook_status_cleanup()

            updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
            self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_ACTIVE_TMP)
            self.assertIsNotNone(updated_wh.first_error)
            self.assertEqual(updated_wh.first_error, updated_wh.last_error)
            self.assertEqual(updated_wh.note, "Response status code: 503")

        with self.subTest("active_tmp_old"):
            day_ago = get_current_datetime() - datetime.timedelta(hours=24, minutes=10)
            wh = Notification_Webhooks.objects.filter(owner=None).first()
            wh.status = Notification_Webhooks.Status.STATUS_ACTIVE_TMP
            wh.first_error = day_ago
            wh.last_error = day_ago
            wh.note = "Response status code: 503"
            wh.save()

            with self.assertLogs("dojo.notifications.helper", level="DEBUG") as cm:
                webhook_status_cleanup()

            updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
            self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_ACTIVE)
            self.assertIsNone(updated_wh.first_error)
            self.assertIsNone(updated_wh.last_error)
            self.assertEqual(updated_wh.note, "Reactivation from active_tmp")
            self.assertIn("Webhook endpoint 'My webhook endpoint' reactivated from 'active_tmp' to 'active'", cm.output[-1])

        with self.subTest("inactive_tmp_new"):
            minute_ago = get_current_datetime() - datetime.timedelta(minutes=1)
            wh = Notification_Webhooks.objects.filter(owner=None).first()
            wh.status = Notification_Webhooks.Status.STATUS_INACTIVE_TMP
            wh.first_error = minute_ago
            wh.last_error = minute_ago
            wh.note = "Response status code: 503"
            wh.save()

            webhook_status_cleanup()

            updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
            self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_INACTIVE_TMP)
            self.assertEqual(updated_wh.first_error, minute_ago)
            self.assertEqual(updated_wh.last_error, minute_ago)
            self.assertEqual(updated_wh.note, "Response status code: 503")

        with self.subTest("inactive_tmp_old"):
            ten_minutes_ago = get_current_datetime() - datetime.timedelta(minutes=10)
            wh = Notification_Webhooks.objects.filter(owner=None).first()
            wh.status = Notification_Webhooks.Status.STATUS_INACTIVE_TMP
            wh.first_error = ten_minutes_ago
            wh.last_error = ten_minutes_ago
            wh.note = "Response status code: 503"
            wh.save()

            with self.assertLogs("dojo.notifications.helper", level="DEBUG") as cm:
                webhook_status_cleanup()

            updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
            self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_ACTIVE_TMP)
            self.assertEqual(updated_wh.first_error, ten_minutes_ago)
            self.assertEqual(updated_wh.last_error, ten_minutes_ago)
            self.assertEqual(updated_wh.note, "Response status code: 503")
            self.assertIn("Webhook endpoint 'My webhook endpoint' reactivated to 'active_tmp'", cm.output[-1])

    @skip("no timeout test")
    def test_system_webhook_timeout(self):
        self.sys_wh.url = f"{self.url_base}/delay/3"
        self.sys_wh.save()

        system_settings = System_Settings.objects.get()
        system_settings.webhooks_notifications_timeout = 1
        system_settings.save()

        with self.assertLogs("dojo.notifications.helper", level="ERROR") as cm:
            send_webhooks_notification(event="dummy", title="Dummy event")

        updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
        self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_INACTIVE_TMP)
        self.assertIsNotNone(updated_wh.first_error)
        self.assertEqual(updated_wh.first_error, updated_wh.last_error)
        self.assertIn("HTTPConnectionPool(host='webhook.endpoint', port=8080): Read timed out.", updated_wh.note)
        self.assertIn("Timeout when sending message to Webhook 'My webhook endpoint'", cm.output[-1])

    def test_system_webhook_wrong_fqdn(self):

        self.sys_wh.url = "http://non.existing.place"
        self.sys_wh.save()

        with self.assertLogs("dojo.notifications.helper", level="ERROR") as cm:
            send_webhooks_notification(event="dummy", title="Dummy event")

        updated_wh = Notification_Webhooks.objects.filter(owner=None).first()
        self.assertEqual(updated_wh.status, Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT)
        self.assertIsNotNone(updated_wh.first_error)
        self.assertEqual(updated_wh.first_error, updated_wh.last_error)
        self.assertIn("HTTPConnectionPool(host='non.existing.place', port=80): Max retries exceeded with url: /", updated_wh.note)
        self.assertIn("HTTPConnectionPool(host='non.existing.place', port=80): Max retries exceeded with url: /", cm.output[-1])

    @patch("requests.request", **{"return_value.status_code": 200})
    def test_headers(self, mock):
        Product_Type.objects.create(name="notif prod type")
        self.assertEqual(mock.call_args.kwargs["headers"], {
            "User-Agent": f"DefectDojo-{dd_version}",
            "X-DefectDojo-Event": "product_type_added",
            "X-DefectDojo-Instance": "http://localhost:8080",
            "Accept": "application/json",
            "Auth": "Token xxx",
        })

    @patch("requests.request", **{"return_value.status_code": 200})
    def test_events_messages(self, mock):
        with self.subTest("product_type_added"):
            prod_type = Product_Type.objects.create(name="notif prod type")
            self.assertEqual(mock.call_args.kwargs["headers"]["X-DefectDojo-Event"], "product_type_added")
            self.assertEqual(mock.call_args.kwargs["json"], {
                "description": None,
                "user": None,
                "url_api": f"http://localhost:8080/api/v2/product_types/{prod_type.pk}/",
                "url_ui": f"http://localhost:8080/product/type/{prod_type.pk}",
                "product_type": {
                    "id": prod_type.pk,
                    "name": "notif prod type",
                    "url_api": f"http://localhost:8080/api/v2/product_types/{prod_type.pk}/",
                    "url_ui": f"http://localhost:8080/product/type/{prod_type.pk}",
                },
            })

        with self.subTest("product_added"):
            prod = Product.objects.create(name="notif prod", prod_type=prod_type)
            self.assertEqual(mock.call_args.kwargs["headers"]["X-DefectDojo-Event"], "product_added")
            self.assertEqual(mock.call_args.kwargs["json"], {
                "description": None,
                "user": None,
                "url_api": f"http://localhost:8080/api/v2/products/{prod.pk}/",
                "url_ui": f"http://localhost:8080/product/{prod.pk}",
                "product_type": {
                    "id": prod_type.pk,
                    "name": "notif prod type",
                    "url_api": f"http://localhost:8080/api/v2/product_types/{prod_type.pk}/",
                    "url_ui": f"http://localhost:8080/product/type/{prod_type.pk}",
                },
                "product": {
                    "id": prod.pk,
                    "name": "notif prod",
                    "url_api": f"http://localhost:8080/api/v2/products/{prod.pk}/",
                    "url_ui": f"http://localhost:8080/product/{prod.pk}",
                },
            })

        with self.subTest("engagement_added"):
            eng = Engagement.objects.create(name="notif eng", product=prod, target_start=timezone.now(), target_end=timezone.now())
            self.assertEqual(mock.call_args.kwargs["headers"]["X-DefectDojo-Event"], "engagement_added")
            self.assertEqual(mock.call_args.kwargs["json"], {
                "description": None,
                "user": None,
                "url_api": f"http://localhost:8080/api/v2/engagements/{eng.pk}/",
                "url_ui": f"http://localhost:8080/engagement/{eng.pk}",
                "product_type": {
                    "id": prod_type.pk,
                    "name": "notif prod type",
                    "url_api": f"http://localhost:8080/api/v2/product_types/{prod_type.pk}/",
                    "url_ui": f"http://localhost:8080/product/type/{prod_type.pk}",
                },
                "product": {
                    "id": prod.pk,
                    "name": "notif prod",
                    "url_api": f"http://localhost:8080/api/v2/products/{prod.pk}/",
                    "url_ui": f"http://localhost:8080/product/{prod.pk}",
                },
                "engagement": {
                    "id": eng.pk,
                    "name": "notif eng",
                    "url_api": f"http://localhost:8080/api/v2/engagements/{eng.pk}/",
                    "url_ui": f"http://localhost:8080/engagement/{eng.pk}",
                },
            })

        with self.subTest("test_added"):
            test = Test.objects.create(title="notif test", engagement=eng, target_start=timezone.now(), target_end=timezone.now(), test_type_id=Test_Type.objects.first().id)
            notifications_helper.notify_test_created(test)
            self.assertEqual(mock.call_args.kwargs["headers"]["X-DefectDojo-Event"], "test_added")
            self.assertEqual(mock.call_args.kwargs["json"], {
                "description": None,
                "user": None,
                "url_api": f"http://localhost:8080/api/v2/tests/{test.pk}/",
                "url_ui": f"http://localhost:8080/test/{test.pk}",
                "product_type": {
                    "id": prod_type.pk,
                    "name": "notif prod type",
                    "url_api": f"http://localhost:8080/api/v2/product_types/{prod_type.pk}/",
                    "url_ui": f"http://localhost:8080/product/type/{prod_type.pk}",
                },
                "product": {
                    "id": prod.pk,
                    "name": "notif prod",
                    "url_api": f"http://localhost:8080/api/v2/products/{prod.pk}/",
                    "url_ui": f"http://localhost:8080/product/{prod.pk}",
                },
                "engagement": {
                    "id": eng.pk,
                    "name": "notif eng",
                    "url_api": f"http://localhost:8080/api/v2/engagements/{eng.pk}/",
                    "url_ui": f"http://localhost:8080/engagement/{eng.pk}",
                },
                "test": {
                    "id": test.pk,
                    "title": "notif test",
                    "url_api": f"http://localhost:8080/api/v2/tests/{test.pk}/",
                    "url_ui": f"http://localhost:8080/test/{test.pk}",
                },
            })

        with self.subTest("scan_added_empty"):
            notifications_helper.notify_scan_added(test, updated_count=0)
            self.assertEqual(mock.call_args.kwargs["headers"]["X-DefectDojo-Event"], "scan_added_empty")
            self.assertEqual(mock.call_args.kwargs["json"], {
                "description": None,
                "user": None,
                "url_api": f"http://localhost:8080/api/v2/tests/{test.pk}/",
                "url_ui": f"http://localhost:8080/test/{test.pk}",
                "product_type": {
                    "id": prod_type.pk,
                    "name": "notif prod type",
                    "url_api": f"http://localhost:8080/api/v2/product_types/{prod_type.pk}/",
                    "url_ui": f"http://localhost:8080/product/type/{prod_type.pk}",
                },
                "product": {
                    "id": prod.pk,
                    "name": "notif prod",
                    "url_api": f"http://localhost:8080/api/v2/products/{prod.pk}/",
                    "url_ui": f"http://localhost:8080/product/{prod.pk}",
                },
                "engagement": {
                    "id": eng.pk,
                    "name": "notif eng",
                    "url_api": f"http://localhost:8080/api/v2/engagements/{eng.pk}/",
                    "url_ui": f"http://localhost:8080/engagement/{eng.pk}",
                },
                "test": {
                    "id": test.pk,
                    "title": "notif test",
                    "url_api": f"http://localhost:8080/api/v2/tests/{test.pk}/",
                    "url_ui": f"http://localhost:8080/test/{test.pk}",
                },
                "finding_count": 0,
                "findings": {
                    "mitigated": [],
                    "new": [],
                    "reactivated": [],
                    "untouched": [],
                },
            })

        with self.subTest("scan_added"):
            notifications_helper.notify_scan_added(test,
                updated_count=4,
                new_findings=[
                    Finding.objects.create(test=test, title="New Finding", severity="Critical"),
                ],
                findings_mitigated=[
                    Finding.objects.create(test=test, title="Mitigated Finding", severity="Medium"),
                ],
                findings_reactivated=[
                    Finding.objects.create(test=test, title="Reactivated Finding", severity="Low"),
                ],
                findings_untouched=[
                    Finding.objects.create(test=test, title="Untouched Finding", severity="Info"),
                ],
            )
            self.assertEqual(mock.call_args.kwargs["headers"]["X-DefectDojo-Event"], "scan_added")
            self.maxDiff = None
            self.assertEqual(mock.call_args.kwargs["json"]["findings"], {
                "new": [{
                    "id": 233,
                    "title": "New Finding",
                    "severity": "Critical",
                    "url_api": "http://localhost:8080/api/v2/findings/233/",
                    "url_ui": "http://localhost:8080/finding/233",
                }],
                "mitigated": [{
                    "id": 234,
                    "title": "Mitigated Finding",
                    "severity": "Medium",
                    "url_api": "http://localhost:8080/api/v2/findings/234/",
                    "url_ui": "http://localhost:8080/finding/234",
                }],
                "reactivated": [{
                    "id": 235,
                    "title": "Reactivated Finding",
                    "severity": "Low",
                    "url_api": "http://localhost:8080/api/v2/findings/235/",
                    "url_ui": "http://localhost:8080/finding/235",
                }],
                "untouched": [{
                    "id": 236,
                    "title": "Untouched Finding",
                    "severity": "Info",
                    "url_api": "http://localhost:8080/api/v2/findings/236/",
                    "url_ui": "http://localhost:8080/finding/236",
                }],
            })
