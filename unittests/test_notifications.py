from unittest.mock import patch

from crum import get_current_user
from django.utils import timezone

from dojo.models import DEFAULT_NOTIFICATION, Alerts, Engagement, Notifications, Product, Product_Type, User
from dojo.notifications.helper import create_notification, send_alert_notification

from .dojo_test_case import DojoTestCase


class TestNotifications(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def test_merge_notifications_list(self):
        global_personal_notifications = Notifications(user=User.objects.get(username='admin'))
        personal_product_notifications = Notifications(user=User.objects.get(username='admin'), product=Product.objects.all()[0])

        global_personal_notifications.product_added = ['alert']
        global_personal_notifications.test_added = ''
        global_personal_notifications.scan_added = None
        global_personal_notifications.other = ['slack', 'mail']

        global_personal_notifications.save()  # we have to save it and retrieve it because only then the fields get turned into lists...

        global_personal_notifications = Notifications.objects.get(id=global_personal_notifications.id)

        # print(vars(global_personal_notifications))

        personal_product_notifications.product_added = ['mail']
        personal_product_notifications.test_added = ['mail', 'alert']
        personal_product_notifications.scan_added = None
        # print(vars(personal_product_notifications))

        personal_product_notifications.save()

        personal_product_notifications = Notifications.objects.get(id=personal_product_notifications.id)

        # print(vars(personal_product_notifications))

        merged_notifications = Notifications.merge_notifications_list([global_personal_notifications, personal_product_notifications])

        # print(vars(merged_notifications))

        self.assertEqual('alert' in merged_notifications.product_added, True)
        self.assertEqual('mail' in merged_notifications.product_added, True)
        self.assertEqual('slack' in merged_notifications.product_added, False)
        self.assertEqual(len(merged_notifications.product_added), 2)

        self.assertEqual('alert' in merged_notifications.test_added, True)
        self.assertEqual('mail' in merged_notifications.test_added, True)
        self.assertEqual('slack' in merged_notifications.test_added, False)
        self.assertEqual(len(merged_notifications.test_added), 2)

        self.assertEqual('alert' in merged_notifications.scan_added, False)
        self.assertEqual('mail' in merged_notifications.scan_added, False)
        self.assertEqual('slack' in merged_notifications.scan_added, False)
        self.assertEqual(len(merged_notifications.scan_added), 0)

        self.assertEqual('alert' in merged_notifications.other, True)
        self.assertEqual('mail' in merged_notifications.other, True)
        self.assertEqual('slack' in merged_notifications.other, True)  # default alert from global
        self.assertEqual(len(merged_notifications.other), 3)
        self.assertEqual(merged_notifications.other, {'alert', 'mail', 'slack'})

    @patch('dojo.notifications.helper.send_alert_notification', wraps=send_alert_notification)
    def test_notifications_system_level_trump(self, mock):
        notif_user, _ = Notifications.objects.get_or_create(user=User.objects.get(username='admin'))
        notif_system, _ = Notifications.objects.get_or_create(user=None, template=False)

        last_count = 0
        with self.subTest('user off, system off'):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count)

        last_count = mock.call_count
        with self.subTest('user off, system on'):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count + 1)

        # Small note for this test-cast: Trump works only in positive direction - system is not able to disable some kind of notification if user enabled it
        last_count = mock.call_count
        with self.subTest('user on, system off'):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count + 1)

        last_count = mock.call_count
        with self.subTest('user on, system on'):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count + 1)
        last_count = mock.call_count

    @patch('dojo.notifications.helper.send_alert_notification', wraps=send_alert_notification)
    def test_non_default_other_notifications(self, mock):
        notif_user, _ = Notifications.objects.get_or_create(user=User.objects.get(username='admin'))
        notif_system, _ = Notifications.objects.get_or_create(user=None, template=False)

        last_count = 0
        with self.subTest('user off, system off'):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count + 0)

        last_count = mock.call_count
        with self.subTest('user off, system on'):
            notif_user.user_mentioned = ()  # no alert
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count + 1)

        # Small note for this test-cast: Trump works only in positive direction - system is not able to disable some kind of notification if user enabled it
        last_count = mock.call_count
        with self.subTest('user on, system off'):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = ()  # no alert
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count + 1)

        last_count = mock.call_count
        with self.subTest('user on, system on'):
            notif_user.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_user.save()
            notif_system.user_mentioned = DEFAULT_NOTIFICATION  # alert only
            notif_system.save()
            create_notification(event="user_mentioned", title="user_mentioned", recipients=['admin'])
            self.assertEqual(mock.call_count, last_count + 1)
        last_count = mock.call_count

    @patch('dojo.notifications.helper.send_alert_notification', wraps=send_alert_notification)
    def test_non_default_other_notifications(self, mock):
        notif, _ = Notifications.objects.get_or_create(user=User.objects.get(username='admin'))

        with self.subTest('do not notify other'):
            notif.other = ()  # no alert
            notif.save()
            create_notification(event="dummy_bar_event", recipients=['admin'])
            self.assertEqual(mock.call_count, 0)

        with self.subTest('notify other'):
            notif.other = DEFAULT_NOTIFICATION  # alert only
            notif.save()
            create_notification(event="dummy_foo_event", title="title_for_dummy_foo_event", description="description_for_dummy_foo_event", recipients=['admin'])
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(mock.call_args_list[0].args[0], 'dummy_foo_event')
            alert = Alerts.objects.get(title='title_for_dummy_foo_event')
            self.assertEqual(alert.source, "Dummy Foo Event")


class TestNotificationTriggers(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    @patch('dojo.notifications.helper.process_notifications')
    def test_products(self, mock):
        with self.subTest('product_added'):
            prod_type = Product_Type.objects.first()
            prod = Product.objects.create(prod_type=prod_type, name='prod name')
            self.assertEqual(mock.call_count, 5)
            self.assertEqual(mock.call_args_list[-1].args[0], 'product_added')

        with self.subTest('product_deleted'):
            prod.delete()
            self.assertEqual(mock.call_count, 7)
            self.assertEqual(mock.call_args_list[-1].args[0], 'product_deleted')
            self.assertEqual(mock.call_args_list[-1].kwargs['description'], f'The product "prod name" was deleted by {get_current_user()}')

    @patch('dojo.notifications.helper.process_notifications')
    def test_engagements(self, mock):
        with self.subTest('engagement_added'):
            prod = Product.objects.first()
            Engagement.objects.create(product=prod, target_start=timezone.now(), target_end=timezone.now())
            self.assertEqual(mock.call_count, 5)
            self.assertEqual(mock.call_args_list[-1].args[0], 'engagement_added')
