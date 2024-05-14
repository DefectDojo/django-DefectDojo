from .dojo_test_case import DojoTestCase
from dojo.models import Product, User, Notifications


class TestNotifications(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def test_merge_notifications_list(self):
        global_personal_notifications = Notifications(user=User.objects.get(username='admin'))
        personal_product_notifications = Notifications(user=User.objects.get(username='admin'), product=Product.objects.all()[0])

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
        # print(vars(personal_product_notifications))

        personal_product_notifications.save()

        personal_product_notifications = Notifications.objects.get(id=personal_product_notifications.id)

        # print(vars(personal_product_notifications))

        merged_notifications = Notifications.merge_notifications_list([global_personal_notifications, personal_product_notifications])

        # print(vars(merged_notifications))

        self.assertEqual('alert' in merged_notifications.product_added, False)
        self.assertEqual('mail' in merged_notifications.product_added, False)
        self.assertEqual('slack' in merged_notifications.product_added, False)
        self.assertEqual(len(merged_notifications.product_added), 0)

        self.assertEqual('alert' in merged_notifications.test_added, False)
        self.assertEqual('mail' in merged_notifications.test_added, False)
        self.assertEqual('slack' in merged_notifications.test_added, False)
        self.assertEqual(len(merged_notifications.test_added), 0)

        self.assertEqual('alert' in merged_notifications.scan_added, False)
        self.assertEqual('mail' in merged_notifications.scan_added, False)
        self.assertEqual('slack' in merged_notifications.scan_added, False)
        self.assertEqual(len(merged_notifications.scan_added), 0)

        self.assertEqual('alert' in merged_notifications.other, False)
        self.assertEqual('mail' in merged_notifications.other, False)
        self.assertEqual('slack' in merged_notifications.other, False)  # default alert from global
        self.assertEqual(len(merged_notifications.other), 1)
        self.assertEqual(merged_notifications.other, {''})
        # TODO: add unittest by default new settings
