"""
The "added" notifications for a new product type, product or engagement go out once the creating transaction commits.

``async_create_notification`` loads the new row by id. Dispatched from ``post_save`` inside the creating
transaction, a worker could run it before the COMMIT, find no row and return without notifying anyone,
while the task still reported success. These tests commit for real, and at the moment a task is handed
to the broker they look for its row from a second database connection, as a worker would. A ``TestCase``
cannot show this: it runs each test in one transaction that never commits, so no other connection ever
sees its rows.
"""

import uuid
from unittest.mock import patch

import psycopg
from crum import impersonate
from django.db import connection, transaction
from django.test import SimpleTestCase
from django.utils import timezone

from dojo.models import Engagement, Product, Product_Type, User, UserContactInfo
from dojo.notifications.tasks import async_create_notification
from unittests.test_dedupe_delete_commit_race import _delete_rows_added_since, _high_water_marks

# The row each "added" event loads in the worker, and the task argument that names it.
ADDED_EVENTS = {
    "product_type_added": (Product_Type, "product_type_id"),
    "product_added": (Product, "product_id"),
    "engagement_added": (Engagement, "engagement_id"),
}


def _committed(model, pk):
    """Whether another connection, like the one a Celery worker uses, can see the row."""
    with psycopg.connect(**connection.get_connection_params(), autocommit=True) as other:
        query = f'SELECT EXISTS (SELECT 1 FROM "{model._meta.db_table}" WHERE id = %s)'
        return other.execute(query, [pk]).fetchone()[0]


class _RollbackError(Exception):
    pass


class TestAddedNotificationsWaitForCommit(SimpleTestCase):

    databases = {"default"}

    def setUp(self):
        super().setUp()
        # Registered first so it runs last: every row a test committed goes, history events included.
        self.addCleanup(_delete_rows_added_since, _high_water_marks())
        self.suffix = uuid.uuid4().hex[:12]
        # What reached the broker: (event, id of its row, whether that row was committed then).
        self.sent = []
        self.senders = []
        broker = patch.object(async_create_notification, "apply_async", side_effect=self._send)
        broker.start()
        self.addCleanup(broker.stop)

    def _send(self, args=None, kwargs=None, **options):
        model, id_kwarg = ADDED_EVENTS[kwargs["event"]]
        self.sent.append((kwargs["event"], kwargs[id_kwarg], _committed(model, kwargs[id_kwarg])))
        self.senders.append(kwargs.get("async_user_id"))

    def _product_type(self):
        return Product_Type.objects.create(name=f"On Commit PT {self.suffix}")

    def _product(self, product_type):
        return Product.objects.create(name=f"On Commit Product {self.suffix}", description="Test", prod_type=product_type)

    def _engagement(self, product):
        return Engagement.objects.create(
            name=f"On Commit Engagement {self.suffix}",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def test_product_type_added_is_sent_after_commit(self):
        with transaction.atomic():
            product_type = self._product_type()

        self.assertEqual(self.sent, [("product_type_added", product_type.id, True)])

    def test_product_added_is_sent_after_commit(self):
        product_type = self._product_type()
        self.sent.clear()

        with transaction.atomic():
            product = self._product(product_type)

        self.assertEqual(self.sent, [("product_added", product.id, True)])

    def test_engagement_added_is_sent_after_commit(self):
        product = self._product(self._product_type())
        self.sent.clear()

        with transaction.atomic():
            engagement = self._engagement(product)

        self.assertEqual(self.sent, [("engagement_added", engagement.id, True)])

    def test_rows_created_together_are_all_sent_after_commit(self):
        """One transaction creating all three, the way an import's auto-create can: three notifications, each row committed."""
        with transaction.atomic():
            product_type = self._product_type()
            product = self._product(product_type)
            engagement = self._engagement(product)

        self.assertEqual(self.sent, [
            ("product_type_added", product_type.id, True),
            ("product_added", product.id, True),
            ("engagement_added", engagement.id, True),
        ])

    def test_a_savepoint_waits_for_the_outer_commit(self):
        with transaction.atomic():
            with transaction.atomic():
                product_type = self._product_type()
            self.assertEqual(self.sent, [], "sent when the savepoint was released, before the COMMIT")

        self.assertEqual(self.sent, [("product_type_added", product_type.id, True)])

    def test_autocommit_sends_before_create_returns(self):
        product_type = self._product_type()
        self.assertEqual(self.sent, [("product_type_added", product_type.id, True)])

    def test_rollback_sends_nothing(self):
        with self.assertRaises(_RollbackError), transaction.atomic():
            self._product_type()
            raise _RollbackError

        self.assertEqual(self.sent, [])

    def test_task_runs_as_the_user_who_created_the_row(self):
        """The user is taken when the row is saved, so a commit after the request's user context has ended still names them."""
        user = User.objects.create(username=f"on_commit_{self.suffix}")

        # The user context closes first, then the transaction commits.
        with transaction.atomic(), impersonate(user):
            self._product_type()

        self.assertEqual(self.senders, [user.id])


class TestForegroundAddedNotificationsWaitForCommit(SimpleTestCase):

    """A user with block_execution runs the task inline: it too waits for the COMMIT, and still runs before create returns in autocommit."""

    databases = {"default"}

    def setUp(self):
        super().setUp()
        self.addCleanup(_delete_rows_added_since, _high_water_marks())
        self.suffix = uuid.uuid4().hex[:12]
        self.user = User.objects.create(username=f"on_commit_fg_{self.suffix}")
        UserContactInfo.objects.create(user=self.user, block_execution=True)
        # What the task body passed on: (event, id of the product type, whether it was committed then).
        self.delivered = []
        self.delivery_error = None
        deliver = patch("dojo.notifications.helper.create_notification", side_effect=self._deliver)
        deliver.start()
        self.addCleanup(deliver.stop)

    def _deliver(self, event=None, **kwargs):
        product_type = kwargs["product_type"]
        self.delivered.append((event, product_type.id, _committed(Product_Type, product_type.id)))
        if self.delivery_error is not None:
            raise self.delivery_error

    def test_runs_after_commit(self):
        with impersonate(self.user), transaction.atomic():
            product_type = Product_Type.objects.create(name=f"On Commit FG PT {self.suffix}")
            self.assertEqual(self.delivered, [], "ran inside the transaction, before the COMMIT")

        self.assertEqual(self.delivered, [("product_type_added", product_type.id, True)])

    def test_autocommit_runs_before_create_returns(self):
        with impersonate(self.user):
            product_type = Product_Type.objects.create(name=f"On Commit FG PT {self.suffix}")
            self.assertEqual(self.delivered, [("product_type_added", product_type.id, True)])

    def test_a_failing_notification_does_not_fail_the_committed_write(self):
        """The row is committed when the task raises: the error is logged, the caller gets none and later hooks still run."""
        self.delivery_error = RuntimeError("mail down")
        later_hooks = []

        with (
            self.assertLogs("django.db.backends.base", level="ERROR") as logged,
            impersonate(self.user),
            transaction.atomic(),
        ):
            product_type = Product_Type.objects.create(name=f"On Commit FG PT {self.suffix}")
            transaction.on_commit(lambda: later_hooks.append("ran"))

        self.assertEqual(self.delivered, [("product_type_added", product_type.id, True)])
        self.assertEqual(later_hooks, ["ran"])
        self.assertTrue(_committed(Product_Type, product_type.id))
        self.assertIn("mail down", "\n".join(logged.output))

    def test_a_failing_notification_in_autocommit_does_not_fail_the_create(self):
        self.delivery_error = RuntimeError("mail down")

        with self.assertLogs("django.db.backends.base", level="ERROR"), impersonate(self.user):
            product_type = Product_Type.objects.create(name=f"On Commit FG PT {self.suffix}")

        self.assertEqual(self.delivered, [("product_type_added", product_type.id, True)])
        self.assertTrue(_committed(Product_Type, product_type.id))
