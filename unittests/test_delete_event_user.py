# Regression: each delete notification looked up who deleted the object through DojoEvents, a UNION
# over every pghistory event table, so deleting one object read every event table in the database.
from unittest.mock import patch

import pghistory
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.auditlog.helpers import get_delete_event_user
from dojo.models import Endpoint, Engagement, Finding_Group, Product, Product_Type, Test, Test_Type
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v2


def event_tables_read(captured_queries):
    """The pghistory event tables named in ``captured_queries``."""
    event_tables = {model._meta.db_table for model in pghistory.core.event_models()}
    return {
        table
        for query in captured_queries
        for table in event_tables
        if f'"{table}"' in query["sql"]
    }


@override_settings(ENABLE_AUDITLOG=True)
class TestDeleteNotificationNamesDeleter(DojoTestCase):

    def setUp(self):
        self.deleter = get_user_model().objects.create(username="delete-signal-deleter")
        self.prod_type = Product_Type.objects.create(name="delete signal org")
        self.product = Product.objects.create(prod_type=self.prod_type, name="delete signal asset", description="d")
        self.engagement = Engagement.objects.create(
            product=self.product, name="delete signal engagement", target_start=timezone.now(), target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=self.engagement, test_type=Test_Type.objects.create(name="delete signal type"),
            target_start=timezone.now(), target_end=timezone.now(),
        )

    def delete_and_capture(self, obj, signal_module, event, *, as_deleter=True):
        """Delete ``obj`` and return (the ``event`` notification's description, the event tables read)."""
        with (
            patch(f"{signal_module}.create_notification") as notify,
            CaptureQueriesContext(connection) as queries,
        ):
            if as_deleter:
                with pghistory.context(user=self.deleter.id):
                    obj.delete()
            else:
                obj.delete()
        descriptions = [call.kwargs["description"] for call in notify.call_args_list if call.kwargs["event"] == event]
        self.assertEqual(len(descriptions), 1, msg=f"expected one {event} notification, got {notify.call_args_list}")
        return descriptions[0], event_tables_read(queries.captured_queries)

    def assert_lookup(self, obj, signal_module, event):
        own_table = pghistory.core.event_models(tracks_model=type(obj))[0]._meta.db_table
        description, tables = self.delete_and_capture(obj, signal_module, event)
        self.assertTrue(
            description.endswith(f" by {self.deleter}"),
            msg=f"expected the deleter named in the {event} notification, got {description!r}",
        )
        self.assertEqual(
            tables, {own_table},
            msg=f"the {event} lookup should read only {own_table}, it read {len(tables)} event tables: {sorted(tables)}",
        )

    def test_product_type(self):
        self.test.delete()
        self.engagement.delete()
        self.product.delete()
        self.assert_lookup(self.prod_type, "dojo.product_type.signals", "product_type_deleted")

    def test_product(self):
        self.test.delete()
        self.engagement.delete()
        self.assert_lookup(self.product, "dojo.product.signals", "product_deleted")

    def test_engagement(self):
        self.test.delete()
        self.assert_lookup(self.engagement, "dojo.engagement.signals", "engagement_deleted")

    def test_test(self):
        self.assert_lookup(self.test, "dojo.test.signals", "test_deleted")

    def test_finding_group(self):
        finding_group = Finding_Group.objects.create(test=self.test, name="delete signal group", creator=self.deleter)
        self.assert_lookup(finding_group, "dojo.finding_group.signals", "finding_group_deleted")

    def test_url(self):
        url = URL.get_or_create_from_values(host="delete-signal.example.com")
        self.assert_lookup(url, "dojo.url.signals", "url_deleted")

    # TODO: Delete this after the move to Locations
    @skip_unless_v2
    def test_endpoint(self):
        endpoint = Endpoint.objects.create(product=self.product, host="delete-signal.example.com")
        self.assert_lookup(endpoint, "dojo.endpoint.signals", "endpoint_deleted")

    def test_delete_without_a_user_names_nobody(self):
        description, tables = self.delete_and_capture(self.test, "dojo.test.signals", "test_deleted", as_deleter=False)
        self.assertNotIn(" by ", description)
        self.assertEqual(tables, {"dojo_testevent"})

    def test_event_query_has_no_limit(self):
        # ORDER BY pgh_id DESC LIMIT 1 makes Postgres walk the primary key backwards (the whole table when the
        # object has no delete event) instead of using the pgh_obj_id index.
        test_id = self.test.id
        with pghistory.context(user=self.deleter.id):
            self.test.delete()
        self.test.id = test_id
        with CaptureQueriesContext(connection) as queries:
            self.assertEqual(get_delete_event_user(self.test), self.deleter)
        event_queries = [q["sql"] for q in queries.captured_queries if '"dojo_testevent"' in q["sql"]]
        self.assertEqual(len(event_queries), 1, msg=event_queries)
        self.assertNotIn("LIMIT", event_queries[0].upper())

    def test_non_delete_event_with_a_user_names_nobody(self):
        # The author of a create or update is not the deleter: only the delete event counts.
        with pghistory.context(user=self.deleter.id):
            test = Test.objects.create(
                engagement=self.engagement, test_type=self.test.test_type,
                target_start=timezone.now(), target_end=timezone.now(),
            )
            test.title = "edited"
            test.save()
        labels_and_users = sorted(
            (event.pgh_label, event.pgh_context.metadata.get("user"))
            for event in apps.get_model("dojo", "TestEvent").objects.filter(pgh_obj_id=test.id)
        )
        self.assertEqual(labels_and_users, [("insert", self.deleter.id), ("update", self.deleter.id)])
        self.assertIsNone(get_delete_event_user(test))

    def test_untracked_model_runs_no_query(self):
        with self.assertNumQueries(0):
            self.assertIsNone(get_delete_event_user(Test_Type(id=1)))
