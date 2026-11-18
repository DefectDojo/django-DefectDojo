"""
Regression: creating a finding with ``found_by`` could deadlock against a bulk delete of that finding.

``Finding.save()`` adds the test's type to ``found_by`` and commits, then the create's ``found_by.set()``
deletes that row (when it was not requested) and inserts the requested ones. Those rows stayed locked until
COMMIT, where Postgres takes FOR KEY SHARE on the finding to check their deferred foreign key. The chunked bulk
delete locks the finding FOR UPDATE first and deletes its found_by rows after, so the two waited on each other
and Postgres aborted one with "deadlock detected" (40P01).

The fix locks the finding FOR KEY SHARE at the start of the found_by write, the order the delete uses. These
tests pin that the create writes found_by through that helper, that the helper's first statement is the lock,
and that found_by still ends up as requested. The race itself needs two connections committing for real.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now
from rest_framework.test import APIClient

from dojo.finding import services
from dojo.finding.api import serializer as serializer_module
from dojo.finding.api.serializer import set_found_by_locking_finding_first
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type

FOUND_BY_TABLE = Finding.found_by.through._meta.db_table


def _is_finding_key_share_lock(sql):
    return f'FROM "{Finding._meta.db_table}"' in sql and sql.rstrip().endswith("FOR KEY SHARE")


def _writes_found_by(sql):
    # Inside a request pghistory prefixes each write with its context ("SELECT set_config(...); DELETE ..."),
    # so the write is matched anywhere in the statement, not only at its start.
    return f'DELETE FROM "{FOUND_BY_TABLE}"' in sql or f'INSERT INTO "{FOUND_BY_TABLE}"' in sql


@override_settings(SECURE_SSL_REDIRECT=False)
class TestFindingCreateFoundByLockOrder(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_superuser("found-by-lock-admin", "admin@example.com", "pw")
        cls.scan_type = Test_Type.objects.create(name="found-by-lock-scan")
        cls.requested_type = Test_Type.objects.create(name="found-by-lock-requested")
        product = Product.objects.create(
            name="found-by-lock product", description="d",
            prod_type=Product_Type.objects.create(name="found-by-lock type"),
        )
        engagement = Engagement.objects.create(product=product, target_start=now(), target_end=now())
        cls.test = Test.objects.create(
            engagement=engagement, test_type=cls.scan_type, target_start=now(), target_end=now(),
        )

    def _found_by_statements(self, ctx):
        """The statements from the finding's key-share lock to the end of the found_by writes, in order."""
        statements = [query["sql"] for query in ctx.captured_queries]
        start = next((index for index, sql in enumerate(statements) if _is_finding_key_share_lock(sql)), None)
        self.assertIsNotNone(start, msg=f"the finding is never locked FOR KEY SHARE: {statements}")
        return statements, start

    def test_create_writes_found_by_through_the_locking_helper(self):
        client = APIClient()
        client.force_authenticate(user=self.admin)
        payload = {
            "test": self.test.id,
            "title": "found by lock order",
            "severity": "High",
            "description": "d",
            "numerical_severity": "S1",
            "active": True,
            "verified": False,
            "found_by": [self.requested_type.id],
        }

        with patch(
            "dojo.finding.api.serializer.set_found_by_locking_finding_first",
            wraps=serializer_module.set_found_by_locking_finding_first,
        ) as helper:
            response = client.post("/api/v2/findings/", payload, format="json")

        self.assertEqual(201, response.status_code, response.content[:1000])
        helper.assert_called_once()
        created = Finding.objects.get(pk=response.data["id"])
        self.assertEqual(helper.call_args[0][0].pk, created.pk)
        # The test's own type, added by Finding.save(), is replaced by what was requested.
        self.assertEqual(list(created.found_by.values_list("id", flat=True)), [self.requested_type.id])

    def test_helper_locks_first_and_sets_exactly_what_was_given(self):
        finding = Finding.objects.create(
            test=self.test, title="found by helper", severity="High", numerical_severity="S1", reporter=self.admin,
        )
        finding.found_by.set([self.scan_type])

        with CaptureQueriesContext(connection) as ctx:
            set_found_by_locking_finding_first(finding, [self.requested_type])

        statements, lock_index = self._found_by_statements(ctx)
        first_write = next(index for index, sql in enumerate(statements) if _writes_found_by(sql))
        self.assertLess(lock_index, first_write, msg=f"the finding must be locked before found_by: {statements}")
        self.assertEqual(list(finding.found_by.values_list("id", flat=True)), [self.requested_type.id])


@override_settings(SECURE_SSL_REDIRECT=False)
class TestFindingFoundByWritersLockOrder(TestCase):

    """
    The other API writers of an existing finding's found_by take the same lock first.

    The v3 create (``services.create_finding``), the v3 update (``services.update_finding``) and the v2 update
    (``FindingSerializer.update``) each replace found_by with ``set()`` in its own transaction, so each deadlocked
    against a bulk delete exactly as the v2 create did. Each test pins that the writer's first statement on the
    found_by table comes after the finding's FOR KEY SHARE lock, and that found_by ends up as requested.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_superuser("found-by-writers-admin", "admin@example.com", "pw")
        cls.scan_type = Test_Type.objects.create(name="found-by-writers-scan")
        cls.requested_type = Test_Type.objects.create(name="found-by-writers-requested")
        product = Product.objects.create(
            name="found-by-writers product", description="d",
            prod_type=Product_Type.objects.create(name="found-by-writers type"),
        )
        engagement = Engagement.objects.create(product=product, target_start=now(), target_end=now())
        cls.test = Test.objects.create(
            engagement=engagement, test_type=cls.scan_type, target_start=now(), target_end=now(),
        )

    def _finding(self):
        finding = Finding.objects.create(
            test=self.test, title="found by writer", severity="High", numerical_severity="S1", reporter=self.admin,
        )
        self.assertEqual(list(finding.found_by.values_list("id", flat=True)), [self.scan_type.id])
        return finding

    def assert_locked_before_found_by_write(self, ctx):
        """
        The finding's FOR KEY SHARE lock comes before set()'s writes: the DELETE of the row that was not requested
        and the INSERT of the requested type. On a create, Finding.save()'s own add of the test's type comes
        earlier still; that plain insert holds no row the delete waits for, so it is not what this pins.
        """
        statements = [query["sql"] for query in ctx.captured_queries]
        set_writes = [
            index for index, sql in enumerate(statements)
            if f'DELETE FROM "{FOUND_BY_TABLE}"' in sql
            or (f'INSERT INTO "{FOUND_BY_TABLE}"' in sql and f", {self.requested_type.id})" in sql)
        ]
        self.assertTrue(set_writes, msg=f"set() never writes found_by: {statements}")
        locks = [index for index, sql in enumerate(statements[:set_writes[0]]) if _is_finding_key_share_lock(sql)]
        self.assertTrue(locks, msg=f"the finding must be locked FOR KEY SHARE before found_by: {statements}")

    def test_v3_create_locks_the_finding_before_found_by(self):
        with CaptureQueriesContext(connection) as ctx:
            created = services.create_finding(test=self.test, user=self.admin, data={
                "title": "v3 found by lock", "severity": "High", "description": "d",
                "active": True, "verified": False, "found_by": [self.requested_type.id],
            })

        self.assert_locked_before_found_by_write(ctx)
        self.assertEqual(list(created.found_by.values_list("id", flat=True)), [self.requested_type.id])

    def test_v3_update_locks_the_finding_before_found_by(self):
        finding = self._finding()

        with CaptureQueriesContext(connection) as ctx:
            services.update_finding(finding, changes={"found_by": [self.requested_type.id]}, user=self.admin)

        self.assert_locked_before_found_by_write(ctx)
        self.assertEqual(list(finding.found_by.values_list("id", flat=True)), [self.requested_type.id])

    def test_v2_update_locks_the_finding_before_found_by(self):
        finding = self._finding()
        client = APIClient()
        client.force_authenticate(user=self.admin)

        with CaptureQueriesContext(connection) as ctx:
            response = client.patch(
                f"/api/v2/findings/{finding.id}/", {"found_by": [self.requested_type.id]}, format="json",
            )

        self.assertEqual(200, response.status_code, response.content[:1000])
        self.assert_locked_before_found_by_write(ctx)
        self.assertEqual(list(finding.found_by.values_list("id", flat=True)), [self.requested_type.id])
