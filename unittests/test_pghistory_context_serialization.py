"""
Regression: dispatching a Celery task while the active pghistory context holds a
non-JSON-serializable metadata value (e.g. a ``user`` set to a User *object*
instead of its pk) crashed dispatch with
``EncodeError: Object of type User is not JSON serializable``.

``get_serializable_pghistory_context`` must coerce metadata to JSON-safe values
so the injected ``_pgh_context`` can always be serialized by kombu.
"""

import pghistory
from kombu.utils.json import dumps as kombu_json_dumps

from dojo.auditlog.helpers import get_serializable_pghistory_context
from dojo.models import Dojo_User

from .dojo_test_case import DojoTestCase


class TestPghistoryContextSerialization(DojoTestCase):

    def setUp(self):
        super().setUp()
        self.user = Dojo_User.objects.create(username="pgh-ctx-serialize-user")

    def test_model_instance_in_context_metadata_is_coerced_to_pk(self):
        # A model instance in the context metadata must be reduced to its pk.
        with pghistory.context(user=self.user, url="/api/v2/products/1/"):
            ctx = get_serializable_pghistory_context()

        self.assertEqual(
            ctx["metadata"]["user"], self.user.pk,
            msg=f"expected user coerced to pk={self.user.pk}, got {ctx['metadata']['user']!r}",
        )

    def test_context_with_model_instance_is_kombu_serializable(self):
        # This is the exact operation Celery dispatch performs on the injected
        # `_pgh_context`; it raised EncodeError before the fix.
        with pghistory.context(user=self.user, url="/api/v2/products/1/"):
            ctx = get_serializable_pghistory_context()

        payload = {"kwargs": {"_pgh_context": ctx}}
        # Must not raise.
        kombu_json_dumps(payload)

    def test_nested_model_instance_is_coerced(self):
        with pghistory.context(actors=[self.user], details={"owner": self.user}):
            ctx = get_serializable_pghistory_context()

        self.assertEqual(ctx["metadata"]["actors"], [self.user.pk])
        self.assertEqual(ctx["metadata"]["details"], {"owner": self.user.pk})
        kombu_json_dumps({"kwargs": {"_pgh_context": ctx}})

    def test_plain_metadata_is_unchanged(self):
        # Control: already-serializable metadata (pk int, strings) passes through.
        with pghistory.context(user=self.user.pk, url="/x", remote_addr="1.2.3.4"):
            ctx = get_serializable_pghistory_context()

        self.assertEqual(ctx["metadata"]["user"], self.user.pk)
        self.assertEqual(ctx["metadata"]["url"], "/x")
        self.assertEqual(ctx["metadata"]["remote_addr"], "1.2.3.4")
        kombu_json_dumps({"kwargs": {"_pgh_context": ctx}})
