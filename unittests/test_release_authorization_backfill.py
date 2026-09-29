import importlib
from unittest.mock import patch

from django.db import connection
from django.db.migrations import RunPython
from django.db.migrations.loader import MigrationLoader

from dojo.models import Dojo_User

from .dojo_test_case import DojoTestCase

NAME = ("dojo", "0268_release_authorization_to_pro")
PREVIOUS = ("dojo", "0267_usercontactinfo_ui_use_tailwind")


class _SchemaEditor:

    """The part of a schema editor the backfill reads: its connection."""

    def __init__(self, conn):
        self.connection = conn


class TestReleaseAuthorizationBackfill(DojoTestCase):

    """The 0268 backfill derives user flags from global roles only when the roles are released."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.migration = importlib.import_module(f"dojo.db_migrations.{NAME[1]}")
        # The models as the backfill sees them: the state after 0267 plus the operations 0268
        # runs before its RunPython (the two authorized_users fields).
        loader = MigrationLoader(connection)
        state = loader.project_state(PREVIOUS)
        for operation in loader.get_migration(*NAME).operations:
            if isinstance(operation, RunPython):
                break
            operation.state_forwards("dojo", state)
        cls.state_apps = state.apps

    def setUp(self):
        role = self.state_apps.get_model("dojo", "Role")
        global_role = self.state_apps.get_model("dojo", "Global_Role")
        owner, _ = role.objects.get_or_create(name="Owner", defaults={"is_owner": True})
        writer, _ = role.objects.get_or_create(name="Writer")
        self.global_owner = Dojo_User.objects.create(username="backfill-global-owner")
        self.global_writer = Dojo_User.objects.create(username="backfill-global-writer")
        global_role.objects.create(user_id=self.global_owner.id, role=owner)
        global_role.objects.create(user_id=self.global_writer.id, role=writer)

    def _backfill(self, *, roles_kept):
        with patch.object(self.migration, "_role_tables_kept_by_installed_app", return_value=roles_kept):
            self.migration.backfill_authorized_users(self.state_apps, _SchemaEditor(connection))
        self.global_owner.refresh_from_db()
        self.global_writer.refresh_from_db()

    def test_global_roles_become_flags_when_the_roles_are_released(self):
        self._backfill(roles_kept=False)
        self.assertTrue(self.global_owner.is_superuser)
        self.assertTrue(self.global_writer.is_staff)

    def test_flags_are_unchanged_while_an_installed_app_keeps_the_roles(self):
        self._backfill(roles_kept=True)
        self.assertFalse(self.global_owner.is_superuser)
        self.assertFalse(self.global_owner.is_staff)
        self.assertFalse(self.global_writer.is_staff)
