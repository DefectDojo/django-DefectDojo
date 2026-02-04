from __future__ import annotations

import os
import secrets
import string
import uuid
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import BaseCommand, CommandError, call_command
from django.db import connection, connections
from django.db.utils import ProgrammingError

from dojo.auditlog import configure_pghistory_triggers
from dojo.models import Announcement, Dojo_User, UserAnnouncement


class Command(BaseCommand):
    help = "Initialize DefectDojo application state"

    def handle(self, *args: Any, **options: Any) -> None:
        if os.getenv("DD_INITIALIZE") == "false":
            self.stdout.write("Initialization skipped (DD_INITIALIZE=false)")
            return

        self.stdout.write("Initializing DefectDojo")

        self.check_enable_auditlog_consistency()
        self.warn_on_missing_migrations()

        self.stdout.write("Applying migrations")
        call_command("migrate", interactive=False)

        self.stdout.write("Configuring pghistory triggers")
        configure_pghistory_triggers()

        if self.admin_user_exists():
            self.stdout.write("Admin user already exists; skipping first-boot setup")
            self.create_announcement_banner()
            self.initialize_data()
            return

        self.ensure_admin_secrets()
        self.first_boot_setup()
        self.create_announcement_banner()
        self.initialize_data()

    # ------------------------------------------------------------------
    # Initialization steps
    # ------------------------------------------------------------------

    def initialize_data(self) -> None:
        self.stdout.write("Initializing test types")
        call_command("initialize_test_types")

        self.stdout.write("Initializing non-standard permissions")
        call_command("initialize_permissions")

    def create_announcement_banner(self) -> None:
        if os.getenv("DD_CREATE_CLOUD_BANNER"):
            return

        self.stdout.write("Creating announcement banner")

        announcement, _ = Announcement.objects.get_or_create(id=1)
        announcement.message = (
            '<a href="https://cloud.defectdojo.com/accounts/onboarding/plg_step_1" '
            'target="_blank">'
            "DefectDojo Pro Cloud and On-Premise Subscriptions Now Available! "
            "Create an account to try Pro for free!"
            "</a>"
        )
        announcement.dismissable = True
        announcement.save()

        for user in Dojo_User.objects.all():
            UserAnnouncement.objects.get_or_create(
                user=user,
                announcement=announcement,
            )

    # ------------------------------------------------------------------
    # Auditlog consistency
    # ------------------------------------------------------------------

    def check_enable_auditlog_consistency(self) -> None:
        self.stdout.write("Checking ENABLE_AUDITLOG consistency")

        try:
            with connections["default"].cursor() as cursor:
                try:
                    cursor.execute("SELECT * FROM dojo_system_settings LIMIT 1")
                except ProgrammingError as exc:
                    msg = str(exc)
                    if "does not exist" in msg or "doesn't exist" in msg:
                        self.stdout.write("Database not initialized yet; skipping auditlog check")
                        return
                    raise
                row = dict(zip([col[0] for col in cursor.description], cursor.fetchone(), strict=False))

        except Exception as exc:
            msg = f"Failed to read system settings from database: {exc}"
            raise CommandError(msg) from exc

        if not row.get("enable_auditlog", True) and settings.ENABLE_AUDITLOG:
            msg = "Auditlog disabled in DB but ENABLE_AUDITLOG=True. Set DD_ENABLE_AUDITLOG=False for all Django containers."
            raise CommandError(msg)

    # ------------------------------------------------------------------
    # Migration checks (warning only)
    # ------------------------------------------------------------------

    def warn_on_missing_migrations(self) -> None:
        self.stdout.write("Checking for missing migrations")

        try:
            call_command(
                "makemigrations",
                "--check",
                "--dry-run",
                verbosity=3,
            )
        except SystemExit:
            self.stderr.write(
                "\n"
                "********************************************************************************\n"
                "WARNING: Missing Database Migrations Detected\n"
                "********************************************************************************\n"
                "You made changes to models without creating migrations.\n\n"
                "Startup will continue, but you should fix this.\n"
                "********************************************************************************\n",
            )

    # ------------------------------------------------------------------
    # Admin / first boot
    # ------------------------------------------------------------------

    def admin_user_exists(self) -> bool:
        username = os.getenv("DD_ADMIN_USER")
        if not username:
            msg = "DD_ADMIN_USER is not set"
            raise CommandError(msg)

        User = get_user_model()
        return User.objects.filter(username=username).exists()

    def ensure_admin_secrets(self) -> None:
        if not os.getenv("DD_ADMIN_PASSWORD"):
            password = self.generate_password(22)
            os.environ["DD_ADMIN_PASSWORD"] = password
            self.stdout.write(f"Admin password: {password}")

        if not os.getenv("DD_JIRA_WEBHOOK_SECRET"):
            secret = str(uuid.uuid4())
            os.environ["DD_JIRA_WEBHOOK_SECRET"] = secret
            self.stdout.write(f"JIRA Webhook Secret: {secret}")

    def first_boot_setup(self) -> None:
        self.stdout.write("Running first boot setup")

        self.create_admin_user()
        self.load_initial_fixtures()
        self.persist_jira_webhook_secret()
        self.load_extra_fixtures()
        self.install_watson()
        call_command("migrate_textquestions")

    def create_admin_user(self) -> None:

        User = get_user_model()
        username = os.getenv("DD_ADMIN_USER")

        if User.objects.filter(username=username).exists():
            self.stdout.write(f"Admin user '{username}' already exists; skipping creation")
            return

        User.objects.create_superuser(
            username,
            os.getenv("DD_ADMIN_MAIL"),
            os.getenv("DD_ADMIN_PASSWORD"),
            first_name=os.getenv("DD_ADMIN_FIRST_NAME"),
            last_name=os.getenv("DD_ADMIN_LAST_NAME"),
        )

    # ------------------------------------------------------------------
    # Fixtures & setup
    # ------------------------------------------------------------------

    def load_initial_fixtures(self) -> None:
        self.stdout.write("Loading initial fixtures")
        call_command(
            "loaddata",
            "system_settings",
            "initial_banner_conf",
            "product_type",
            "test_type",
            "development_environment",
            "benchmark_type",
            "benchmark_category",
            "benchmark_requirement",
            "language_type",
            "objects_review",
            "regulation",
            "initial_surveys",
            "role",
            "sla_configurations",
        )

    def persist_jira_webhook_secret(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE dojo_system_settings SET jira_webhook_secret = %s",
                [os.getenv("DD_JIRA_WEBHOOK_SECRET")],
            )

    def load_extra_fixtures(self) -> None:
        for fixture in sorted(Path("dojo/fixtures").glob("extra_*.json")):
            self.stdout.write(f"Loading {fixture}")
            call_command("loaddata", fixture.stem)

    def install_watson(self) -> None:
        self.stdout.write("Installing watson search index")
        call_command("installwatson")

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def generate_password(self, length: int) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))
