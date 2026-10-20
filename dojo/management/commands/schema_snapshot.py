"""
Load a release's schema snapshot into an empty database instead of applying every migration.

Migrating an empty database from zero takes about two minutes on a CI runner, and every UI, k8s
and unit-test job used to do it. Each release now builds that schema once
(``scripts/build_schema_snapshot.sh``: migrate from zero on the oldest PostgreSQL it supports,
then ``pg_dump``) and adds it to the django image under ``/schema-snapshot/``. The initializer
loads it when, and only when, the database has no tables at all, then carries on exactly as
before: ``migrate`` applies whatever is newer than the snapshot (nothing, in the release's own
image), and first boot creates the admin and loads the initial fixtures, because the snapshot
holds no user. CI images carry the latest release's snapshot, so a CI job applies only the
migrations its branch added since that release.

An upgrade never sees the snapshot: a database that has any table is migrated as it always was.
So does DefectDojo Pro, whose initializer migrates before this one runs.

The snapshot lives outside ``/app`` so a bind mount of the repository over ``/app`` (the unit-test
compose setup) does not hide it, and apart from Pro's own schema dump (``/app/schema``).

The snapshot is skipped, with the reason logged, and the initializer migrates from zero when:

* the image has no snapshot (``DD_SCHEMA_SNAPSHOT_PATH`` set to empty turns it off too);
* its manifest is missing or unreadable;
* the manifest records a migration this code does not ship (a snapshot from a newer release, or
  a branch based on a ``dev`` older than the release), or a ``dojo`` migration file whose content
  differs from this code's copy (a released migration rewritten in place);
* the database server is older than the one the snapshot was made on.

The migrations that read a setting or the environment are safe to snapshot: the backfills (0250,
0257) find no rows on an empty database, 0156 and 0175 copy settings into System_Settings, which
first boot's ``system_settings`` fixture replaces whole, and 0027 and 0182 only set field choices.

``manage.py schema_snapshot --write-manifest FILE`` describes a migrated database for the
release, and refuses one that holds a user or an API token. ``--check FILE`` reports whether a
manifest fits this code, and ``--load`` runs the same load the initializer does.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder

from dojo import __version__

# Where the image carries the snapshot. Empty turns the fast path off.
SNAPSHOT_PATH_ENV_VAR = "DD_SCHEMA_SNAPSHOT_PATH"
DEFAULT_SNAPSHOT_PATH = "/schema-snapshot/migrated.sql"
MANIFEST_NAME = "manifest.json"
MANIFEST_FORMAT = 1

# Whose migration files must match the snapshot's byte for byte. Third-party apps change their
# migrations only with a new package version, and a removed one still fails the "ships" check.
DIGESTED_APPS = frozenset({"dojo"})

# Serializes concurrent initializers on one empty database: the second waits for the first to
# commit the snapshot, sees tables, and leaves the load to it. Any constant unique to this lock.
_LOAD_LOCK_KEY = 0x5D_0A_55_01

# Lines a plain pg_dump writes that only psql understands, or that only an extension's owner may
# run. The snapshot is executed over the application's own database connection (so its SSL
# options and managed databases work unchanged), not through psql, which the image does not have.
_SKIPPED_LINE_PREFIXES = (
    "\\",  # psql meta-commands: \restrict and \unrestrict
    "COMMENT ON EXTENSION",  # needs the extension's owner, which a managed database's user is not
)


def snapshot_path() -> Path | None:
    """The snapshot the image ships, or None when there is none or the fast path is off."""
    value = os.environ.get(SNAPSHOT_PATH_ENV_VAR, DEFAULT_SNAPSHOT_PATH).strip()
    if not value:
        return None
    path = Path(value)
    return path if path.is_file() else None


def disk_migrations() -> dict:
    """Every migration this code ships, keyed ``(app_label, name)``. Needs no database."""
    return MigrationLoader(None, ignore_no_migrations=True).disk_migrations


def known_migrations(migrations: dict) -> set[str]:
    """
    ``app.name`` of every shipped migration, and of every migration a shipped one replaces.

    Applying a squashed migration records the migrations it replaces as applied too, so a
    snapshot migrated through a squash lists names that no longer have a file.
    """
    known = {f"{app_label}.{name}" for app_label, name in migrations}
    for migration in migrations.values():
        known.update(f"{app_label}.{name}" for app_label, name in getattr(migration, "replaces", None) or ())
    return known


def migration_digests(migrations: dict) -> dict[str, str]:
    """SHA-256 of each migration file of ``DIGESTED_APPS``, keyed ``app.name``."""
    digests = {}
    for (app_label, name), migration in migrations.items():
        if app_label not in DIGESTED_APPS:
            continue
        source = getattr(sys.modules.get(type(migration).__module__), "__file__", None)
        if source:
            digests[f"{app_label}.{name}"] = hashlib.sha256(Path(source).read_bytes()).hexdigest()
    return digests


def build_manifest(migrations: dict, db=None) -> dict[str, Any]:
    """What a dump of the migrated database ``db`` holds."""
    db = db or connection
    return {
        "format": MANIFEST_FORMAT,
        "release": __version__,
        "postgres": db.pg_version,
        "applied": sorted(f"{app_label}.{name}" for app_label, name in MigrationRecorder(db).applied_migrations()),
        "digests": migration_digests(migrations),
    }


def manifest_problem(manifest: Any, migrations: dict, server_version: int | None = None) -> str | None:
    """Why a snapshot with ``manifest`` must not be loaded with this code, or None when it may."""
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        return "its manifest is not in a format this code reads"
    known = known_migrations(migrations)
    unknown = [entry for entry in manifest.get("applied", []) if entry not in known]
    if unknown:
        return f"it records {len(unknown)} migration(s) this code does not ship, starting with {unknown[0]}"
    current = migration_digests(migrations)
    changed = [
        entry for entry, digest in sorted(manifest.get("digests", {}).items()) if current.get(entry, digest) != digest
    ]
    if changed:
        return f"{len(changed)} migration file(s) differ from the snapshot's, starting with {changed[0]}"
    made_on = manifest.get("postgres")
    # Compared by major version: a plain dump loads into the same major version or a newer one.
    if server_version and isinstance(made_on, int) and server_version // 10000 < made_on // 10000:
        return f"it was made on PostgreSQL {made_on // 10000} and this server is PostgreSQL {server_version // 10000}"
    return None


def read_manifest(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def database_is_empty(db=None) -> bool:
    """True when the database has no table or view in its search path at all."""
    db = db or connection
    with db.cursor() as cursor:
        return not db.introspection.table_names(cursor, include_views=True)


def executable_sql(text: str) -> str:
    """The dump without the lines the application's connection cannot or must not run."""
    return "".join(line for line in text.splitlines(keepends=True) if not line.startswith(_SKIPPED_LINE_PREFIXES))


def load_schema_snapshot_if_empty(command: BaseCommand, db=None) -> bool:
    """
    Load the image's schema snapshot into an empty database. True when it was loaded.

    Touches no database when the image has no snapshot, and is silent on a database that has
    tables, which is every upgrade. Anything else that stops the load is reported, and the caller
    then migrates from zero exactly as it did before.
    """
    path = snapshot_path()
    if path is None:
        return False
    db = db or connection
    if not database_is_empty(db):
        return False
    manifest = read_manifest(path.parent / MANIFEST_NAME)
    problem = manifest_problem(manifest, disk_migrations(), db.pg_version)
    if problem:
        command.stdout.write(f"Not loading the schema snapshot at {path} because {problem}: applying every migration")
        return False

    release = manifest.get("release", "unknown")
    started = time.monotonic()
    sql = executable_sql(path.read_text(encoding="utf-8"))
    # One transaction, so a failure leaves the database empty and the next start can retry.
    with transaction.atomic(using=db.alias), db.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_LOAD_LOCK_KEY])
        if db.introspection.table_names(cursor, include_views=True):
            command.stdout.write("Another initializer loaded the schema snapshot while this one waited for it")
            return False
        command.stdout.write(f"Empty database: loading the schema snapshot of release {release} instead of every migration")
        # The raw driver cursor: Django's debug cursor would log the whole multi-megabyte statement.
        cursor.cursor.execute(sql)
    # The dump clears search_path for the session (set_config(..., false)); a fresh connection
    # gets the normal one back.
    db.close()
    command.stdout.write(
        f"Loaded the schema snapshot in {time.monotonic() - started:.1f}s "
        f"({len(manifest.get('applied', []))} migrations recorded as applied)",
    )
    return True


def deployment_data() -> dict[str, int]:
    """Rows a published snapshot must not hold, by kind, for the kinds that have any."""
    from rest_framework.authtoken.models import Token  # noqa: PLC0415 -- needs the app registry

    counts = {"users": get_user_model().objects.count(), "API tokens": Token.objects.count()}
    return {kind: count for kind, count in counts.items() if count}


class Command(BaseCommand):
    help = (
        "Describe a migrated database for the release's schema snapshot (--write-manifest), check whether a "
        "snapshot's manifest fits this code (--check), or load the image's snapshot into an empty database (--load)."
    )

    # The release runs this against a database that is only migrated, and --check and --load run before
    # the database holds anything: the system checks would read tables neither has filled.
    requires_system_checks = []

    def add_arguments(self, parser):
        action = parser.add_mutually_exclusive_group(required=True)
        action.add_argument("--write-manifest", metavar="FILE", help="Describe the migrated database in FILE.")
        action.add_argument(
            "--check", metavar="FILE", help="Exit non-zero unless the snapshot FILE describes fits this code.",
        )
        action.add_argument(
            "--load", action="store_true", help="Load the image's snapshot if the database has no tables.",
        )

    def handle(self, *args, **options):
        if options["load"]:
            load_schema_snapshot_if_empty(self)
        elif options["check"]:
            self.check_manifest(Path(options["check"]))
        else:
            self.write_manifest(Path(options["write_manifest"]))

    def check_manifest(self, path: Path) -> None:
        manifest = read_manifest(path)
        if manifest is None:
            msg = f"The schema snapshot manifest {path} could not be read"
            raise CommandError(msg)
        migrations = disk_migrations()
        if problem := manifest_problem(manifest, migrations):
            msg = f"The schema snapshot of release {manifest.get('release', 'unknown')} does not fit: {problem}"
            raise CommandError(msg)
        newer = len(known_migrations(migrations) - set(manifest.get("applied", [])))
        self.stdout.write(
            f"The schema snapshot of release {manifest.get('release', 'unknown')} fits this code: "
            f"{len(manifest.get('applied', []))} migrations recorded, at most {newer} newer to apply",
        )

    def write_manifest(self, path: Path) -> None:
        if held := deployment_data():
            msg = f"The database holds deployment data a published snapshot must not: {held}"
            raise CommandError(msg)
        manifest = build_manifest(disk_migrations())
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.stdout.write(
            f"Wrote {path}: {len(manifest['applied'])} applied migrations, {len(manifest['digests'])} migration file digests",
        )
