"""
Behaviour settings an instance can keep in its System Settings instead of the environment.

Each name in ``SETTING_FIELDS`` is a Django setting (filled from a ``DD_*`` environment
variable) with a nullable twin on ``System_Settings``. :func:`get_setting` returns the stored
value when there is one and the deployment's setting otherwise, so an instance that never saved
a value behaves exactly as before, and the environment stays the default.

Read these settings through :func:`get_setting` (or ``dojo.utils.get_setting``, which calls it),
never as ``settings.NAME``: the System Settings row is per database, so a deployment that serves
several databases gets each one's own value.

The two per-scanner maps (``HASHCODE_FIELDS_PER_SCANNER`` and
``DEDUPLICATION_ALGORITHM_PER_PARSER``) store overrides, not a whole map: the stored entries
replace or add to the deployment's map, the way ``DD_HASHCODE_FIELDS_PER_SCANNER`` and
``DD_DEDUPLICATION_ALGORITHM_PER_PARSER`` do. Changing either one does not recompute hash codes
already stored; run ``manage.py dedupe --hash_code_only`` for the scan types it names.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from functools import wraps
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import Http404
from django.utils.translation import gettext as translate

if TYPE_CHECKING:
    from collections.abc import Callable

# Django setting -> System_Settings field. None stored in the field means "use the setting".
SETTING_FIELDS = {
    "EDITABLE_MITIGATED_DATA": "editable_mitigated_data",
    "DISABLE_FINDING_MERGE": "disable_finding_merge",
    "TRACK_IMPORT_HISTORY": "track_import_history",
    "DELETE_PREVIEW": "delete_preview",
    "DUPLICATE_CLUSTER_CASCADE_DELETE": "duplicate_cluster_cascade_delete",
    "USE_FIRST_SEEN": "use_first_seen",
    "USE_QUALYS_LEGACY_SEVERITY_PARSING": "qualys_legacy_severity_parsing",
    "QUALYS_WAS_UNIQUE_ID": "qualys_was_unique_id",
    "QUALYS_WAS_WEAKNESS_IS_VULN": "qualys_was_weakness_is_vuln",
    "SONARQUBE_API_PARSER_HOTSPOTS": "sonarqube_api_parser_hotspots",
    "JIRA_WEBHOOK_ALLOW_FINDING_GROUP_REOPEN": "jira_webhook_allow_finding_group_reopen",
    "ALERT_REFRESH": "alert_refresh",
    "DISABLE_ALERT_COUNTER": "disable_alert_counter",
    "MAX_ALERTS_PER_USER": "max_alerts_per_user",
    "NOTIFICATION_SCAN_ADDED_MAX_FINDINGS": "notification_scan_added_max_findings",
    "NOTIFICATIONS_SYSTEM_LEVEL_TRUMP": "notifications_system_level_trump",
    "SLA_NOTIFY_PRE_BREACH": "sla_notify_pre_breach",
    "SLA_NOTIFY_POST_BREACH": "sla_notify_post_breach",
    "HASHCODE_FIELDS_PER_SCANNER": "hashcode_fields_per_scanner",
    "DEDUPLICATION_ALGORITHM_PER_PARSER": "deduplication_algorithm_per_parser",
    "LANGUAGE_CODE": "default_language_code",
    "API_TOKENS_ENABLED": "api_tokens_enabled",
    "API_TOKEN_AUTH_ENDPOINT_ENABLED": "api_token_auth_endpoint_enabled",
    "API_TOKEN_DEFAULT_EXPIRY_DAYS": "api_token_default_expiry_days",
    "AUDITLOG_FLUSH_RETENTION_PERIOD": "auditlog_flush_retention_period",
    "JIRA_SSL_VERIFY": "jira_ssl_verify",
    "JIRA_CONNECT_TIMEOUT": "jira_connect_timeout",
    "JIRA_READ_TIMEOUT": "jira_read_timeout",
    "JIRA_MAX_RETRIES": "jira_max_retries",
    "JIRA_DESCRIPTION_MAX_LENGTH": "jira_description_max_length",
}

# Settings whose stored value is merged over the deployment's map instead of replacing it.
MERGED_SETTINGS = frozenset({"HASHCODE_FIELDS_PER_SCANNER", "DEDUPLICATION_ALGORITHM_PER_PARSER"})

# Settings that already moved to a System_Settings field: the field is the only source, and the
# setting is no longer read (FEATURE_FINDING_GROUPS seeded enable_finding_groups; TEAM_NAME is
# the default team_name shows when the field is blank).
FIELD_ONLY = {
    "FEATURE_FINDING_GROUPS": "enable_finding_groups",
}

#: What a resolver returns for a name it does not hold a value for.
NOT_RESOLVED = object()

# Resolvers an installed app registers (register_setting_resolver) for settings it keeps somewhere
# other than System Settings, for example a value an operator stores for each database. Consulted,
# in registration order, for every name outside SETTING_FIELDS and FIELD_ONLY.
_resolvers: list[Callable[[str], object]] = []

# One merged map per setting, rebuilt only when the stored overrides object changes. Holding the
# overrides object keeps its id from being reused, so an identity check is enough.
_merged: dict[str, tuple[object, object, dict]] = {}


def _system_settings():
    from dojo.models import System_Settings  # noqa: PLC0415 circular import

    return System_Settings.objects.get()


def _merge(name: str, base: dict, overrides: dict) -> dict:
    cached = _merged.get(name)
    if cached is not None and cached[0] is overrides and cached[1] is base:
        return cached[2]
    merged = {**base, **overrides}
    _merged[name] = (overrides, base, merged)
    return merged


def register_setting_resolver(resolver: Callable[[str], object]) -> None:
    """
    Let an installed app answer :func:`get_setting` for names it holds a value for.

    ``resolver(name)`` returns the value, or :data:`NOT_RESOLVED` to leave the name to the next
    resolver and finally to the Django setting. Registering the same resolver twice is a no-op.
    """
    if resolver not in _resolvers:
        _resolvers.append(resolver)


def unregister_setting_resolver(resolver: Callable[[str], object]) -> None:
    if resolver in _resolvers:
        _resolvers.remove(resolver)


# A batch that reads the same setting once per row (a bulk save firing each row's signals) pins them:
# inside pinned_settings() each name is resolved once, on first use, and reused until the block ends.
_pinned = threading.local()


@contextmanager
def pinned_settings():
    """
    Resolve each behaviour setting at most once for the enclosed batch.

    The per-request settings cache is reset at every task boundary, and a task run inline (an eager
    Celery task inside a bulk save) would otherwise make every row re-read System Settings. A batch runs
    for one instance (one tenant), so one value per name is right for all of its rows. Nested blocks share
    the outer block's values.
    """
    outer = getattr(_pinned, "values", None)
    _pinned.values = {} if outer is None else outer
    try:
        yield
    finally:
        _pinned.values = outer


def get_setting(name: str):
    """Return the instance's value for ``name``: its System Settings field, else the setting."""
    values = getattr(_pinned, "values", None)
    if values is None:
        return _resolve(name)
    if name not in values:
        values[name] = _resolve(name)
    return values[name]


def _resolve(name: str):
    field = FIELD_ONLY.get(name)
    if field is not None:
        return getattr(_system_settings(), field)
    field = SETTING_FIELDS.get(name)
    if field is None:
        for resolver in _resolvers:
            value = resolver(name)
            if value is not NOT_RESOLVED:
                return value
        return getattr(settings, name)
    value = getattr(_system_settings(), field, None)
    if value is None or (isinstance(value, str) and not value):
        return getattr(settings, name)
    if name in MERGED_SETTINGS:
        return _merge(name, getattr(settings, name), value)
    return value


def require_settings(*names: str):
    """
    Answer 404 unless every named behaviour setting is on for this instance.

    For a route that used to be mounted only when a deployment setting was on: the route is now
    always mounted, and this asks the setting per request, so each database (each tenant) gets its own.
    """

    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if not all(get_setting(name) for name in names):
                raise Http404
            return view(request, *args, **kwargs)

        return wrapped

    return decorator


def jira_timeout() -> tuple:
    """The Jira client's (connect, read) timeout: this instance's, else DD_JIRA_CONNECT/READ_TIMEOUT."""
    row = _system_settings()
    if row.jira_connect_timeout is None and row.jira_read_timeout is None:
        # Nothing saved: the deployment's pair, which an operator may also set as JIRA_TIMEOUT directly.
        return getattr(settings, "JIRA_TIMEOUT", (settings.JIRA_CONNECT_TIMEOUT, settings.JIRA_READ_TIMEOUT))
    return (get_setting("JIRA_CONNECT_TIMEOUT"), get_setting("JIRA_READ_TIMEOUT"))


DEFAULT_JIRA_ISSUE_TYPES = (
    ("Task", "Task"),
    ("Story", "Story"),
    ("Epic", "Epic"),
    ("Spike", "Spike"),
    ("Bug", "Bug"),
    ("Security", "Security"),
)


def jira_issue_type_choices() -> tuple:
    """
    The issue types a Jira configuration may default to: the deployment's (which include
    DD_JIRA_EXTRA_ISSUE_TYPES), then this instance's own extra types, without repeats.
    """
    choices = tuple(getattr(settings, "JIRA_ISSUE_TYPE_CHOICES_CONFIG", DEFAULT_JIRA_ISSUE_TYPES))
    known = {value for value, _label in choices}
    extra = _system_settings().jira_extra_issue_types or ""
    for issue_type in (part.strip() for part in extra.split(",")):
        if issue_type and issue_type not in known:
            known.add(issue_type)
            choices += ((issue_type, issue_type),)
    return choices


def team_name() -> str:
    """The team name reports and the API show: the System Settings field, else ``DD_TEAM_NAME``."""
    return _system_settings().team_name or settings.TEAM_NAME


def _algorithms() -> set[str]:
    return {
        settings.DEDUPE_ALGO_LEGACY,
        settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
        settings.DEDUPE_ALGO_HASH_CODE,
        settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    }


def validate_hashcode_fields_per_scanner(value) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or not all(
        isinstance(scan_type, str) and isinstance(fields, list) and all(isinstance(f, str) for f in fields)
        for scan_type, fields in value.items()
    ):
        raise ValidationError(
            translate(
                'Enter an object that maps a scan type to a list of field names, for example {"Scanner": ["title", "cwe"]}.',
            ),
        )


def validate_deduplication_algorithm_per_parser(value) -> None:
    if value is None:
        return
    allowed = _algorithms()
    if not isinstance(value, dict) or not all(
        isinstance(scan_type, str) and algorithm in allowed for scan_type, algorithm in value.items()
    ):
        raise ValidationError(
            translate("Enter an object that maps a scan type to one of: %(algorithms)s.")
            % {"algorithms": ", ".join(sorted(allowed))},
        )


def validate_notifications_system_level_trump(value) -> None:
    if value is None:
        return
    if not isinstance(value, list) or not all(isinstance(event, str) for event in value):
        raise ValidationError(translate('Enter a list of notification event names, for example ["user_mentioned"].'))


def validate_language_code(value) -> None:
    if value in {None, ""}:
        return
    if value not in {code for code, _name in settings.LANGUAGES}:
        raise ValidationError(translate("Choose one of the languages this instance offers."))


def validate_retention_period(value) -> None:
    if value is None or value == -1 or (isinstance(value, int) and value >= 1):
        return
    raise ValidationError(translate("Enter -1 to keep everything, or at least 1."))
