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

from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import ValidationError
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


def get_setting(name: str):
    """Return the instance's value for ``name``: its System Settings field, else the setting."""
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
