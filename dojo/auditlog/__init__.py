"""
Audit-log package for DefectDojo.

The public API is exposed lazily via PEP 562 so that importing
``dojo.auditlog`` (and especially ``dojo.auditlog.settings``) at Django
settings-load time does not pull in submodules that depend on
``django.conf.settings`` or other not-yet-built parts of the dojo app.
"""
import importlib

_LAZY_EXPORTS = {  # noqa: RUF067 -- table backs the PEP 562 __getattr__ re-export
    "run_flush_auditlog":               "dojo.auditlog.services",
    "configure_audit_system":           "dojo.auditlog.services",
    "configure_pghistory_triggers":     "dojo.auditlog.services",
    "register_django_pghistory_models": "dojo.auditlog.services",
    "process_events_for_display":       "dojo.auditlog.helpers",
    "TAG_MODEL_MAPPING":                "dojo.auditlog.helpers",
    "get_tracked_models":               "dojo.auditlog.backfill",
    "process_model_backfill":           "dojo.auditlog.backfill",
}


def __getattr__(name):
    module_path = _LAZY_EXPORTS.get(name)
    if module_path is None:
        msg = f"module 'dojo.auditlog' has no attribute {name!r}"
        raise AttributeError(msg)
    return getattr(importlib.import_module(module_path), name)
