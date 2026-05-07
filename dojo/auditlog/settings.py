"""
Source of truth for audit-log settings.

This module is imported during Django settings construction, so it must
remain dependency-free except for stdlib and pghistory. Do not add
``django.conf`` or other ``dojo.*`` imports here.
"""
import pghistory

# Env-var schema merged into settings.dist.py's environ.Env() call.
ENV_SCHEMA = {
    "DD_ENABLE_AUDITLOG": (bool, True),
    "DD_AUDITLOG_FLUSH_RETENTION_PERIOD": (int, -1),
    "DD_AUDITLOG_FLUSH_BATCH_SIZE": (int, 1000),
    "DD_AUDITLOG_FLUSH_MAX_BATCHES": (int, 100),
}

# pghistory field configuration — re-exported as Django settings.
PGHISTORY_FOREIGN_KEY_FIELD = pghistory.ForeignKey(db_index=False)
PGHISTORY_CONTEXT_FIELD = pghistory.ContextForeignKey(db_index=True)
PGHISTORY_OBJ_FIELD = pghistory.ObjForeignKey(db_index=True)

# Fixture-compat constant.
AUDITLOG_DISABLE_ON_RAW_SAVE = False
