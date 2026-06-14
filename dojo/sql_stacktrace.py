"""
Temporary debugging helper: django-sql-stacktrace-style execute_wrapper.

Enabled only when the env var DD_SQL_STACKTRACE is set. When active it
registers a connection.execute_wrapper on every DB connection that, for any
SQL matching DD_SQL_STACKTRACE_FILTER (default: 'pro_enhanced_finding'),
prints the originating Python traceback to stderr. Used to pinpoint the exact
call site emitting the per-finding deduplication queries in the importer perf
tests. NOT for production — remove before merge.
"""
import os
import sys
import traceback

from django.db.backends.signals import connection_created
from django.dispatch import receiver

_FILTER = os.environ.get("DD_SQL_STACKTRACE_FILTER", "pro_enhanced_finding")
_counter = {"n": 0}


def _stacktrace_wrapper(execute, sql, params, many, context):
    if _FILTER in sql:
        _counter["n"] += 1
        stack = "".join(traceback.format_stack()[:-1])
        sys.stderr.write(
            f"\n===== DD_SQL_STACKTRACE hit #{_counter['n']} (filter={_FILTER!r}) =====\n"
            f"SQL: {sql[:200]}\n"
            f"{stack}"
            f"===== end DD_SQL_STACKTRACE hit #{_counter['n']} =====\n",
        )
        sys.stderr.flush()
    return execute(sql, params, many, context)


@receiver(connection_created)
def _install_wrapper(sender, connection, **kwargs):
    # execute_wrappers persist for the life of the connection; guard against
    # double-registration if the signal fires more than once for a connection.
    if getattr(connection, "_dd_sql_stacktrace_installed", False):
        return
    connection._dd_sql_stacktrace_installed = True
    connection.execute_wrappers.append(_stacktrace_wrapper)


def maybe_enable():
    """Touch the module so the connection_created receiver is connected.

    Returns True when the DD_SQL_STACKTRACE env var requested activation.
    """
    return bool(os.environ.get("DD_SQL_STACKTRACE"))
