"""Database-level helpers that are not tied to any particular model or app."""

# SQLSTATEs meaning "this transaction lost a concurrency race": 40P01
# deadlock_detected and 40001 serialization_failure. Postgres aborts one participant
# and lets the other commit, so the aborted work is not invalid -- it just has to run
# again. Anything else (a statement timeout, a dropped connection) is not in this
# category and repeating it only repeats the problem.
TRANSIENT_DB_CONFLICT_SQLSTATES = frozenset({"40P01", "40001"})


def is_transient_db_conflict(exc):
    """
    Whether exc is a deadlock or serialization failure, and so safe to retry.

    Django re-raises the driver error as its own OperationalError and keeps the driver
    exception -- the one carrying the SQLSTATE -- as ``__cause__``, so check both rather
    than matching on the message text, which is localized and version-dependent.
    """
    return any(
        getattr(err, "sqlstate", None) in TRANSIENT_DB_CONFLICT_SQLSTATES
        for err in (exc, exc.__cause__)
    )
