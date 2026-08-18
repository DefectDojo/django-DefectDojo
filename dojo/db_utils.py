"""Database-level helpers that are not tied to any particular model or app."""

# SQLSTATEs meaning "this transaction lost a concurrency race": 40P01
# deadlock_detected and 40001 serialization_failure. Postgres aborts one participant
# and lets the other commit, so the aborted work is not invalid -- it just has to run
# again. Anything else (a statement timeout, a dropped connection) is not in this
# category and repeating it only repeats the problem.
TRANSIENT_DB_CONFLICT_SQLSTATES = frozenset({"40P01", "40001"})

# 23503 foreign_key_violation. Retryable ONLY in the cascade-delete context: it means a
# row referencing what we are deleting appeared after the cascade step had already
# cleared the children -- an import committing a new child (e.g. a Test_Import row for a
# Test being deleted) between the cascade step and the top-level delete. The reference is
# real but transient: on a re-run the cascade step clears the newly-created child and the
# delete succeeds. Outside a delete an FK violation is a genuine bug, so this is exposed as
# its own predicate and never folded into is_transient_db_conflict.
FK_VIOLATION_SQLSTATE = "23503"


def _iter_sqlstates(exc):
    """
    Yield the SQLSTATE of exc and of its driver ``__cause__``.

    Django re-raises the driver error as its own OperationalError/IntegrityError and keeps
    the driver exception -- the one carrying the SQLSTATE -- as ``__cause__``, so check
    both rather than matching on the message text, which is localized and version-dependent.
    """
    for err in (exc, getattr(exc, "__cause__", None)):
        state = getattr(err, "sqlstate", None)
        if state is not None:
            yield state


def is_transient_db_conflict(exc):
    """Whether exc is a deadlock or serialization failure, and so safe to retry."""
    return any(state in TRANSIENT_DB_CONFLICT_SQLSTATES for state in _iter_sqlstates(exc))


def is_foreign_key_conflict(exc):
    """
    Whether exc is a foreign-key violation (SQLSTATE 23503).

    See ``FK_VIOLATION_SQLSTATE`` -- retryable only while cascade-deleting, where it is the
    delete-vs-import race, not a generic transient conflict.
    """
    return any(state == FK_VIOLATION_SQLSTATE for state in _iter_sqlstates(exc))
