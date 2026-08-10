"""Database-level helpers that are not tied to any particular model or app."""

from django.db import models

# Stored-format prefixes written by dojo_crypto_encrypt(). "AES.1" is the legacy
# OFB format, "AES.2" the current GCM one; prepare_for_view() reads both.
ENCRYPTED_VALUE_PREFIXES = ("AES.1:", "AES.2:")

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


class EncryptedTextField(models.TextField):

    """
    TextField whose value is encrypted at rest and decrypted on read.

    Encrypting in the field rather than at each write site means every writer is
    covered: forms, serializers, the admin, ``loaddata`` and ``QuerySet.update()``.

    Values stored before a column moved to this field are plaintext. They are
    returned as they are and encrypted the next time the row is written, so an
    unconverted row stays readable instead of decoding to an empty string.
    """

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if not value or value.startswith(ENCRYPTED_VALUE_PREFIXES):
            return value
        from dojo.utils import dojo_crypto_encrypt  # noqa: PLC0415 circular import
        return dojo_crypto_encrypt(value)

    def from_db_value(self, value, expression, connection):
        if not value or not value.startswith(ENCRYPTED_VALUE_PREFIXES):
            return value
        from dojo.utils import prepare_for_view  # noqa: PLC0415 circular import
        return prepare_for_view(value)
