"""Audit-log UI filters for the action_history page."""
from auditlog.models import LogEntry
from django.db.models import JSONField, Q
from django_filters import (
    CharFilter,
    ModelChoiceFilter,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
)
from django_filters.filters import ChoiceFilter

from dojo.filters import DateRangeFilter, DojoFilter
from dojo.models import Dojo_User
from dojo.user.queries import get_authorized_users


class LogEntryFilter(DojoFilter):

    action = MultipleChoiceFilter(choices=LogEntry.Action.choices)
    actor = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.none())
    timestamp = DateRangeFilter()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["actor"].queryset = get_authorized_users("view")

    class Meta:
        model = LogEntry
        exclude = ["content_type", "object_pk", "object_id", "object_repr",
                   "changes", "additional_data", "remote_addr"]
        filter_overrides = {
            JSONField: {
                "filter_class": CharFilter,
                "extra": lambda _: {
                    "lookup_expr": "icontains",
                },
            },
        }


class PgHistoryFilter(DojoFilter):

    """
    Filter for django-pghistory audit entries.

    This filter works with pghistory event tables that have:
    - pgh_created_at: timestamp of the event
    - pgh_label: event type (insert/update/delete)
    - user: user ID from context
    - url: URL from context
    - remote_addr: IP address from context
    """

    pgh_created_at = DateRangeFilter(field_name="pgh_created_at", label="Timestamp")

    pgh_label = ChoiceFilter(
        field_name="pgh_label",
        label="Event Type",
        choices=[
            ("", "All"),
            ("insert", "Insert"),
            ("update", "Update"),
            ("delete", "Delete"),
            ("initial_backfill", "Initial Backfill"),
        ],
    )

    user = ModelChoiceFilter(
        field_name="user",
        queryset=Dojo_User.objects.none(),
        label="User",
        empty_label="All Users",
    )

    remote_addr = CharFilter(
        field_name="remote_addr",
        lookup_expr="icontains",
        label="IP Address Contains",
    )

    pgh_diff = CharFilter(
        method="filter_pgh_diff_contains",
        label="Changes Contains",
        help_text="Search for field names or values in the changes (optimized for JSONB, but can be slow)",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["user"].queryset = get_authorized_users("view")

    def filter_pgh_diff_contains(self, queryset, name, value):
        """
        Custom filter for pgh_diff that uses efficient JSONB operations.
        Searches both keys and values in the JSONB field.
        """
        if not value:
            return queryset

        return queryset.filter(
            Q(pgh_diff__has_key=value)
            | Q(pgh_diff__has_any_keys=[value])
            | Q(pgh_diff__contains=f'"{value}"'),
        )

    class Meta:
        fields = ["pgh_created_at", "pgh_label", "user", "url", "remote_addr", "pgh_diff"]
        exclude = []
