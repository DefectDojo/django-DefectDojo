import logging
from datetime import UTC, date, datetime

from auditlog.models import LogEntry
from dateutil.relativedelta import relativedelta
from django.test import override_settings

from dojo.models import Finding
from dojo.tasks import flush_auditlog

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestFlushAuditlog(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    @override_settings(AUDITLOG_FLUSH_RETENTION_PERIOD=-1)
    def test_flush_auditlog_disabled(self):
        entries_before = LogEntry.objects.all().count()
        flush_auditlog()
        entries_after = LogEntry.objects.all().count()
        self.assertEqual(entries_before, entries_after)

    @override_settings(AUDITLOG_FLUSH_RETENTION_PERIOD=0)
    def test_delete_all_entries(self):
        entries_before = LogEntry.objects.filter(timestamp__date__lt=date.today()).count()
        flush_auditlog()
        entries_after = LogEntry.objects.filter(timestamp__date__lt=date.today()).count()
        # we have three old log entries in our testdata
        self.assertEqual(entries_before - 3, entries_after)

    @override_settings(AUDITLOG_FLUSH_RETENTION_PERIOD=1)
    def test_delete_entries_with_retention_period(self):
        entries_before = LogEntry.objects.filter(timestamp__date__lt=datetime.now(UTC)).count()
        two_weeks_ago = datetime.now(UTC) - relativedelta(weeks=2)
        log_entry = LogEntry.objects.log_create(
            instance=Finding.objects.all()[0],
            timestamp=two_weeks_ago,
            changes="foo",
            action=LogEntry.Action.UPDATE,
        )
        log_entry.timestamp = two_weeks_ago
        log_entry.save()
        flush_auditlog()
        entries_after = LogEntry.objects.filter(timestamp__date__lt=datetime.now(UTC)).count()
        # we have three old log entries in our testdata and added a new one
        self.assertEqual(entries_before - 3 + 1, entries_after)
