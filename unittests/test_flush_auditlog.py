from dojo.tasks import flush_auditlog
from .dojo_test_case import DojoTestCase
from django.conf import settings
from auditlog.models import LogEntry
from datetime import date, datetime
from dojo.models import Finding
from dateutil.relativedelta import relativedelta
import logging
logger = logging.getLogger(__name__)


class TestFlushAuditlog(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def test_flush_auditlog_disabled(self):
        settings.AUDITLOG_FLUSH_RETENTION_PERIOD = -1
        entries_before = LogEntry.objects.all().count()
        flush_auditlog()
        entries_after = LogEntry.objects.all().count()
        self.assertEqual(entries_before, entries_after)

    def test_delete_all_entries(self):
        settings.AUDITLOG_FLUSH_RETENTION_PERIOD = 0
        entries_before = LogEntry.objects.filter(timestamp__date__lt=date.today()).count()
        flush_auditlog()
        entries_after = LogEntry.objects.filter(timestamp__date__lt=date.today()).count()
        # we have three old log entries in our testdata
        self.assertEqual(entries_before - 3, entries_after)

    def test_delete_entries_with_retention_period(self):
        settings.AUDITLOG_FLUSH_RETENTION_PERIOD = 1
        entries_before = LogEntry.objects.filter(timestamp__date__lt=date.today()).count()
        two_weeks_ago = datetime.today() - relativedelta(weeks=2)
        log_entry = LogEntry.objects.log_create(
            instance=Finding.objects.all()[0],
            timestamp=two_weeks_ago,
            changes="foo",
            action=LogEntry.Action.UPDATE,
        )
        log_entry.timestamp = two_weeks_ago
        log_entry.save()
        flush_auditlog()
        entries_after = LogEntry.objects.filter(timestamp__date__lt=date.today()).count()
        # we have three old log entries in our testdata and added a new one
        self.assertEqual(entries_before - 3 + 1, entries_after)
