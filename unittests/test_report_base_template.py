import re
from pathlib import Path

from django.test import SimpleTestCase

TEMPLATE = Path(__file__).resolve().parents[1] / "dojo" / "templates" / "report_base.html"


class ReportBaseTemplateTest(SimpleTestCase):

    """The report base template loads nothing from another host."""

    def test_no_remote_stylesheet_or_font(self):
        # A report is often opened from disk or printed, and a Content-Security-Policy on the app
        # origin (default-src 'self') blocks a remote @import: the page then waits on a request
        # that never succeeds and falls back to whatever font the browser picks.
        text = TEMPLATE.read_text(encoding="utf-8")
        remote = re.findall(r"@import\s+url\(\s*['\"]?(?:https?:)?//[^)]*\)", text)
        remote += re.findall(r"<link[^>]+href=['\"](?:https?:)?//[^'\"]+", text)
        self.assertEqual([], remote)
