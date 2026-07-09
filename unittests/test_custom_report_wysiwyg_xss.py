import json

from dojo.reports.widgets import report_widget_factory
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestCustomReportWysiwygXss(DojoTestCase):

    """
    Regression tests for the Custom Report Builder "Custom Content" (WYSIWYG)
    widget.

    The widget renders user-supplied markup with Django's |safe filter, so the
    content must be sanitized before it reaches the template. These tests drive
    the same data flow as the report builder -- custom-content.hidden_content ->
    report_widget_factory() -> WYSIWYGContent.content -> get_html() -> the
    |safe template -- and assert that active content cannot be emitted as raw
    executable markup while legitimate rich-text formatting survives.
    """

    fixtures = ["dojo_testdata.json"]

    # The exact payload validated in the original report.
    SCRIPT_PAYLOAD = "<script>alert(document.domain)</script><img src=x onerror=alert(1)>"
    JS_URL_PAYLOAD = '<a href="javascript:alert(1)">click me</a>'
    SAFE_PAYLOAD = '<b>bold</b> <u>underline</u> <a href="https://example.com/safe">safe link</a>'
    # <img> is allowed, so an inline base64 image must survive...
    DATA_IMAGE_PAYLOAD = (
        '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB'
        'CAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC" alt="pixel">'
    )
    # ...but data: must be limited to images -- data:text/html on an <img src>...
    DATA_HTML_IMAGE_PAYLOAD = '<img src="data:text/html,<script>alert(1)</script>">'
    # ...and data: URLs must never be accepted on a link href.
    DATA_URL_LINK_PAYLOAD = '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">link</a>'
    # Event handlers must be stripped even from allow-listed tags.
    EVENT_HANDLER_PAYLOAD = '<div onclick="alert(1)">click</div>'

    def _render_custom_content(self, hidden_content, heading="Custom Content"):
        """Render a Custom Content widget the way the report builder does."""
        widget_json = json.dumps([
            {"custom-content": [
                {"name": "heading", "value": heading},
                {"name": "hidden_content", "value": hidden_content},
                {"name": "page_break_after", "value": False},
            ]},
        ])
        widgets = report_widget_factory(json_data=widget_json, request=None)
        return str(widgets["custom-content-0"].get_html())

    def test_script_is_neutralized_and_image_handler_is_stripped(self):
        """<script> is escaped to inert text; <img> is kept but its onerror is removed."""
        html = self._render_custom_content(self.SCRIPT_PAYLOAD)

        # <script> is escaped (rendered as inert text, not a raw tag)...
        self.assertNotIn("<script", html)
        # ...the image element itself is allowed...
        self.assertIn("<img", html)
        # ...but the event handler that made it dangerous is gone.
        self.assertNotIn("onerror", html)

    def test_data_url_image_is_preserved(self):
        """Inline data:image/ sources survive so pasted/base64 images still render."""
        html = self._render_custom_content(self.DATA_IMAGE_PAYLOAD)

        self.assertIn("data:image/png;base64", html)

    def test_data_url_non_image_is_stripped(self):
        """data: on an <img src> is limited to images; data:text/html is dropped."""
        html = self._render_custom_content(self.DATA_HTML_IMAGE_PAYLOAD)

        self.assertNotIn("data:text/html", html)
        self.assertNotIn("<script", html)

    def test_data_url_link_is_stripped(self):
        """data: URLs are never allowed on link hrefs (only on <img src>)."""
        html = self._render_custom_content(self.DATA_URL_LINK_PAYLOAD)

        self.assertNotIn("data:text/html", html)
        self.assertIn("link", html)  # anchor text is preserved

    def test_obfuscated_data_url_link_is_stripped(self):
        """data: on a link href stays blocked even when its scheme is split by control chars."""
        for payload in (
            '<a href="da&#10;ta:text/html,alert(1)">l</a>',  # newline in scheme
            '<a href="da&#9;ta:text/html,alert(1)">l</a>',  # tab in scheme
        ):
            html = self._render_custom_content(payload)
            self.assertNotIn("ta:text/html", html)

    def test_event_handler_on_allowed_tag_is_stripped(self):
        """Event-handler attributes are removed even from allow-listed tags."""
        html = self._render_custom_content(self.EVENT_HANDLER_PAYLOAD)

        self.assertNotIn("onclick", html)
        self.assertIn("click", html)

    def test_javascript_url_is_stripped(self):
        """javascript: hrefs are removed; the anchor text is preserved."""
        html = self._render_custom_content(self.JS_URL_PAYLOAD)

        self.assertNotIn("javascript:", html)
        self.assertIn("click me", html)

    def test_safe_formatting_is_preserved(self):
        """The formatting the WYSIWYG editor emits must pass through intact."""
        html = self._render_custom_content(self.SAFE_PAYLOAD)

        self.assertIn("<b>bold</b>", html)
        self.assertIn("<u>underline</u>", html)
        self.assertIn('href="https://example.com/safe"', html)
        self.assertIn("safe link", html)

    def test_heading_is_escaped(self):
        """The heading is auto-escaped and cannot be used to inject markup."""
        html = self._render_custom_content("benign", heading="<script>alert(1)</script>")

        self.assertNotIn("<script", html)
