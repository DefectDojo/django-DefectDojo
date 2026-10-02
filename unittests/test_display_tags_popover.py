from html.parser import HTMLParser
from unittest import mock

from django.test import SimpleTestCase

from dojo.templatetags.display_tags import import_settings_tag, jira_project_tag

PAYLOAD = '<a href="https://evil.example/sso">re-authenticate</a><img src="https://evil.example/b.png">'


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.popover_values = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attrs = dict(attrs)
        if "has-popover" in (attrs.get("class") or ""):
            self.popover_values += [v for k, v in attrs.items() if k in {"data-content", "title"} and v]


def _tags_after_second_parse(rendered):
    """Tags a browser materialises from the popover attributes."""
    # Parsing the page decodes the character references in the attribute values;
    # the popover then assigns those values as HTML, which parses them again.
    page = _Collector()
    page.feed(str(rendered))
    second = _Collector()
    for value in page.popover_values:
        second.feed(value)
    return second.tags


class TestPopoverContentEscaping(SimpleTestCase):

    def test_import_settings_tag_keeps_injected_markup_inert(self):
        test_import = mock.Mock(id=1, import_settings={"service": PAYLOAD})
        tags = _tags_after_second_parse(import_settings_tag(test_import))
        self.assertNotIn("a", tags)
        self.assertNotIn("img", tags)

    def test_import_settings_tag_still_renders_a_plain_service(self):
        test_import = mock.Mock(id=1, import_settings={"service": "nightly-scan"})
        self.assertIn("<b>Service:</b> nightly-scan", str(import_settings_tag(test_import)))

    def test_jira_project_tag_keeps_injected_markup_inert(self):
        jira_project = mock.Mock(project_key=PAYLOAD, component="", push_all_issues=False,
                                 enable_engagement_epic_mapping=False, push_notes=False)
        with mock.patch("dojo.templatetags.display_tags.jira_services.get_project",
                        return_value=jira_project):
            tags = _tags_after_second_parse(jira_project_tag(mock.Mock()))
        self.assertNotIn("a", tags)
        self.assertNotIn("img", tags)
