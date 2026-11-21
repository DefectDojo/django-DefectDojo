"""
The Jira description's template context can be adjusted through ``JIRA_DESCRIPTION_CONTEXT_METHOD``.

Without the setting the context renders exactly as built. With it, the named callable receives the
object and the context and returns the context to render, which is how a deployment can, for
example, cap a long location list and add a ``locations_more`` line the stock template prints.
"""

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from dojo.jira import helper as jira_helper


def add_marker(obj, context):
    return {**context, "marker": f"seen {obj.pk}"}


class TestJiraDescriptionContextMethod(SimpleTestCase):

    def test_without_the_setting_the_context_is_unchanged(self):
        method = jira_helper.get_jira_description_context_method()
        context = {"finding": object()}
        self.assertIs(context, method(object(), context))

    @override_settings(JIRA_DESCRIPTION_CONTEXT_METHOD="unittests.test_jira_description_context.add_marker")
    def test_the_named_method_adjusts_the_rendered_context(self):
        obj = MagicMock(pk=7)
        obj.get_absolute_url.return_value = "/finding/7"
        with (
            patch.object(jira_helper, "get_jira_issue_template", return_value="t.tpl"),
            patch.object(jira_helper, "render_to_string", return_value="body") as render,
            patch.object(jira_helper, "get_full_url", return_value="https://dojo.example.com/finding/7"),
        ):
            self.assertEqual("body", jira_helper.jira_description(obj))
        self.assertEqual("seen 7", render.call_args.args[1]["marker"])

    @override_settings(JIRA_DESCRIPTION_CONTEXT_METHOD="no.such.module.method")
    def test_a_method_that_cannot_be_imported_falls_back_to_the_built_context(self):
        context = {"finding": object()}
        self.assertIs(context, jira_helper.get_jira_description_context_method()(object(), context))
