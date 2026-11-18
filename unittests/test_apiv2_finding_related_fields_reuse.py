"""
Regression test for ``?related_fields=true`` on the findings API.

``FindingSerializer.get_related_fields`` built a new ``FindingRelatedFieldsSerializer`` for every
row, and that serializer built a new ``FindingTestSerializer`` (three levels of nested serializers)
and a new ``JIRAIssueSerializer`` for every row too. Building a serializer builds its whole field
tree, so a 1000-row page spent seconds rebuilding the same trees. Nothing in those trees depends on
the row, so one instance now serves every row a serializer renders. The same page read each JIRA
issue's project and instance with a query each to render the issue's url (for an issue with no project,
the engagement's or the product's); a ``related_fields`` page now loads them with the page while JIRA is
enabled.

The tests pin that each of the three is built once for 2 rows and for 6, that related_fields adds the
same statements to 2 rows as to 6, and that the payload is the one the per-row construction produced,
byte for byte, with and without a JIRA issue.
"""

import re
from collections import Counter
from unittest.mock import patch

from crum import impersonate
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now
from rest_framework.renderers import JSONRenderer
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from dojo.finding.api.serializer import (
    FindingRelatedFieldsSerializer,
    FindingSerializer,
    FindingTestSerializer,
)
from dojo.finding.api.views import FindingViewSet
from dojo.jira import services as jira_services
from dojo.jira.api.serializers import JIRAIssueSerializer
from dojo.jira.models import JIRA_Instance, JIRA_Issue, JIRA_Project
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase


def _shapes(sqls):
    """Each query with its literals replaced, so one per-row query on different ids counts as one shape."""
    return Counter(
        re.sub(r"\(\s*%s(\s*,\s*%s)*\s*\)", "(...)", re.sub(r"\b\d+\b|'[^']*'", "%s", sql))[:300] for sql in sqls
    )


class _RelatedFieldsBefore(FindingRelatedFieldsSerializer):

    """``FindingRelatedFieldsSerializer`` before it reused its nested serializers: new ones for every row."""

    def get_test(self, obj):
        return FindingTestSerializer(read_only=True).to_representation(obj.test)

    def get_jira(self, obj):
        issue = jira_services.get_issue(obj)
        if issue is None:
            return None
        return JIRAIssueSerializer(read_only=True).to_representation(issue)


def _get_related_fields_before(self, obj):
    """``FindingSerializer.get_related_fields`` before it reused one serializer: a new one for every row."""
    request = self.context.get("request", None)
    if request is None:
        return None
    if request.query_params.get("related_fields", "false") == "true":
        return _RelatedFieldsBefore(required=False).to_representation(obj)
    return None


_NESTED = {
    "related_fields": FindingRelatedFieldsSerializer,
    "test": FindingTestSerializer,
    "jira": JIRAIssueSerializer,
}


class FindingRelatedFieldsReuseTest(DojoTestCase):

    """A page of ``related_fields`` builds each nested serializer once, and renders what it rendered before."""

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="RelatedFieldsReuse PT")
        product = Product.objects.create(name="RelatedFieldsReuse Product", description="reuse", prod_type=prod_type)
        engagement = Engagement.objects.create(
            name="RelatedFieldsReuse Engagement", product=product, target_start=now(), target_end=now(),
        )
        cls.admin = Dojo_User.objects.create(username="related-fields-reuse-admin", is_superuser=True, is_staff=True)
        cls.test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="RelatedFieldsReuse Scan")[0],
            environment=Development_Environment.objects.get_or_create(name="RelatedFieldsReuse Env")[0],
            target_start=now(),
            target_end=now(),
        )
        instance = JIRA_Instance.objects.create(
            configuration_name="related fields reuse",
            url="https://jira.test",
            username="dojo",
            password="secret",  # noqa: S106 -- test-only Jira instance
            default_issue_type="Bug",
            epic_name_id=10011,
            open_status_key=11,
            close_status_key=21,
            info_mapping_severity="Lowest",
            low_mapping_severity="Low",
            medium_mapping_severity="Medium",
            high_mapping_severity="High",
            critical_mapping_severity="Highest",
        )
        cls.jira_project = JIRA_Project.objects.create(jira_instance=instance, project_key="REL", product=product)

    def setUp(self):
        super().setUp()
        # A JIRA issue's url is resolved through its project and instance only while JIRA is enabled
        self.system_settings(enable_jira=True)

    def _add_finding(self, index, *, jira=True, linked=True):
        """A finding with a JIRA issue linked to the product's project, or (``linked=False``) with no project of its own."""
        finding = Finding.objects.create(
            title=f"related {index}", test=self.test, reporter=self.admin, severity="High", numerical_severity="S1",
        )
        if jira:
            JIRA_Issue.objects.create(
                jira_id=f"r{index}",
                jira_key=f"REL-{index}",
                finding=finding,
                jira_project=self.jira_project if linked else None,
            )
        return finding

    def _render(self, params):
        """The test's findings, read by the list's queryset and rendered through one ``many=True`` FindingSerializer."""
        request = Request(APIRequestFactory().get("/api/v2/findings/", params))
        request.user = self.admin
        view = FindingViewSet()
        view.request = request
        with impersonate(self.admin):
            findings = view.get_queryset().filter(test=self.test).order_by("id")
            data = FindingSerializer(findings, many=True, context={"request": request}).data
        return JSONRenderer().render(data)

    def _statements(self, params):
        with CaptureQueriesContext(connection) as queries:
            body = self._render(params)
        return [query["sql"] for query in queries.captured_queries], body

    def test_related_fields_adds_no_statements_per_row(self):
        # Measured against the plain page, so only what related_fields itself reads is counted. Odd rows' issues have
        # no project of their own, so their url comes from the product's project.
        for index in range(2):
            self._add_finding(index, linked=index % 2 == 0)
        self._render({"related_fields": "true"})  # per-process caches (system settings) fill on first use
        two, _ = self._statements({"related_fields": "true"})
        two_plain, _ = self._statements({})
        for index in range(2, 6):
            self._add_finding(index, linked=index % 2 == 0)
        six, body = self._statements({"related_fields": "true"})
        six_plain, _ = self._statements({})
        added_two = _shapes(two) - _shapes(two_plain)
        added_six = _shapes(six) - _shapes(six_plain)
        self.assertEqual(
            added_two,
            added_six,
            f"related_fields added {sum(added_two.values())} statements to 2 rows and {sum(added_six.values())} to 6",
        )
        for index in range(6):
            self.assertIn(f'"url":"https://jira.test/browse/REL-{index}"'.encode(), body)

    def _jira_lookups(self, params):
        request = Request(APIRequestFactory().get("/api/v2/findings/", params))
        request.user = self.admin
        view = FindingViewSet()
        view.request = request
        with impersonate(self.admin):
            lookups = view.get_queryset()._prefetch_related_lookups
        return {lookup for lookup in lookups if isinstance(lookup, str) and "jira_project" in lookup}

    def test_jira_projects_are_prefetched_only_for_related_fields_while_jira_is_enabled(self):
        self.assertEqual(
            self._jira_lookups({"related_fields": "true"}),
            {
                "jira_issue__jira_project__jira_instance",
                "test__engagement__jira_project__jira_instance",
                "test__engagement__product__jira_project_set__jira_instance",
            },
        )
        self.assertEqual(self._jira_lookups({}), set())
        self.system_settings(enable_jira=False)
        self.assertEqual(self._jira_lookups({"related_fields": "true"}), set())

    def _constructions(self, params):
        spies = {
            name: patch.object(cls, "__init__", autospec=True, side_effect=cls.__init__)
            for name, cls in _NESTED.items()
        }
        started = {name: spy.start() for name, spy in spies.items()}
        try:
            body = self._render(params)
        finally:
            for spy in spies.values():
                spy.stop()
        return {name: started[name].call_count for name in _NESTED}, body

    def test_each_nested_serializer_is_built_once_per_page(self):
        for index in range(2):
            self._add_finding(index)
        two, _ = self._constructions({"related_fields": "true"})
        for index in range(2, 6):
            self._add_finding(index)
        six, body = self._constructions({"related_fields": "true"})
        self.assertEqual(two, {"related_fields": 1, "test": 1, "jira": 1})
        self.assertEqual(six, {"related_fields": 1, "test": 1, "jira": 1})
        self.assertIn(b'"jira_key":"REL-5"', body)

    def test_a_page_without_related_fields_builds_none_of_them(self):
        self._add_finding(0)
        counts, body = self._constructions({})
        self.assertEqual(counts, {"related_fields": 0, "test": 0, "jira": 0})
        self.assertIn(b'"related_fields":null', body)

    def test_payload_is_byte_identical_to_the_per_row_construction(self):
        for index in range(3):
            self._add_finding(index)
        self._add_finding(3, jira=False)
        self._add_finding(4, linked=False)
        for params in ({"related_fields": "true"}, {}):
            after = self._render(params)
            with patch.object(FindingSerializer, "get_related_fields", _get_related_fields_before):
                before = self._render(params)
            self.assertEqual(after, before, params)
        after = self._render({"related_fields": "true"})
        self.assertIn(b'"jira":null', after)
        self.assertIn(b'"url":"https://jira.test/browse/REL-2"', after)
        self.assertIn(b'"url":"https://jira.test/browse/REL-4"', after)
        self.assertIn(b'"environment":{"id":', after)
        self.assertIn(b'"prod_type":{"id":', after)
