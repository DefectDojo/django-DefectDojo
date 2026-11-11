"""
Regression test for ``?prefetch=duplicate_finding`` on the findings list.

The prefetcher serializes each distinct original a page's duplicates name with the full
``FindingSerializer``, from the original's own instance. Nothing loaded that instance's
relations, so every original read its tags, notes (and their authors, types and history),
endpoints or locations, finding groups and their JIRA issues, CWEs, vulnerability ids, risk
acceptances and the rest one query at a time: about 25 queries per distinct original. A risk
acceptance's ``path`` also looked its engagement up with a query of its own, and every original
built a serializer (and its fields) of its own.

The tests pin that the prefetch costs the same for 2 originals as for 6, for a superuser and for
a product member, that the payload is the one the per-original serialization produced, byte for
byte, and that ``path`` names the same engagement it did.
"""

import re
from collections import Counter
from datetime import date
from unittest.mock import patch

from crum import impersonate
from django.db import connection
from django.db.models import prefetch_related_objects
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.renderers import JSONRenderer
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from dojo.api_v2.prefetch import prefetcher as prefetcher_module
from dojo.finding.helper import save_vulnerability_ids
from dojo.jira.models import JIRA_Instance, JIRA_Issue, JIRA_Project
from dojo.location.feature import locations_enabled
from dojo.models import (
    BurpRawRequestResponse,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    FileUpload,
    Finding,
    Finding_CWE,
    Finding_Group,
    Note_Type,
    NoteHistory,
    Notes,
    Product,
    Product_Member,
    Product_Type,
    Risk_Acceptance,
    Test,
    Test_Type,
)
from dojo.request_cache import begin_task_cache, end_task_cache
from dojo.risk_acceptance.api.serializer import RiskAcceptanceSerializer
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, versioned_fixtures


def _shapes(sqls):
    """Each query with its literals replaced, so one per-original query on different ids counts as one shape."""
    return Counter(
        re.sub(r"\(\s*%s(\s*,\s*%s)*\s*\)", "(...)", re.sub(r"\b\d+\b|'[^']*'|\"s\d+_x\d+\"", "%s", sql))[:300]
        for sql in sqls
    )


def _prefetch_single_before(self, field_to_fetch, field_values, authorized_qs, extra_serializer, serializer_kwargs):
    """``_Prefetcher._prefetch_single`` before it reused one serializer: a new serializer for every object."""
    authorized_ids = set(authorized_qs.filter(pk__in={value.pk for value in field_values}).values_list("pk", flat=True))
    if prefetch_related := prefetcher_module._PREFETCH_PREFETCH_RELATED.get(type(field_values[0])):
        prefetch_related_objects([value for value in field_values if value.pk in authorized_ids], *prefetch_related)
    serialized = set()
    for field_value in field_values:
        if field_value.pk not in authorized_ids or field_value.pk in serialized:
            continue
        serialized.add(field_value.pk)
        data = extra_serializer(**serializer_kwargs).to_representation(field_value)
        self._prefetch_data[field_to_fetch][data["id"]] = data


def _get_path_before(serializer, acceptance):
    """``RiskAcceptanceSerializer.get_path`` before it read the acceptance's ``engagement_set``."""
    engagement = Engagement.objects.filter(risk_acceptance__id__in=[acceptance.id]).first()
    path = "No proof has been supplied"
    if engagement and acceptance.filename() is not None:
        path = reverse("download_risk_acceptance", args=(engagement.id, acceptance.id))
        request = serializer.context.get("request")
        if request:
            path = request.build_absolute_uri(path)
    return path


@versioned_fixtures
class PrefetchDuplicateFindingTest(DojoTestCase):

    """``?prefetch=duplicate_finding`` must cost the same for 2 distinct originals as for 6."""

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="PrefetchDuplicates PT")
        cls.test_type, _ = Test_Type.objects.get_or_create(name="PrefetchDuplicates Scan")
        cls.product = Product.objects.create(
            name="PrefetchDuplicates Product", description="duplicate finding prefetch", prod_type=prod_type,
        )
        cls.engagement = Engagement.objects.create(
            name="PrefetchDuplicates Engagement", product=cls.product, target_start=now(), target_end=now(),
        )
        cls.admin = Dojo_User.objects.get(username="admin")
        cls.member = Dojo_User.objects.create(username="prefetch-duplicates-member")
        cls.product.authorized_users.add(cls.member)
        # Owner, so accepted_risks (gated on edit) is serialized for the member too
        Product_Member.objects.create(product=cls.product, user=cls.member, role_id=4)
        cls.originals_test = cls._test()
        cls.duplicates_test = cls._test()
        cls.note_type = Note_Type.objects.create(name="PrefetchDuplicates note type", description="prefetch")
        instance = JIRA_Instance.objects.create(
            configuration_name="prefetch duplicates",
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
        cls.jira_project = JIRA_Project.objects.create(jira_instance=instance, project_key="DUP", product=cls.product)

    @classmethod
    def _test(cls):
        return Test.objects.create(
            engagement=cls.engagement, test_type=cls.test_type, target_start=now(), target_end=now(), lead=cls.admin,
        )

    def setUp(self):
        super().setUp()
        # A JIRA issue's url is resolved through its project and instance only while JIRA is enabled
        self.system_settings(enable_jira=True)

    def _add_duplicate(self, index):
        """A duplicate naming its own original, which carries every relation ``FindingSerializer`` reads."""
        original = Finding.objects.create(
            title=f"original {index}", test=self.originals_test, reporter=self.admin, severity="High",
            numerical_severity="S1",
        )
        original.tags.add(f"duplicate-{index}", "duplicate-shared")
        public = Notes.objects.create(entry=f"public {index}", author=self.admin, note_type=self.note_type)
        public.history.add(
            NoteHistory.objects.create(data=f"public {index}", current_editor=self.admin, note_type=self.note_type),
        )
        private = Notes.objects.create(entry=f"private {index}", author=self.admin, private=True)
        original.notes.add(public, private)
        if locations_enabled():
            url = URL(host=f"duplicate-{index}.example.com")
            url.save()
            url.location.associate_with_finding(finding=original)
        else:
            endpoint = Endpoint.objects.create(host=f"duplicate-{index}.example.com", product=self.product)
            Endpoint_Status.objects.create(endpoint=endpoint, finding=original)
        save_vulnerability_ids(original, [f"CVE-2026-{index:04d}"])
        Finding_CWE.objects.create(finding=original, cwe=f"CWE-{index + 1}")
        group = Finding_Group.objects.create(name=f"group {index}", test=self.originals_test, creator=self.admin)
        group.findings.add(original)
        JIRA_Issue.objects.create(
            jira_id=f"g{index}", jira_key=f"DUP-G{index}", finding_group=group, jira_project=self.jira_project,
        )
        JIRA_Issue.objects.create(
            jira_id=f"f{index}", jira_key=f"DUP-F{index}", finding=original, jira_project=self.jira_project,
        )
        acceptance = Risk_Acceptance.objects.create(
            name=f"acceptance {index}", owner=self.admin, path=f"risk_acceptance/proof-{index}.pdf",
        )
        acceptance.accepted_findings.add(original)
        self.engagement.risk_acceptance.add(acceptance)
        original.reviewers.add(self.admin)
        original.found_by.add(self.test_type)
        original.files.add(FileUpload.objects.create(title=f"file {index}", file=f"uploaded_files/dup-{index}.txt"))
        BurpRawRequestResponse.objects.create(
            finding=original, burpRequestBase64=b"R0VUIC8=", burpResponseBase64=b"SFRUUC8xLjEgMjAw",
        )
        DojoMeta.objects.create(finding=original, name="duplicate", value=str(index))
        Finding.objects.create(
            title=f"duplicate {index}", test=self.duplicates_test, reporter=self.admin, severity="High",
            numerical_severity="S1", duplicate=True, duplicate_finding=original,
        )

    def _prefetch(self, user):
        # Fresh instances each time, so nothing loaded by an earlier call is reused
        duplicates = list(Finding.objects.filter(test=self.duplicates_test).order_by("id"))
        request = Request(APIRequestFactory().get("/api/v2/findings/", {"prefetch": "duplicate_finding"}))
        request.user = user
        prefetcher = prefetcher_module._Prefetcher(request=request)
        # A request caches the member's authorized product ids once for all its permission checks (accepted_risks
        # asks per finding); outside a request the task cache is the same scope.
        begin_task_cache()
        try:
            with impersonate(user), CaptureQueriesContext(connection) as queries:
                prefetcher.prefetch_entries(duplicates, ["duplicate_finding"])
        finally:
            end_task_cache()
        return [query["sql"] for query in queries.captured_queries], prefetcher.prefetched_data

    def _assert_flat(self, user):
        self._add_duplicate(0)
        self._add_duplicate(1)
        self._prefetch(user)  # per-process caches (system settings, roles) fill on first use
        two, _ = self._prefetch(user)
        for index in range(2, 6):
            self._add_duplicate(index)
        six, data = self._prefetch(user)
        self.assertEqual(
            len(two),
            len(six),
            f"?prefetch=duplicate_finding cost {len(two)} queries for 2 originals and {len(six)} for 6. "
            f"Query shapes that ran more often: {dict(_shapes(six) - _shapes(two))}",
        )
        originals = data["duplicate_finding"]
        self.assertEqual(6, len(originals))
        for original in originals.values():
            self.assertEqual(2, len(original["tags"]))
            self.assertEqual(1, len(original["endpoints"]))
            self.assertEqual(1, len(original["vulnerability_ids"]))
            self.assertEqual(1, len(original["cwes"]))
            [group] = original["finding_groups"]
            self.assertTrue(group["jira_issue"]["url"].startswith("https://jira.test/browse/DUP-G"))
            [acceptance] = original["accepted_risks"]
            self.assertIn(f"/{self.engagement.id}/risk_acceptance/{acceptance['id']}/download", acceptance["path"])
        return originals

    def test_prefetch_duplicate_finding_is_flat_for_a_superuser(self):
        originals = self._assert_flat(self.admin)
        for original in originals.values():
            self.assertEqual(["private", "public"], sorted(note["entry"].split()[0] for note in original["notes"]))

    def test_prefetch_duplicate_finding_is_flat_for_a_member(self):
        originals = self._assert_flat(self.member)
        # The member sees each original's public note and not the admin's private one
        for original in originals.values():
            self.assertEqual(["public"], [note["entry"].split()[0] for note in original["notes"]])

    def test_prefetch_duplicate_finding_payload_is_unchanged(self):
        for index in range(3):
            self._add_duplicate(index)
        for user in (self.admin, self.member):
            _, batched = self._prefetch(user)
            with (
                patch.dict(prefetcher_module._PREFETCH_PREFETCH_RELATED),
                patch.object(prefetcher_module._Prefetcher, "_prefetch_single", _prefetch_single_before),
                patch.object(RiskAcceptanceSerializer, "get_path", _get_path_before),
            ):
                prefetcher_module._PREFETCH_PREFETCH_RELATED.pop(Finding, None)
                _, unbatched = self._prefetch(user)
            self.assertEqual(3, len(batched["duplicate_finding"]))
            self.assertEqual(JSONRenderer().render(unbatched), JSONRenderer().render(batched), user.username)


class RiskAcceptancePathTest(DojoTestCase):

    """``path`` reads the acceptance's engagements through the relation, and only when there is a proof."""

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="RiskAcceptancePath PT")
        product = Product.objects.create(name="RiskAcceptancePath Product", description="path", prod_type=prod_type)
        owner, _ = Dojo_User.objects.get_or_create(username="risk-acceptance-path-owner")
        cls.acceptance = Risk_Acceptance.objects.create(name="path", owner=owner)
        # Created first, so the lower id, but the later start: Engagement's manager orders by id, not by
        # Meta.ordering (-target_start), and path has always named the lowest id.
        cls.first = Engagement.objects.create(
            name="first", product=product, target_start=date(2026, 2, 1), target_end=date(2026, 2, 2),
        )
        cls.second = Engagement.objects.create(
            name="second", product=product, target_start=date(2026, 1, 1), target_end=date(2026, 1, 2),
        )

    def _path(self):
        acceptance = Risk_Acceptance.objects.get(pk=self.acceptance.pk)
        serializer = RiskAcceptanceSerializer(context={})
        with CaptureQueriesContext(connection) as queries:
            path = serializer.get_path(acceptance)
        self.assertEqual(_get_path_before(serializer, acceptance), path)
        return path, len(queries.captured_queries)

    def _add_proof(self):
        Risk_Acceptance.objects.filter(pk=self.acceptance.pk).update(path="risk_acceptance/proof.pdf")

    def test_no_proof_needs_no_query(self):
        self.first.risk_acceptance.add(self.acceptance)
        self.assertEqual(("No proof has been supplied", 0), self._path())

    def test_proof_without_an_engagement_has_no_path(self):
        self._add_proof()
        self.assertEqual("No proof has been supplied", self._path()[0])

    def test_proof_names_the_engagement_with_the_lowest_id(self):
        self._add_proof()
        self.second.risk_acceptance.add(self.acceptance)
        self.first.risk_acceptance.add(self.acceptance)
        path, _ = self._path()
        self.assertEqual(reverse("download_risk_acceptance", args=(self.first.id, self.acceptance.id)), path)

    def test_prefetched_engagements_serve_the_path(self):
        self._add_proof()
        self.second.risk_acceptance.add(self.acceptance)
        self.first.risk_acceptance.add(self.acceptance)
        acceptance = Risk_Acceptance.objects.prefetch_related("engagement_set").get(pk=self.acceptance.pk)
        with CaptureQueriesContext(connection) as queries:
            path = RiskAcceptanceSerializer(context={}).get_path(acceptance)
        self.assertEqual(reverse("download_risk_acceptance", args=(self.first.id, self.acceptance.id)), path)
        self.assertEqual(0, len(queries.captured_queries))
