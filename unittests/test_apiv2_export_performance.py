import base64
from unittest.mock import patch

import pghistory
from auditlog.models import LogEntry
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.files.base import ContentFile
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from dojo.endpoint.models import Endpoint_Status
from dojo.endpoint.utils import endpoint_get_or_create
from dojo.finding.helper import save_vulnerability_ids
from dojo.location.feature import locations_enabled
from dojo.location.models import Location, LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import (
    Answered_Survey,
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Benchmark_Type,
    BurpRawRequestResponse,
    Check_List,
    Choice,
    ChoiceAnswer,
    ChoiceQuestion,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Engagement,
    Engagement_Survey,
    FileUpload,
    Finding,
    Finding_Group,
    Finding_Template,
    General_Survey,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Notes,
    Objects_Product,
    Objects_Review,
    Product,
    Risk_Acceptance,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    TextAnswer,
    TextQuestion,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures

# Keyed on locations_enabled(). Each batch of findings runs one query per prefetch in finding_queryset(): notes,
# their history, vulnerability_references, finding_cwe_set, reviewers, found_by, risk_acceptance_set, tags,
# jira_issue, finding_group_set, finding_group_set__jira_issue, files, burprawrequestresponse_set and finding_meta (14).
# Django skips a nested level (finding_group_set__jira_issue, locations__location, locations__location__tags) when
# the batch has no row at the level above it, so add_findings gives every finding a group and two endpoints.
QUERIES_PER_FINDING_BATCH = {
    # Locations mode adds locations, locations__location and locations__location__tags.
    True: 17,
    # Endpoints mode adds status_finding (with its endpoint joined) and endpoint__tags.
    False: 16,
}

# One page of product_endpoint lines is the page query, a prefetch of the tags and a prefetch of the metadata, in both
# modes. A page with no row runs the page query only.
PRODUCT_ENDPOINT_QUERIES_PER_PAGE = 3


@versioned_fixtures
class TestProductExportQueryCount(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.login_as_admin()
        self.admin = Dojo_User.objects.get(username="admin")
        self.product = Product.objects.get(id=2)
        self.url = reverse("export-product", args=[2])
        b"".join(self.client.get(self.url).streaming_content)

    def add_findings(self, product: Product, count: int, prefix: str) -> None:
        test = Test.objects.filter(engagement__product=product).order_by("id").first()
        risk_acceptance = Risk_Acceptance.objects.create(name=prefix, owner=self.admin)
        test.engagement.risk_acceptance.add(risk_acceptance)
        for i in range(count):
            finding = Finding.objects.create(title=f"{prefix}-{i}", test=test, reporter=self.admin, severity="High")
            finding.tags = "perf_a, perf_b"
            finding.save()
            save_vulnerability_ids(finding, [f"CVE-2024-{i:04d}"])
            for n in range(2):
                if locations_enabled():
                    url = URL.get_or_create_from_object(URL.from_value(f"https://{prefix}-{i}-{n}.example"))
                    url.location.associate_with_finding(finding)
                else:
                    endpoint, _ = endpoint_get_or_create(host=f"{prefix}-{i}-{n}.example", product=product)
                    Endpoint_Status.objects.create(finding=finding, endpoint=endpoint)
            finding.notes.add(Notes.objects.create(entry=f"{prefix}-{i}", author=self.admin))
            file_upload = FileUpload.objects.create(title="poc.txt", file=ContentFile(b"hello", name="poc.txt"))
            self.addCleanup(file_upload.file.storage.delete, file_upload.file.name)
            finding.files.add(file_upload)
            Finding_Group.objects.create(name=f"{prefix}-{i}", test=test, creator=self.admin).findings.add(finding)
            DojoMeta.objects.create(finding=finding, name="k", value="v")
            BurpRawRequestResponse.objects.create(
                finding=finding,
                burpRequestBase64=base64.b64encode(b"GET / HTTP/1.1"),
                burpResponseBase64=base64.b64encode(b"HTTP/1.1 200 OK"),
            )
            risk_acceptance.accepted_findings.add(finding)

    def add_owners(self, product: Product, count: int, prefix: str) -> None:
        now = timezone.now()
        for i in range(count):
            engagement = Engagement.objects.create(
                name=f"{prefix}-{i}", product=product, target_start=now.date(), target_end=now.date(), lead=self.admin,
            )
            test = Test.objects.create(
                title=f"{prefix}-{i}", engagement=engagement, test_type=Test_Type.objects.first(), target_start=now, target_end=now,
            )
            risk_acceptance = Risk_Acceptance.objects.create(name=f"{prefix}-{i}", owner=self.admin)
            engagement.risk_acceptance.add(risk_acceptance)
            for owner in (engagement, test, risk_acceptance):
                owner.notes.add(Notes.objects.create(entry=f"{prefix}-{i}", author=self.admin))
            finding = Finding.objects.create(title=f"{prefix}-{i}", test=test, reporter=self.admin, severity="Low")
            risk_acceptance.accepted_findings.add(finding)
            Check_List.objects.create(engagement=engagement).session_issues.add(finding)

    def add_imports(self, product: Product, count: int, prefix: str) -> None:
        test = Test.objects.filter(engagement__product=product).order_by("id").first()
        for i in range(count):
            test_import = Test_Import.objects.create(test=test, type="reimport", import_settings={"n": i})
            for n in range(2):
                finding = Finding.objects.create(title=f"{prefix}-{i}-{n}", test=test, reporter=self.admin, severity="Low")
                Test_Import_Finding_Action.objects.create(test_import=test_import, finding=finding, action="N")

    def add_audit_history(self, product: Product, count: int, prefix: str) -> None:
        test = Test.objects.filter(engagement__product=product).order_by("id").first()
        content_type = ContentType.objects.get_for_model(Finding)
        for i in range(count):
            finding = Finding.objects.create(title=f"{prefix}-{i}", test=test, reporter=self.admin, severity="Low")
            with pghistory.context(user=self.admin.id):
                finding.title = f"{prefix}-{i} edited"
                finding.save()
            LogEntry.objects.create(
                content_type=content_type, object_pk=str(finding.id), object_id=finding.id, object_repr="F", action=1, changes={},
            )
            risk_acceptance = Risk_Acceptance.objects.create(name=f"{prefix}-{i}", owner=self.admin)
            risk_acceptance.accepted_findings.add(finding)

    def add_surveys_and_benchmarks(self, count: int, prefix: str) -> None:
        for i in range(count):
            survey = Engagement_Survey.objects.create(name=f"{prefix}-{i}")
            text = TextQuestion.objects.create(text=f"{prefix}-{i} text")
            pick = ChoiceQuestion.objects.create(text=f"{prefix}-{i} pick", multichoice=True)
            choices = [Choice.objects.create(order=n, label=f"{prefix}-{i}-{n}") for n in range(2)]
            pick.choices.add(*choices)
            survey.questions.add(text, pick)
            General_Survey.objects.create(survey=survey)
            response = Answered_Survey.objects.create(survey=survey, assignee=self.admin, responder=self.admin)
            TextAnswer.objects.create(question=text, answered_survey=response, answer="a")
            ChoiceAnswer.objects.create(question=pick, answered_survey=response).answer.add(*choices)
            benchmark = Benchmark_Type.objects.create(name=f"{prefix}-{i}", version="1")
            for n in range(2):
                category = Benchmark_Category.objects.create(type=benchmark, name=f"{prefix}-{i}-{n}", objective="o")
                Benchmark_Requirement.objects.create(category=category, objective="o")

    def add_jira(self, product: Product, count: int, prefix: str) -> None:
        instance = JIRA_Instance.objects.create(
            configuration_name="Main", url="https://jira.example.com", username="bot", password="x", epic_name_id=1,  # noqa: S106
            open_status_key=1, close_status_key=2, info_mapping_severity="a", low_mapping_severity="a",
            medium_mapping_severity="a", high_mapping_severity="a", critical_mapping_severity="a",
        )
        now = timezone.now()
        for i in range(count):
            engagement = Engagement.objects.create(
                name=f"{prefix}-{i}", product=product, target_start=now.date(), target_end=now.date(), lead=self.admin,
            )
            project = JIRA_Project.objects.create(jira_instance=instance, engagement=engagement, project_key=f"{prefix}{i}")
            JIRA_Issue.objects.create(jira_project=project, engagement=engagement, jira_id=f"{prefix}-e{i}", jira_key=f"E-{i}")
            JIRA_Project.objects.create(jira_instance=instance, product=product, project_key=f"{prefix}p{i}")
            test = Test.objects.create(
                title=f"{prefix}-{i}", engagement=engagement, test_type=Test_Type.objects.first(), target_start=now, target_end=now,
            )
            finding = Finding.objects.create(title=f"{prefix}-{i}", test=test, reporter=self.admin, severity="Low")
            JIRA_Issue.objects.create(jira_project=project, finding=finding, jira_id=f"{prefix}-f{i}", jira_key=f"F-{i}")

    def add_product_extras(self, product: Product, count: int, prefix: str) -> None:
        engagement = Engagement.objects.filter(product=product).order_by("id").first()
        for i in range(count):
            tracking_file = Objects_Product.objects.create(
                product=product, name=f"{prefix}-{i}", review_status=Objects_Review.objects.create(name=f"{prefix}-{i}"),
            )
            tracking_file.tags.add("perf_a", "perf_b")
            benchmark = Benchmark_Type.objects.create(name=f"{prefix}-{i}", version="1")
            category = Benchmark_Category.objects.create(type=benchmark, name=f"{prefix}-{i}", objective="o")
            for n in range(2):
                result = Benchmark_Product.objects.create(
                    product=product, control=Benchmark_Requirement.objects.create(category=category, objective="o"),
                )
                result.notes.add(Notes.objects.create(entry=f"{prefix}-{i}-{n}", author=self.admin))
            Benchmark_Product_Summary.objects.create(product=product, benchmark_type=benchmark)
            survey = Engagement_Survey.objects.create(name=f"{prefix}-{i}")
            text = TextQuestion.objects.create(text=f"{prefix}-{i} text")
            pick = ChoiceQuestion.objects.create(text=f"{prefix}-{i} pick", multichoice=True)
            choices = [Choice.objects.create(order=n, label=f"{prefix}-{i}-{n}") for n in range(2)]
            pick.choices.add(*choices)
            survey.questions.add(text, pick)
            response = Answered_Survey.objects.create(survey=survey, engagement=engagement, assignee=self.admin, responder=self.admin)
            TextAnswer.objects.create(question=text, answered_survey=response, answer="a")
            ChoiceAnswer.objects.create(question=pick, answered_survey=response).answer.add(*choices)

    def grow_product_endpoints(self, product: Product, total: int) -> None:
        count = total - (LocationProductReference if locations_enabled() else Endpoint).objects.filter(product=product).count()
        prefix = f"g{total}"
        if locations_enabled():
            owners = Location.objects.bulk_create(
                Location(location_type="url", location_value=f"https://{prefix}-{i}.example") for i in range(count)
            )
            LocationProductReference.objects.bulk_create(
                LocationProductReference(location=owner, product=product, status=ProductLocationStatus.Active) for owner in owners
            )
            DojoMeta.objects.bulk_create(
                [DojoMeta(location=owner, location_product=product, name="k", value="v") for owner in owners]
                + [DojoMeta(location=owner, name="z", value="v") for owner in owners],
            )
            model = Location
        else:
            owners = Endpoint.objects.bulk_create(
                Endpoint(product=product, protocol="https", host=f"{prefix}-{i}.example") for i in range(count)
            )
            DojoMeta.objects.bulk_create(DojoMeta(endpoint=owner, name="k", value="v") for owner in owners)
            model = Endpoint
        field = model._meta.get_field("tags")
        owner_column, tag_column = (column.name for column in field.remote_field.through._meta.fields if column.name != "id")
        tags = [field.related_model.objects.get_or_create(name=name)[0] for name in ("perf_a", "perf_b")]
        field.remote_field.through.objects.bulk_create(
            field.remote_field.through(**{owner_column: owner, tag_column: tag}) for owner in owners for tag in tags
        )

    def measure(self, url) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(url)
            if response.streaming:
                b"".join(response.streaming_content)
        self.assertEqual(200, response.status_code)
        return len(ctx)

    def test_query_count_is_constant_within_a_batch(self):
        self.add_findings(self.product, 8, "a")
        q_a = self.measure(self.url)
        self.add_findings(self.product, 8, "b")
        q_b = self.measure(self.url)
        self.assertEqual(q_a, q_b, f"The export stream issues {q_a} queries with 8 added findings and {q_b} with 16.")

    def test_query_count_per_batch_is_pinned(self):
        with patch("dojo.export.api.views.EXPORT_CHUNK_SIZE", 4):
            self.add_findings(self.product, 4, "c")
            q_1 = self.measure(self.url)
            self.add_findings(self.product, 4, "d")
            q_2 = self.measure(self.url)
        self.assertEqual(QUERIES_PER_FINDING_BATCH[locations_enabled()], q_2 - q_1, f"{q_1} queries before the extra batch, {q_2} after.")

    def test_query_count_is_constant_across_engagements_tests_and_risk_acceptances(self):
        self.add_owners(self.product, 4, "f")
        q_a = self.measure(self.url)
        self.add_owners(self.product, 4, "g")
        q_b = self.measure(self.url)
        self.assertEqual(q_a, q_b, f"The export stream issues {q_a} queries with 4 added engagements and {q_b} with 8.")

    def test_manifest_query_count_is_constant(self):
        url = reverse("export-manifest")
        self.add_finding_templates(1, "t")
        before = self.measure(url)
        self.add_findings(self.product, 8, "e")
        self.create_product("perf", prod_type=self.product.prod_type)
        self.add_finding_templates(20, "u")
        after = self.measure(url)
        self.assertEqual(before, after, f"The manifest issues {before} queries before the added data and {after} after.")

    def add_finding_templates(self, count, prefix):
        for i in range(count):
            template = Finding_Template.objects.create(title=f"{prefix} template {i}", severity="High")
            template.tags.add(f"{prefix}-tag-{i}")

    def test_manifest_query_count_is_constant_with_group_permissions(self):
        url = reverse("export-manifest")
        group = Group.objects.create(name="perf configuration group")
        group.permissions.set(Permission.objects.filter(codename__in=["add_user", "view_user"]))
        Dojo_User.objects.get(username="user1").groups.add(group)
        before = self.measure(url)
        for i in range(4):
            Dojo_User.objects.create(username=f"perf-group-{i}").groups.add(group)
        after = self.measure(url)
        self.assertEqual(before, after, f"The manifest issues {before} queries before the added group members and {after} after.")

    def test_manifest_queries_do_not_grow_with_questionnaires_or_benchmarks(self):
        url = reverse("export-manifest")
        self.add_surveys_and_benchmarks(1, "n")
        self.measure(url)
        one = self.measure(url)
        self.add_surveys_and_benchmarks(9, "o")
        ten = self.measure(url)
        self.assertEqual(one, ten, f"The manifest issues {one} queries with one questionnaire and type and {ten} with ten.")

    def test_manifest_query_count_is_constant_with_import_history(self):
        url = reverse("export-manifest") + "?import_history=true"
        before = self.measure(url)
        self.add_imports(self.product, 4, "h")
        after = self.measure(url)
        self.assertEqual(before, after, f"The manifest issues {before} queries before the added imports and {after} after.")

    def test_stream_query_count_is_constant_across_imports_with_import_history(self):
        url = self.url + "?import_history=true"
        self.add_imports(self.product, 4, "i")
        q_a = self.measure(url)
        self.add_imports(self.product, 4, "j")
        q_b = self.measure(url)
        self.assertEqual(q_a, q_b, f"The export stream issues {q_a} queries with 4 added imports and {q_b} with 8.")

    def test_manifest_query_count_is_constant_with_audit_history(self):
        url = reverse("export-manifest") + "?audit_history=true"
        self.measure(url)
        before = self.measure(url)
        self.add_audit_history(self.product, 4, "k")
        after = self.measure(url)
        self.assertEqual(before, after, f"The manifest issues {before} queries before the added history and {after} after.")

    def test_stream_query_count_is_constant_across_audit_history(self):
        url = self.url + "?audit_history=true"
        self.measure(url)
        self.add_audit_history(self.product, 4, "l")
        q_a = self.measure(url)
        self.add_audit_history(self.product, 4, "m")
        q_b = self.measure(url)
        self.assertEqual(q_a, q_b, f"The export stream issues {q_a} queries with 4 added findings of history and {q_b} with 8.")

    def test_stream_query_count_is_constant_across_product_extras(self):
        url = self.url + "?product_extras=true"
        self.add_product_extras(self.product, 1, "p")
        self.measure(url)
        one = self.measure(url)
        self.add_product_extras(self.product, 9, "q")
        ten = self.measure(url)
        self.assertEqual(one, ten, f"The export stream issues {one} queries with one row of each extra line and {ten} with ten.")

    def test_manifest_query_count_is_constant_with_product_extras(self):
        url = reverse("export-manifest") + "?product_extras=true"
        self.add_product_extras(self.product, 1, "r")
        self.measure(url)
        before = self.measure(url)
        self.add_product_extras(self.product, 4, "s")
        after = self.measure(url)
        self.assertEqual(before, after, f"The manifest issues {before} queries with one row of each extra and {after} with five.")

    def test_stream_query_count_is_constant_across_jira(self):
        url = self.url + "?jira=true"
        self.add_jira(self.product, 1, "j")
        self.measure(url)
        one = self.measure(url)
        self.add_jira(self.product, 9, "k")
        ten = self.measure(url)
        self.assertEqual(one, ten, f"The export stream issues {one} queries with one row of Jira data and {ten} with ten.")

    def test_manifest_query_count_is_constant_with_jira(self):
        url = reverse("export-manifest") + "?jira=true"
        self.add_jira(self.product, 1, "l")
        self.measure(url)
        before = self.measure(url)
        self.add_jira(self.product, 4, "m")
        after = self.measure(url)
        self.assertEqual(before, after, f"The manifest issues {before} queries with one row of Jira data and {after} with five.")

    def test_stream_query_count_is_constant_per_page_of_product_endpoints(self):
        url = self.url + "?product_extras=true"
        self.measure(url)
        queries = {}
        for total in (100, 499, 500, 2500, 3000):
            self.grow_product_endpoints(self.product, total)
            queries[total] = self.measure(url)
        self.assertEqual(queries[100], queries[499], f"One page costs {queries[100]} queries with 100 rows and {queries[499]} with 499.")
        per_page = queries[3000] - queries[2500]
        self.assertEqual(PRODUCT_ENDPOINT_QUERIES_PER_PAGE, per_page, f"The queries by row count: {queries}.")
        self.assertEqual(4 * per_page, queries[2500] - queries[500], f"The queries by row count: {queries}.")
