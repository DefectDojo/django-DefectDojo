from unittest.mock import patch

from django.apps import apps
from django.contrib.admin.utils import NestedObjects
from django.contrib.auth.models import Permission
from django.db import DEFAULT_DB_ALIAS, connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.api_v2.mixins import DELETE_PREVIEW_MAX_PAGE_SIZE
from dojo.models import (
    Answered_Survey,
    Choice,
    ChoiceAnswer,
    ChoiceQuestion,
    Endpoint,
    Engagement,
    Engagement_Survey,
    Finding,
    Notes,
    Product,
    Regulation,
    Test,
    TextAnswer,
    TextQuestion,
    User,
)
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class DeletePreviewPermissionTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.author = User.objects.create(username="delete-preview-author")
        note = Notes.objects.create(entry="delete preview note", author=self.author)
        Finding.objects.get(id=2).notes.add(note)

        self.viewer = User.objects.create(username="delete-preview-viewer")
        self.viewer.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="view_user"))
        self.viewer = User.objects.get(pk=self.viewer.pk)

    def _client(self, user):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get_or_create(user=user)[0].key)
        return client

    def test_view_permission_allows_detail_but_not_delete_preview(self):
        client = self._client(self.viewer)
        response = client.get(reverse("user-detail", args=(self.author.id,)))
        self.assertEqual(200, response.status_code, response.content[:500])

        response = client.get(reverse("user-delete-preview", args=(self.author.id,)))
        self.assertEqual(403, response.status_code, response.content[:500])
        self.assertNotIn(b"delete preview note", response.content)

    def test_delete_permission_allows_delete_preview(self):
        self.viewer.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="delete_user"))
        self.viewer = User.objects.get(pk=self.viewer.pk)
        response = self._client(self.viewer).get(reverse("user-delete-preview", args=(self.author.id,)))
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_superuser_delete_preview(self):
        admin = User.objects.get(username="admin")
        response = self._client(admin).get(reverse("user-delete-preview", args=(self.author.id,)))
        self.assertEqual(200, response.status_code, response.content[:500])
        self.assertIn("Notes", [row["model"] for row in response.json()["results"]])


@versioned_fixtures
class DeletePreviewBoundTest(DojoTestCase):

    """
    delete_preview pages through the cascade in SQL and renders only the page asked for.

    It used to load and render every object a delete would remove before paginating, which on a
    product with millions of findings ran for many minutes and held gigabytes of memory.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.admin = User.objects.get(username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get_or_create(user=self.admin)[0].key)
        self.test = Test.objects.get(id=3)
        Finding.objects.bulk_create(
            Finding(
                test=self.test,
                title=f"Bounded preview finding {i}",
                severity="Low",
                numerical_severity="S3",
                reporter=self.admin,
                date=self.test.target_start.date(),
            )
            for i in range(DELETE_PREVIEW_MAX_PAGE_SIZE + 10)
        )

    def _preview(self, basename, pk, **params):
        response = self.client.get(reverse(f"{basename}-delete-preview", args=(pk,)), params)
        self.assertEqual(200, response.status_code, response.content[:500])
        return response.json()

    def _collector_rows(self, obj):
        """What Django's deletion Collector would remove, as (model, id) pairs."""
        with Endpoint.allow_endpoint_init():
            collector = NestedObjects(using=DEFAULT_DB_ALIAS)
            collector.collect([obj])

            def flatten(elem):
                if isinstance(elem, list):
                    for child in elem:
                        yield from flatten(child)
                else:
                    yield elem

            return sorted((type(x).__name__, getattr(x, "id", None)) for x in flatten(collector.nested()))

    def _all_pages(self, basename, pk):
        rows, offset = [], 0
        while True:
            page = self._preview(basename, pk, limit=100, offset=offset)
            rows.extend((row["model"], row["id"]) for row in page["results"])
            offset += 100
            if offset >= page["count"]:
                return sorted(rows), page["count"]

    def test_renders_only_the_requested_page(self):
        with patch.object(Finding, "__str__", autospec=True, side_effect=lambda finding: finding.title) as rendered:
            body = self._preview("test", self.test.id, limit=5)
        self.assertLessEqual(rendered.call_count, 5)
        self.assertEqual(5, len(body["results"]))
        self.assertEqual(len(self._collector_rows(self.test)), body["count"])

    def test_page_size_is_capped(self):
        body = self._preview("test", self.test.id, limit=100000)
        self.assertGreater(body["count"], DELETE_PREVIEW_MAX_PAGE_SIZE)
        self.assertEqual(DELETE_PREVIEW_MAX_PAGE_SIZE, len(body["results"]))
        self.assertIsNotNone(body["next"])

    def test_pages_list_what_the_collector_would_delete(self):
        for basename, obj in (
            ("product", Product.objects.get(id=2)),
            ("test", self.test),
            ("user", User.objects.create(username="delete-preview-bound-user")),
        ):
            with self.subTest(basename=basename):
                Notes.objects.create(entry="preview note", author=self.admin)
                rows, count = self._all_pages(basename, obj.id)
                expected = self._collector_rows(obj)
                self.assertEqual(expected, rows)
                self.assertEqual(len(expected), count)

    def test_polymorphic_survey_answers_match_what_the_collector_would_delete(self):
        # Answered_Survey -> Answer -> TextAnswer/ChoiceAnswer sit behind django-polymorphic's PolymorphicGuard
        # (a wrapped CASCADE), and the answers are multi-table children of Answer.
        engagement = Engagement.objects.filter(product_id=2).first()
        text_question = TextQuestion.objects.create(text="Preview text question", order=1)
        choice_question = ChoiceQuestion.objects.create(text="Preview choice question", order=2)
        choice = Choice.objects.create(label="Preview choice", order=1)
        choice_question.choices.add(choice)
        questionnaire = Engagement_Survey.objects.create(name="Preview questionnaire", description="d")
        questionnaire.questions.add(text_question, choice_question)
        answered = Answered_Survey.objects.create(survey=questionnaire, engagement=engagement, completed=True)
        text_answer = TextAnswer.objects.create(question=text_question, answered_survey=answered, answer="yes")
        choice_answer = ChoiceAnswer.objects.create(question=choice_question, answered_survey=answered)
        choice_answer.answer.add(choice)

        for basename, obj in (("engagement", engagement), ("product", Product.objects.get(id=2))):
            with self.subTest(basename=basename), self.assertNoLogs("dojo.api_v2.mixins", "WARNING"):
                rows, count = self._all_pages(basename, obj.id)
                self.assertEqual(self._collector_rows(obj), rows)
                self.assertEqual(len(rows), count)
                for row in (
                    ("Answered_Survey", answered.id),
                    ("Answer", text_answer.id),
                    ("TextAnswer", text_answer.id),
                    ("Answer", choice_answer.id),
                    ("ChoiceAnswer", choice_answer.id),
                ):
                    self.assertIn(row, rows)

    def test_no_model_has_a_generic_relation(self):
        # The Collector also deletes rows a GenericRelation points at; delete_preview_querysets does not walk
        # them. If this fails, teach the walk that relation before adding it.
        generic = [
            f"{model._meta.label}.{field.name}"
            for model in apps.get_models()
            for field in model._meta.private_fields
            if hasattr(field, "bulk_related_objects")
        ]
        self.assertEqual([], generic)

    def test_cascade_subqueries_are_not_sorted(self):
        # A model's Meta.ordering inside an IN (SELECT ...) makes Postgres sort every parent row on each
        # walk step: on a product with millions of findings each one took seconds.
        with CaptureQueriesContext(connection) as captured:
            self._preview("product", 2)
        walk_queries = [query["sql"] for query in captured.captured_queries if "IN (SELECT" in query["sql"]]
        self.assertTrue(walk_queries)
        for sql in walk_queries:
            self.assertLessEqual(sql.count("ORDER BY"), 1, sql)

    def test_cascade_deeper_than_the_guard_stops_walking(self):
        with patch("dojo.api_v2.mixins.DELETE_PREVIEW_MAX_DEPTH", 0), self.assertLogs("dojo.api_v2.mixins", "WARNING"):
            rows, _ = self._all_pages("product", 2)
        models = {model for model, _ in rows}
        self.assertIn("Engagement", models)
        self.assertNotIn("Test", models)

    def test_root_object_comes_first(self):
        body = self._preview("product", 2, limit=1)
        self.assertEqual([{"model": "Product", "id": 2, "name": str(Product.objects.get(id=2))}], body["results"])


@versioned_fixtures
class DeletePreviewConfigurationPermissionTest(DojoTestCase):

    """Configuration viewsets guarded by BaseDjangoModelPermission hold delete_preview to the delete permission."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.regulation = Regulation.objects.create(name="Delete preview regulation", acronym="DPR", category="privacy", jurisdiction="EU")
        self.user = User.objects.create(username="delete-preview-regulation-user")

    def _client(self, codenames):
        self.user.user_permissions.set(Permission.objects.filter(content_type__app_label="dojo", codename__in=codenames))
        user = User.objects.get(pk=self.user.pk)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get_or_create(user=user)[0].key)
        return client

    def test_view_permission_allows_detail_but_not_delete_preview(self):
        client = self._client(["view_regulation"])
        self.assertEqual(200, client.get(reverse("regulations-detail", args=(self.regulation.id,))).status_code)
        self.assertEqual(403, client.get(reverse("regulations-delete-preview", args=(self.regulation.id,))).status_code)

    def test_delete_permission_allows_delete_preview(self):
        client = self._client(["view_regulation", "delete_regulation"])
        self.assertEqual(200, client.get(reverse("regulations-delete-preview", args=(self.regulation.id,))).status_code)
