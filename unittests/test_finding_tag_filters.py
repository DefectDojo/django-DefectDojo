"""
Tag filters on the findings API: same results as the JOIN-based lookups, without DISTINCT.

The JOIN form of ``tags__name`` filters made DojoFilter add a query-wide DISTINCT to the
finding list (and to its COUNT), ``tags__and`` grouped every matching row, and
``has_tags`` re-joined dojo_finding to itself per row. On large instances that cost 5-12 s
of SQL per page. Each filter now tests membership with Exists() on the tags through
table. These tests pin the result sets to the old JOIN semantics and pin the SQL shape.
"""
from django.contrib.auth.models import User
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from django_filters import BooleanFilter, CharFilter
from rest_framework.test import APIClient

from dojo.filters import ApiFindingFilter, CharFieldFilterANDExpression, CharFieldInFilter, tag_exists
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoAPITestCase, DojoTestCase


class LegacyJoinTagFilter(ApiFindingFilter):

    """The JOIN-based tag filter definitions ApiFindingFilter used before, as the reference."""

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in")
    tags__and = CharFieldFilterANDExpression(field_name="tags__name")
    test__tags = CharFieldInFilter(field_name="test__tags__name", lookup_expr="in")
    test__tags__and = CharFieldFilterANDExpression(field_name="test__tags__name")
    test__engagement__tags = CharFieldInFilter(field_name="test__engagement__tags__name", lookup_expr="in")
    test__engagement__tags__and = CharFieldFilterANDExpression(field_name="test__engagement__tags__name")
    test__engagement__product__tags = CharFieldInFilter(field_name="test__engagement__product__tags__name", lookup_expr="in")
    test__engagement__product__tags__and = CharFieldFilterANDExpression(field_name="test__engagement__product__tags__name")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in", exclude="True")
    not_test__tags = CharFieldInFilter(field_name="test__tags__name", lookup_expr="in", exclude="True")
    not_test__engagement__tags = CharFieldInFilter(field_name="test__engagement__tags__name", lookup_expr="in", exclude="True")
    not_test__engagement__product__tags = CharFieldInFilter(
        field_name="test__engagement__product__tags__name", lookup_expr="in", exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True)


def _ids(queryset):
    return sorted(queryset.values_list("id", flat=True))


@override_settings(SECURE_SSL_REDIRECT=False)
class FindingTagFilterEquivalenceTest(DojoAPITestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser("tag-filter-admin", "admin@example.com", "x")
        product_type = Product_Type.objects.create(name="Tag filter org")
        test_type = Test_Type.objects.get_or_create(name="Tag filter scan")[0]
        tests = []
        for index in range(3):
            product = Product.objects.create(name=f"Tag filter asset {index}", description="x", prod_type=product_type)
            engagement = Engagement.objects.create(
                name=f"Tag filter engagement {index}", product=product,
                target_start=timezone.now(), target_end=timezone.now())
            tests.append(Test.objects.create(
                engagement=engagement, test_type=test_type, target_start=timezone.now(), target_end=timezone.now()))
        # Tags are stored lowercase (force_lowercase), so the mixed-case query values
        # below exercise case handling, not stored case.
        layout = [
            ["alpha", "beta"],
            ["alpha", "gamma", "prod-critical"],
            ["beta"],
            ["gamma-ray"],
            [],
            ["alpha", "beta", "gamma"],
        ]
        for index, tags in enumerate(layout):
            finding = Finding.objects.create(
                title=f"Tag filter finding {index}", severity="High", test=tests[index % 3], reporter=cls.admin)
            finding.tags = tags
            finding.save()
        tests[0].tags = ["test-tag", "shared"]
        tests[0].save()
        tests[1].engagement.tags = ["eng-tag", "shared"]
        tests[1].engagement.save()
        tests[2].engagement.product.tags = ["prod-tag", "shared"]
        tests[2].engagement.product.save()

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(self.admin)
        self.base = Finding.objects.filter(title__istartswith="Tag filter finding")

    def filtered(self, filterset_class=ApiFindingFilter, **params):
        filterset = filterset_class(params, queryset=self.base)
        self.assertTrue(filterset.is_valid(), filterset.errors)
        return filterset.qs

    def assert_same_as_legacy(self, params):
        actual = self.filtered(**params)
        expected = self.filtered(LegacyJoinTagFilter, **params)
        with self.subTest(params=params):
            self.assertEqual(_ids(actual), _ids(expected))
            self.assertEqual(actual.count(), expected.count())
            # one row per finding without DISTINCT
            self.assertEqual(actual.count(), len(set(actual.values_list("id", flat=True))))

    def test_tag_contains(self):
        # icontains: case-insensitive substring
        for value in ["alpha", "ALPHA", "Gam", "ray", "a", "nomatch"]:
            self.assert_same_as_legacy({"tag": value})

    def test_not_tag(self):
        for value in ["alpha", "GAMMA", "ray", "a", "nomatch"]:
            self.assert_same_as_legacy({"not_tag": value})

    def test_tags_in(self):
        # the tagulous form field lowercases and splits on commas or spaces
        for value in ["alpha", "beta,gamma", "gamma-ray,prod-critical", "ALPHA", "Beta Gamma", "nomatch"]:
            self.assert_same_as_legacy({"tags": value})

    def test_not_tags(self):
        for value in ["alpha", "beta,gamma", "ALPHA", "nomatch"]:
            self.assert_same_as_legacy({"not_tags": value})

    def test_tags_and(self):
        # exact and case-sensitive, a set (duplicates collapse), blank elements kept
        for value in ["alpha", "alpha,beta", "alpha,beta,gamma", "beta,gamma-ray", "alpha,alpha", "ALPHA,beta", "alpha,"]:
            self.assert_same_as_legacy({"tags__and": value})

    def test_has_tags(self):
        for value in ["true", "false"]:
            self.assert_same_as_legacy({"has_tags": value})

    def test_related_model_tags(self):
        for prefix in ["test__", "test__engagement__", "test__engagement__product__"]:
            for value in ["test-tag", "ENG-TAG", "prod-tag", "shared", "test-tag,eng-tag", "nomatch"]:
                self.assert_same_as_legacy({f"{prefix}tags": value})
                self.assert_same_as_legacy({f"not_{prefix}tags": value})
                self.assert_same_as_legacy({f"{prefix}tags__and": value})

    def test_combinations_without_and_match(self):
        for params in [
            {"tags": "alpha,beta", "not_tag": "gamma"},
            {"tag": "a", "tags": "alpha,beta,gamma", "has_tags": "true"},
            {"test__tags": "shared", "test__engagement__tags": "shared", "not_tags": "beta"},
        ]:
            self.assert_same_as_legacy(params)

    def test_combined_filters_match(self):
        # tags + tags__and on the same relation: two JOINs used to multiply each other,
        # which broke the HAVING COUNT; the Exists() form is a plain intersection.
        params = {"tags": "alpha,beta", "tags__and": "alpha,beta", "not_tag": "gamma", "has_tags": "true"}
        expected = (
            self.base.filter(id__in=self.base.filter(tags__name__in=["alpha", "beta"]).values("id"))
            .filter(id__in=self.base.filter(tags__name="alpha").values("id"))
            .filter(id__in=self.base.filter(tags__name="beta").values("id"))
            .exclude(tags__name__icontains="gamma")
            .exclude(tags__isnull=True)
        )
        self.assertEqual(_ids(self.filtered(**params)), _ids(expected))
        # the legacy JOIN form drops it: HAVING COUNT(name) counted 2 x 2 joined rows, not 2
        self.assertEqual(_ids(self.filtered(LegacyJoinTagFilter, **params)), [])
        self.assertEqual(_ids(self.filtered(**params)), [self.base.get(title__iexact="Tag filter finding 0").id])

    def test_tag_filters_add_no_distinct_or_group_by(self):
        params = {
            "tag": "alpha", "tags": "alpha,beta", "tags__and": "alpha,beta", "not_tag": "x",
            "not_tags": "x,y", "has_tags": "true", "test__tags": "shared", "not_test__tags": "x",
            "test__engagement__tags__and": "shared", "test__engagement__product__tags": "shared",
        }
        for name, value in params.items():
            with self.subTest(filter=name):
                sql = str(self.filtered(**{name: value}).query).upper()
                self.assertNotIn("DISTINCT", sql)
                self.assertNotIn("GROUP BY", sql)
                # no self-join of dojo_finding inside the tag subquery
                self.assertEqual(sql.count('FROM "DOJO_FINDING"'), 1, sql)

    def test_api_list_counts_and_results(self):
        url = reverse("finding-list")
        cases = {
            "tags=alpha": Finding.objects.filter(tags__name="alpha"),
            "not_tag=ALPHA": Finding.objects.exclude(tags__name__icontains="alpha"),
            "tags__and=alpha,beta": Finding.objects.filter(tags__name="alpha").filter(tags__name="beta"),
            "has_tags=true": Finding.objects.exclude(tags__isnull=True),
            "test__engagement__product__tags=shared": Finding.objects.filter(test__engagement__product__tags__name="shared"),
        }
        for query, expected in cases.items():
            with self.subTest(query=query):
                response = self.client.get(f"{url}?{query}&limit=100", format="json")
                self.assertEqual(response.status_code, 200, response.content[:500])
                self.assertEqual(response.data["count"], expected.count())
                self.assertEqual(sorted(row["id"] for row in response.data["results"]), _ids(expected))


class TagExistsTest(DojoTestCase):

    def test_rejects_non_tag_field(self):
        with self.assertRaises(ValueError):
            tag_exists(Finding, "title", "exact", "x")

    def test_related_paths_resolve(self):
        for model, field in [(Finding, "tags__name"), (Finding, "test__engagement__product__tags__name"),
                             (Test, "engagement__tags__name"), (Engagement, "product__tags__name"), (Product, "tags__name")]:
            with self.subTest(model=model.__name__, field=field):
                self.assertIsNotNone(list(model.objects.filter(tag_exists(model, field, "in", ["x"]))))
