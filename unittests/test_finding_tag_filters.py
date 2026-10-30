"""
Tag filters on the findings API: same results as the JOIN-based lookups, without DISTINCT.

The JOIN form of ``tags__name`` filters made DojoFilter add a query-wide DISTINCT to the
finding list (and to its COUNT), ``tags__and`` grouped every matching row, and
``has_tags`` re-joined dojo_finding to itself per row. On large instances that cost 5-12 s
of SQL per page. Each filter now tests membership with Exists() on the tags through
table. These tests pin the result sets to the old JOIN semantics and pin the SQL shape.
"""
from unittest import mock
from urllib.parse import parse_qsl

from django.contrib.auth.models import User
from django.db.models import Count
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from django_filters import BooleanFilter, CharFilter
from rest_framework.test import APIClient

from dojo.filters import (
    ApiFindingFilter,
    CharFieldFilterANDExpression,
    CharFieldInFilter,
    order_with_pk_tiebreak,
    query_has_multivalued_join,
    tag_exists,
)
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
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
        # Two reviewers and two found_by test types on most findings: an ordering or filter that
        # joined either relation would return those findings twice.
        cls.reviewers = [Dojo_User.objects.create(username=f"tag-filter-reviewer-{n}") for n in range(2)]
        extra_type = Test_Type.objects.get_or_create(name="Tag filter scan 2")[0]
        for index, finding in enumerate(Finding.objects.filter(title__istartswith="Tag filter finding").order_by("id")):
            if index % 3 != 2:
                finding.reviewers.add(*cls.reviewers)
                finding.found_by.add(test_type, extra_type)
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

    # Every tag filter, alone and in the combinations a list request sends, for the page walk below.
    PAGE_WALK_FILTERS = (
        "tag=a", "tag=ALPHA", "not_tag=gamma", "tags=alpha,beta,gamma", "tags=Beta+Gamma",
        "not_tags=beta", "tags__and=alpha,beta", "tags__and=alpha,alpha,", "has_tags=true", "has_tags=false",
        "test__tags=shared", "not_test__tags=shared", "test__tags__and=test-tag,shared",
        "test__engagement__tags=shared,eng-tag", "not_test__engagement__tags=eng-tag",
        "test__engagement__tags__and=eng-tag,shared", "test__engagement__product__tags=shared,prod-tag",
        "not_test__engagement__product__tags=prod-tag", "test__engagement__product__tags__and=prod-tag,shared",
        "tags=alpha,beta&tags__and=alpha,beta", "tag=a&tags=alpha,gamma&has_tags=true&not_tags=beta",
        "tags=alpha,beta,gamma&test__engagement__product__tags=shared",
        "tags=alpha,beta,gamma&reviewers={reviewer}", "tags=alpha,beta,gamma&found_by={found_by}",
    )
    # Orderings, most of them on keys that repeat (every finding here is High, most share reviewers,
    # found_by and product): ApiFindingFilter ends each one on the pk, so page boundaries hold anyway.
    PAGE_WALK_ORDERINGS = (
        "", "&o=title", "&o=severity", "&o=-date", "&o=reviewers", "&o=-found_by", "&o=test__engagement__product__name",
        "&o=-severity,id", "&o=",
    )

    def _walk(self, query, limit=2):
        url = reverse("finding-list")
        ids, count, offset = [], None, 0
        while True:
            response = self.client.get(f"{url}?{query}&limit={limit}&offset={offset}", format="json")
            self.assertEqual(response.status_code, 200, response.content[:500])
            page = [row["id"] for row in response.data["results"]]
            count = response.data["count"] if count is None else count
            self.assertEqual(response.data["count"], count, f"{query}: count moved between pages")
            self.assertEqual(len(page), len(set(page)), f"{query}: duplicate on one page")
            ids += page
            offset += limit
            if not response.data["next"]:
                return ids, count

    def test_api_pages_never_repeat_or_skip_a_finding(self):
        # Several findings share every tag, and some findings match two or three values of one
        # filter (alpha, beta and gamma together), so any join left on tags or on reviewers /
        # found_by would multiply them. Each page walk must return every match exactly once, and
        # the count must be the number of distinct findings.
        params = {
            "reviewer": self.reviewers[0].id,
            "found_by": Test_Type.objects.get(name="Tag filter scan").id,
        }
        for template in self.PAGE_WALK_FILTERS:
            filters = template.format(**params)
            # Each filter ANDs with the others, so the expected set is the intersection of what each
            # one returns alone through the old JOIN definitions.
            expected = set(_ids(self.base))
            for key, value in parse_qsl(filters):
                expected &= set(_ids(self.filtered(LegacyJoinTagFilter, **{key: value})))
            expected = sorted(expected)
            for ordering in self.PAGE_WALK_ORDERINGS:
                for prefetch in ("", "&prefetch=reviewers,found_by,test"):
                    query = filters + ordering + prefetch
                    with self.subTest(query=query):
                        ids, count = self._walk(query)
                        self.assertEqual(len(ids), len(set(ids)), f"{query}: a finding repeats across pages")
                        self.assertEqual(sorted(ids), expected, f"{query}: pages skip or add findings")
                        self.assertEqual(count, len(expected))

    def test_distinct_kept_when_another_join_can_multiply(self):
        # The Exists() tag filters no longer bring a DISTINCT, but the old one also covered any
        # other to-many join in the query. A filter that still joins (here a plain lookup on the
        # reviewers m2m) must get its DISTINCT back when it is combined with a tag filter.
        class JoinedReviewerFilter(ApiFindingFilter):
            reviewer_name = CharFilter(field_name="reviewers__username", lookup_expr="startswith")

        params = {"tags": "alpha,beta", "reviewer_name": "tag-filter-reviewer"}
        qs = self.filtered(JoinedReviewerFilter, **params)
        self.assertIn("DISTINCT", str(qs.query).upper())
        ids = list(qs.values_list("id", flat=True))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            sorted(ids),
            _ids(self.base.filter(tags__name__in=["alpha", "beta"], reviewers__username__startswith="tag-filter-reviewer").distinct()),
        )
        # without the joined filter there is nothing to dedupe
        self.assertNotIn("DISTINCT", str(self.filtered(JoinedReviewerFilter, tags="alpha,beta").query).upper())

    def test_list_ordering_ends_on_the_pk(self):
        # FindingViewSet.filter_queryset applies order_with_pk_tiebreak to the filtered queryset.
        default = list(self.base.query.order_by) or list(Finding._meta.ordering)
        default = default if {term.lstrip("-") for term in default} & {"id", "pk"} else [*default, "pk"]
        cases = {
            # the model's default ordering (OSS: numerical_severity, -date, title, ...), plus the pk;
            # this filterset's o= keeps it
            None: default,
            "": default,
            "severity": ["severity", "pk"],
            "-reviewers": ["-_ord_reviewers", "pk"],
            "-date,id": ["-date", "id"],
            "-id": ["-id"],
        }
        for value, expected in cases.items():
            with self.subTest(o=value):
                params = {} if value is None else {"o": value}
                self.assertEqual(list(order_with_pk_tiebreak(self.filtered(**params)).query.order_by), expected)
        # An ordering filter that clears the ordering on o= (order_by() with no terms) gets pk order:
        # an unordered LIMIT/OFFSET page is not stable either.
        self.assertEqual(list(order_with_pk_tiebreak(self.base.order_by()).query.order_by), ["pk"])

    def test_filterset_leaves_ordering_alone_for_aggregations(self):
        # The tiebreak belongs to the list view only: a filterset also feeds .values() aggregations
        # (dashboards, metrics), and an explicit ORDER BY pk would join their GROUP BY.
        qs = self.filtered(o="severity", tags="alpha,beta,gamma")
        self.assertEqual(list(qs.query.order_by), ["severity"])
        grouped = list(qs.order_by().values("severity").annotate(n=Count("id")))
        self.assertEqual(grouped, [{"severity": "High", "n": qs.count()}])

    def test_multivalued_join_detection(self):
        self.assertFalse(query_has_multivalued_join(self.base.filter(test__engagement__product__name="x").query))
        self.assertTrue(query_has_multivalued_join(self.base.filter(reviewers__username="x").query))
        self.assertTrue(query_has_multivalued_join(Product.objects.filter(engagement__name="x").query))
        self.assertFalse(query_has_multivalued_join(self.base.filter(reviewers__username="x").distinct().query))
        self.assertFalse(query_has_multivalued_join(self.base.filter(tag_exists(Finding, "tags__name", "in", ["alpha"])).query))


@override_settings(SECURE_SSL_REDIRECT=False)
class OtherModelTagFiltersUnchangedTest(DojoAPITestCase):

    """
    Only the findings filterset uses the Exists() tag filters. The other lists still join tags,
    so they must keep the DISTINCT and still return each object once.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser("tag-filter-admin-2", "admin2@example.com", "x")
        product_type = Product_Type.objects.create(name="Tag filter org 2")
        test_type = Test_Type.objects.get_or_create(name="Tag filter scan")[0]
        cls.products = []
        for index in range(3):
            product = Product.objects.create(name=f"Tag filter shared {index}", description="x", prod_type=product_type)
            product.tags = ["one", "two", "three"]
            product.save()
            engagement = Engagement.objects.create(
                name=f"Tag filter shared {index}", product=product, target_start=timezone.now(), target_end=timezone.now())
            engagement.tags = ["one", "two", "three"]
            engagement.save()
            test = Test.objects.create(
                engagement=engagement, test_type=test_type, target_start=timezone.now(), target_end=timezone.now())
            test.tags = ["one", "two", "three"]
            test.save()
            cls.products.append(product)

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def test_lists_return_each_object_once(self):
        for route in ("product-list", "engagement-list", "test-list"):
            for query in ("tags=one,two,three", "tag=o", "not_tags=nomatch", "tags__and=one,two"):
                with self.subTest(route=route, query=query):
                    seen = []
                    offset = 0
                    while True:
                        response = self.client.get(f"{reverse(route)}?{query}&limit=1&offset={offset}", format="json")
                        self.assertEqual(response.status_code, 200, response.content[:500])
                        seen += [row["id"] for row in response.data["results"]]
                        offset += 1
                        if not response.data["next"]:
                            break
                    self.assertEqual(len(seen), len(set(seen)))
                    self.assertEqual(len(seen), response.data["count"])
                    self.assertGreaterEqual(len(seen), 3)

    def test_other_filtersets_keep_their_tag_filters(self):
        # The JOIN-based classes, so DojoFilter.filter_queryset still adds DISTINCT for them.
        from dojo.engagement.api.filters import ApiEngagementFilter  # noqa: PLC0415
        from dojo.product.api.filters import ApiProductFilter  # noqa: PLC0415
        from dojo.test.api.filters import ApiTestFilter  # noqa: PLC0415

        for filterset_class, model in ((ApiProductFilter, Product), (ApiEngagementFilter, Engagement), (ApiTestFilter, Test)):
            with self.subTest(filterset=filterset_class.__name__):
                self.assertTrue(getattr(filterset_class.base_filters["tags"], "multiplies_rows", True))
                qs = filterset_class({"tags": "one,two,three"}, queryset=model.objects.all()).qs
                self.assertIn("DISTINCT", str(qs.query).upper())
                ids = list(qs.values_list("id", flat=True))
                self.assertEqual(len(ids), len(set(ids)))


class TagExistsTest(DojoTestCase):

    def test_rejects_non_tag_field(self):
        with self.assertRaises(ValueError):
            tag_exists(Finding, "title", "exact", "x")

    def test_related_paths_resolve(self):
        for model, field in [(Finding, "tags__name"), (Finding, "test__engagement__product__tags__name"),
                             (Test, "engagement__tags__name"), (Engagement, "product__tags__name"), (Product, "tags__name")]:
            with self.subTest(model=model.__name__, field=field):
                self.assertIsNotNone(list(model.objects.filter(tag_exists(model, field, "in", ["x"]))))

    def test_matches_on_tag_ids_not_on_names(self):
        # The planner can only see how common a tag is when the query names its id. Joined by name, it
        # assumed the average tag and mis-planned popular ones (a 20 s COUNT instead of 2.5 s).
        finding = Finding.objects.create(
            title="Tag id finding", severity="High", reporter=User.objects.create(username="tag-id-reporter"),
            test=Test.objects.create(
                engagement=Engagement.objects.create(
                    name="Tag id engagement", target_start=timezone.now(), target_end=timezone.now(),
                    product=Product.objects.create(
                        name="Tag id asset", description="x", prod_type=Product_Type.objects.create(name="Tag id org"))),
                test_type=Test_Type.objects.get_or_create(name="Tag id scan")[0],
                target_start=timezone.now(), target_end=timezone.now()))
        finding.tags = ["tag-id-one", "tag-id-two"]
        finding.save()
        tag_model = Finding._meta.get_field("tags").related_model
        wanted = tag_model.objects.get(name="tag-id-one").pk
        for lookup, value in [("exact", "tag-id-one"), ("in", ["tag-id-one"]), ("icontains", "ID-ONE")]:
            with self.subTest(lookup=lookup):
                qs = Finding.objects.filter(tag_exists(Finding, "tags__name", lookup, value))
                sql = str(qs.query)
                subquery = sql[sql.index("EXISTS"):]
                self.assertNotIn(tag_model._meta.db_table, subquery)
                self.assertIn(f"IN ({wanted})", subquery)
                self.assertEqual(list(qs), [finding])
                self.assertNotIn(finding, Finding.objects.exclude(tag_exists(Finding, "tags__name", lookup, value)))

    def test_an_unknown_tag_matches_nothing_and_its_negation_everything(self):
        everything = Finding.objects.count()
        self.assertEqual(Finding.objects.filter(tag_exists(Finding, "tags__name", "in", ["no-such-tag"])).count(), 0)
        self.assertEqual(
            Finding.objects.filter(~tag_exists(Finding, "tags__name", "in", ["no-such-tag"])).count(), everything)

    def test_a_lookup_matching_many_tags_keeps_the_name_join(self):
        tag_model = Finding._meta.get_field("tags").related_model
        tag_model.objects.bulk_create(
            [tag_model(name=f"many-tags-{n}", slug=f"many-tags-{n}") for n in range(4)])
        with mock.patch("dojo.filters.TAG_ID_LITERAL_LIMIT", 3):
            sql = str(Finding.objects.filter(tag_exists(Finding, "tags__name", "icontains", "many-tags")).query)
        self.assertIn(tag_model._meta.db_table, sql[sql.index("EXISTS"):])
