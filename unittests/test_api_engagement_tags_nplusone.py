from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now
from rest_framework.test import APITestCase

from dojo.models import (
    Dojo_User,
    Engagement,
    Product,
    Product_Type,
)


class TestEngagementListTagsNPlusOne(APITestCase):

    """
    Regression: the engagements list serializes each row's tags through
    TagListSerializerField, but EngagementViewSet.get_queryset did not
    prefetch_related("tags"). Every engagement on the page cost one extra query
    to load its tags, so the query count grew with the number of engagements
    returned. TestsViewSet already prefetches "tags" for this exact reason; this
    pins the engagement list to the same behaviour.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(
            username="eng_tags_np1_user", is_staff=True, is_superuser=True,
        )
        cls.product_type = Product_Type.objects.create(name="Eng Tags NP1 PT")
        cls.product = Product.objects.create(
            name="Eng Tags NP1 Product", prod_type=cls.product_type, description="np1",
        )

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def _add_engagement(self, index):
        engagement = Engagement.objects.create(
            name=f"Eng Tags NP1 {index}",
            product=self.product,
            target_start=now(),
            target_end=now(),
        )
        # Two tags per row, one of them shared, so the serialized tag set is non-trivial.
        engagement.tags.set([f"np1-tag-{index}", "np1-shared"])
        return engagement

    def _list(self):
        url = f"/api/v2/engagements/?product={self.product.id}&limit=100"
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content[:1000])
        return response, len(ctx.captured_queries)

    def test_engagement_list_query_count_independent_of_row_count(self):
        self._add_engagement(0)
        self._list()  # warm-up: fills ContentType and other first-request caches
        _, with_one = self._list()
        for i in range(1, 5):
            self._add_engagement(i)
        response, with_five = self._list()
        # The page now serializes five engagements, each carrying tags.
        self.assertEqual(response.json()["count"], 5)
        self.assertEqual(
            with_one, with_five,
            f"engagements list ran {with_five - with_one} extra queries for 4 extra "
            f"rows: tags are loaded per row instead of being prefetched",
        )

    def test_engagement_list_still_returns_each_rows_tags(self):
        engagement = self._add_engagement(99)
        response, _ = self._list()
        row = next(r for r in response.json()["results"] if r["id"] == engagement.id)
        self.assertEqual(sorted(row["tags"]), ["np1-shared", "np1-tag-99"])
