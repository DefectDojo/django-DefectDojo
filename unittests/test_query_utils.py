from django.db.models import Count

from dojo.engagement.views import prefetch_for_view_tests
from dojo.models import Finding, Test
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestQueryUtils(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_prefetch_for_view_tests_finding_counts_match_direct_count(self):
        test = Test.objects.annotate(finding_count=Count("finding")).filter(finding_count__gt=1).first()
        # If fixtures ever change, ensure we still have a representative test case.
        self.assertIsNotNone(test)

        annotated = prefetch_for_view_tests(Test.objects.filter(id=test.id))
        annotated_count = annotated.values_list("count_findings_test_all", flat=True).get()

        direct_count = Finding.objects.filter(test_id=test.id).count()
        self.assertEqual(annotated_count, direct_count)
