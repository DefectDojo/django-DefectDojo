from django.core.management.base import BaseCommand
from django.db.models import Count, Q

from dojo.models import Test


class Command(BaseCommand):
    help = "List the top 25 tests with the most findings"

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=25,
            help="Number of tests to display (default: 25)",
        )

    def handle(self, *args, **options):
        limit = options["limit"]

        # Annotate tests with finding counts
        tests = (
            Test.objects.annotate(
                total_findings=Count("finding", distinct=True),
                active_findings=Count("finding", filter=Q(finding__active=True), distinct=True),
                duplicate_findings=Count("finding", filter=Q(finding__duplicate=True), distinct=True),
            )
            .filter(total_findings__gt=0)
            .select_related("engagement", "engagement__product", "test_type")
            .order_by("-total_findings")[:limit]
        )

        if not tests:
            self.stdout.write(self.style.WARNING("No tests with findings found."))
            return

        # Calculate column widths
        max_test_id_len = max(
            (len(str(test.id)) for test in tests),
            default=8,
        )
        max_product_len = max(
            (len(str(test.engagement.product.name)) for test in tests),
            default=20,
        )
        max_engagement_len = max(
            (len(str(test.engagement.name)) for test in tests),
            default=20,
        )
        max_test_len = max(
            (len(str(test.title or test.id)) for test in tests),
            default=20,
        )
        max_test_type_len = max(
            (len(str(test.test_type.name)) for test in tests),
            default=20,
        )
        max_dedup_algo_len = max(
            (len(str(test.deduplication_algorithm)) for test in tests),
            default=20,
        )

        # Ensure minimum widths for readability
        max_test_id_len = max(max_test_id_len, 8)
        max_product_len = max(max_product_len, 20)
        max_engagement_len = max(max_engagement_len, 20)
        max_test_len = max(max_test_len, 20)
        max_test_type_len = max(max_test_type_len, 20)
        max_dedup_algo_len = max(max_dedup_algo_len, 20)

        # Header
        header = (
            f"{'Test ID':<{max_test_id_len}} | "
            f"{'Product':<{max_product_len}} | "
            f"{'Engagement':<{max_engagement_len}} | "
            f"{'Test':<{max_test_len}} | "
            f"{'Test Type':<{max_test_type_len}} | "
            f"{'Dedup Algorithm':<{max_dedup_algo_len}} | "
            f"{'Total':>8} | "
            f"{'Active':>8} | "
            f"{'Duplicate':>10}"
        )
        separator = "-" * len(header)

        self.stdout.write(self.style.SUCCESS(header))
        self.stdout.write(separator)

        # Data rows
        for test in tests:
            test_id = str(test.id)
            product_name = str(test.engagement.product.name)
            engagement_name = str(test.engagement.name)
            test_name = str(test.title or f"Test #{test.id}")
            test_type_name = str(test.test_type.name)
            dedup_algo = str(test.deduplication_algorithm)
            total = test.total_findings
            active = test.active_findings
            duplicate = test.duplicate_findings

            row = (
                f"{test_id:<{max_test_id_len}} | "
                f"{product_name:<{max_product_len}} | "
                f"{engagement_name:<{max_engagement_len}} | "
                f"{test_name:<{max_test_len}} | "
                f"{test_type_name:<{max_test_type_len}} | "
                f"{dedup_algo:<{max_dedup_algo_len}} | "
                f"{total:>8} | "
                f"{active:>8} | "
                f"{duplicate:>10}"
            )
            self.stdout.write(row)

        # Summary
        self.stdout.write(separator)
        self.stdout.write(
            self.style.SUCCESS(
                f"\nDisplayed top {len(tests)} tests with findings.",
            ),
        )
