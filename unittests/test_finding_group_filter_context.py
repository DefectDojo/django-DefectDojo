from django.test import TestCase
from django.utils.timezone import now

from dojo.filters import FindingFilter, FindingFilterWithoutObjectLookups
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Test,
    Test_Type,
)


class TestFindingGroupFilterContext(TestCase):
    """Test that Finding Group filter respects Test/Engagement/Product context."""

    @classmethod
    def setUpTestData(cls):
        """Create test data hierarchy."""
        # Create test type
        cls.test_type = Test_Type.objects.create(name="Test Type")
        
        # Create user
        cls.user = Dojo_User.objects.create(
            username="testuser",
            is_staff=True,
            is_superuser=True,
        )

        # Create Product Type
        cls.prod_type = Product_Type.objects.create(name="Product Type")

        # Create two products
        cls.product1 = Product.objects.create(
            name="Product 1",
            prod_type=cls.prod_type,
        )
        cls.product2 = Product.objects.create(
            name="Product 2",
            prod_type=cls.prod_type,
        )

        # Create engagements for each product
        cls.engagement1 = Engagement.objects.create(
            name="Engagement 1",
            product=cls.product1,
            target_start=now(),
            target_end=now(),
        )
        cls.engagement2 = Engagement.objects.create(
            name="Engagement 2",
            product=cls.product2,
            target_start=now(),
            target_end=now(),
        )
        cls.engagement3 = Engagement.objects.create(
            name="Engagement 3",
            product=cls.product1,  # Same product as engagement1
            target_start=now(),
            target_end=now(),
        )

        # Create tests for each engagement
        cls.test1 = Test.objects.create(
            title="Test 1",
            engagement=cls.engagement1,
            test_type=cls.test_type,
            target_start=now(),
            target_end=now(),
        )
        cls.test2 = Test.objects.create(
            title="Test 2",
            engagement=cls.engagement2,
            test_type=cls.test_type,
            target_start=now(),
            target_end=now(),
        )
        cls.test3 = Test.objects.create(
            title="Test 3",
            engagement=cls.engagement3,
            test_type=cls.test_type,
            target_start=now(),
            target_end=now(),
        )

        # Create finding groups in each test
        cls.group1 = Finding_Group.objects.create(
            name="Group 1",
            test=cls.test1,
            creator=cls.user,
        )
        cls.group2 = Finding_Group.objects.create(
            name="Group 2",
            test=cls.test2,
            creator=cls.user,
        )
        cls.group3 = Finding_Group.objects.create(
            name="Group 3",
            test=cls.test3,
            creator=cls.user,
        )

        # Create a finding in each group (required for group to be valid)
        cls.finding1 = Finding.objects.create(
            title="Finding 1",
            test=cls.test1,
            reporter=cls.user,
            severity="High",
            finding_group=cls.group1,
        )
        cls.finding2 = Finding.objects.create(
            title="Finding 2",
            test=cls.test2,
            reporter=cls.user,
            severity="High",
            finding_group=cls.group2,
        )
        cls.finding3 = Finding.objects.create(
            title="Finding 3",
            test=cls.test3,
            reporter=cls.user,
            severity="High",
            finding_group=cls.group3,
        )

    def test_finding_group_filter_in_test_context(self):
        """Test filter shows only groups from specific test."""
        # Create filter with test context
        finding_filter = FindingFilter(
            data={},
            queryset=Finding.objects.all(),
            user=self.user,
            tid=self.test1.id,
        )

        # Get the finding group queryset
        group_queryset = finding_filter.form.fields["finding_group"].queryset

        # Should only show group from test1
        self.assertEqual(group_queryset.count(), 1)
        self.assertIn(self.group1, group_queryset)
        self.assertNotIn(self.group2, group_queryset)
        self.assertNotIn(self.group3, group_queryset)

    def test_finding_group_filter_in_engagement_context(self):
        """Test filter shows only groups from engagement's tests."""
        # Create filter with engagement context
        finding_filter = FindingFilter(
            data={},
            queryset=Finding.objects.all(),
            user=self.user,
            eid=self.engagement1.id,
        )

        # Get the finding group queryset
        group_queryset = finding_filter.form.fields["finding_group"].queryset

        # Should only show group from engagement1's tests (test1)
        self.assertEqual(group_queryset.count(), 1)
        self.assertIn(self.group1, group_queryset)
        self.assertNotIn(self.group2, group_queryset)
        self.assertNotIn(self.group3, group_queryset)

    def test_finding_group_filter_in_product_context(self):
        """Test filter shows only groups from product's tests."""
        # Create filter with product context
        finding_filter = FindingFilter(
            data={},
            queryset=Finding.objects.all(),
            user=self.user,
            pid=self.product1.id,
        )

        # Get the finding group queryset
        group_queryset = finding_filter.form.fields["finding_group"].queryset

        # Should show groups from product1's tests (test1 and test3)
        self.assertEqual(group_queryset.count(), 2)
        self.assertIn(self.group1, group_queryset)
        self.assertIn(self.group3, group_queryset)
        self.assertNotIn(self.group2, group_queryset)

    def test_finding_group_filter_global_context(self):
        """Test filter shows all authorized groups in global context."""
        # Create filter without context
        finding_filter = FindingFilter(
            data={},
            queryset=Finding.objects.all(),
            user=self.user,
        )

        # Get the finding group queryset
        group_queryset = finding_filter.form.fields["finding_group"].queryset

        # Should show all groups (user is superuser)
        self.assertEqual(group_queryset.count(), 3)
        self.assertIn(self.group1, group_queryset)
        self.assertIn(self.group2, group_queryset)
        self.assertIn(self.group3, group_queryset)

    def test_finding_group_filter_hierarchy_precedence(self):
        """Test that test context takes precedence over engagement/product."""
        # Create filter with all contexts (test should win)
        finding_filter = FindingFilter(
            data={},
            queryset=Finding.objects.all(),
            user=self.user,
            pid=self.product1.id,
            eid=self.engagement1.id,
            tid=self.test3.id,  # Different test
        )

        # Get the finding group queryset
        group_queryset = finding_filter.form.fields["finding_group"].queryset

        # Should only show group from test3 (most specific context)
        self.assertEqual(group_queryset.count(), 1)
        self.assertIn(self.group3, group_queryset)

    def test_finding_group_filter_without_object_lookups_test_context(self):
        """Test FindingFilterWithoutObjectLookups respects test context."""
        # Create filter with test context
        finding_filter = FindingFilterWithoutObjectLookups(
            data={},
            queryset=Finding.objects.all(),
            user=self.user,
            tid=self.test1.id,
        )

        # Verify test filter fields are hidden in test context
        self.assertNotIn("test__name", finding_filter.form.fields)
        self.assertNotIn("test__engagement__name", finding_filter.form.fields)

    def test_finding_group_filter_without_object_lookups_engagement_context(self):
        """Test FindingFilterWithoutObjectLookups respects engagement context."""
        # Create filter with engagement context
        finding_filter = FindingFilterWithoutObjectLookups(
            data={},
            queryset=Finding.objects.all(),
            user=self.user,
            eid=self.engagement1.id,
        )

        # Verify engagement filter fields are hidden in engagement context
        self.assertNotIn("test__engagement__name", finding_filter.form.fields)
