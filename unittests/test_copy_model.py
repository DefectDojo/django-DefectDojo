from django.db import models
from dojo.models import Endpoint, Endpoint_Status, Engagement, Finding, Product, Test, User

from .dojo_test_case import DojoTestCase


class EqualityHelpers:
    def compare_querysets(self, queryset_1, queryset_2):
        """
        Compares two querysets and returns True if all fields (excluding primary key)
        are equal for each model instance in both querysets. Otherwise, returns False.
        """
        # Make sure the querysets are the same length
        if queryset_1.count() != queryset_2.count():
            return False
        # Get the model class from the queryset
        model_class = queryset_1.model
        # Create sets of field names excluding the primary key (ID)
        field_names = [f.name for f in model_class._meta.get_fields() if not isinstance(f, models.AutoField)]
        # Sort the querysets to compare them in order (if needed)
        queryset_1 = queryset_1.order_by(*field_names)
        queryset_2 = queryset_2.order_by(*field_names)
        # Compare the fields of each model instance in the querysets
        for obj1, obj2 in zip(queryset_1, queryset_2):
            # Compare each field in the model, skipping the primary key
            for field in field_names:
                if getattr(obj1, field) != getattr(obj2, field):
                    return False
        return True


class TestCopyFindingModel(DojoTestCase, EqualityHelpers):

    def test_duplicate_finding_same_test(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_finding", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        finding = Finding.objects.create(test=test, reporter=user)
        # Do the counting
        current_finding_count = Finding.objects.filter(test=test).count()
        # Do the copy
        finding_copy = finding.copy(test=test)
        # Make sure the copy was made without error
        self.assertEqual(current_finding_count + 1, Finding.objects.filter(test=test).count())
        # Are the findings the same
        self.assertEqual(finding.hash_code, finding_copy.hash_code)

    def test_duplicate_finding_different_test(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_finding", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test1 = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test1")
        test2 = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test2")
        finding = Finding.objects.create(test=test1, reporter=user)
        # Do the counting
        engagement_finding_count = Finding.objects.filter(test__engagement=engagement).count()
        # Do the copy
        finding_copy = finding.copy(test=test2)
        # Make sure the copy was made without error
        self.assertEqual(Finding.objects.filter(test=test1).count(), Finding.objects.filter(test=test2).count())
        # Are the findings the same
        self.assertEqual(finding.hash_code, finding_copy.hash_code)
        # Does the engagement have more findings
        self.assertEqual(engagement_finding_count + 1, Finding.objects.filter(test__engagement=engagement).count())

    def test_duplicate_finding_with_tags(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_finding", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        finding = Finding.objects.create(test=test, reporter=user)
        finding.unsaved_tags = ["test_tag"]
        finding.save()
        # Do the counting
        current_finding_count = Finding.objects.filter(test=test).count()
        # Do the copy
        finding_copy = finding.copy(test=test)
        # Make sure the copy was made without error
        self.assertEqual(current_finding_count + 1, Finding.objects.filter(test=test).count())
        # Do the tags match
        self.assertEqual(finding.tags, finding_copy.tags)

    def test_duplicate_finding_with_notes(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_finding", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        finding = Finding.objects.create(test=test, reporter=user)
        finding.unsaved_notes = ["test_note"]
        finding.save()
        # Do the counting
        current_finding_count = Finding.objects.filter(test=test).count()
        # Do the copy
        finding_copy = finding.copy(test=test)
        # Make sure the copy was made without error
        self.assertEqual(current_finding_count + 1, Finding.objects.filter(test=test).count())
        # Do the notes match
        self.assertTrue(self.compare_querysets(finding.notes.all(), finding_copy.notes.all()))

    def test_duplicate_finding_with_tags_and_notes(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_finding", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        finding = Finding.objects.create(test=test, reporter=user)
        finding.unsaved_tags = ["test_tag"]
        finding.unsaved_notes = ["test_note"]
        finding.save()
        # Do the counting
        current_finding_count = Finding.objects.filter(test=test).count()
        # Do the copy
        finding_copy = finding.copy(test=test)
        # Make sure the copy was made without error
        self.assertEqual(current_finding_count + 1, Finding.objects.filter(test=test).count())
        # Do the tags match
        self.assertEqual(finding.tags, finding_copy.tags)
        # Do the notes match
        self.assertTrue(self.compare_querysets(finding.notes.all(), finding_copy.notes.all()))

    def test_duplicate_finding_with_endpoints(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_finding", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        endpoint = Endpoint.from_uri("0.0.0.0")  # noqa: S104
        endpoint.save()
        finding = Finding.objects.create(test=test, reporter=user)
        endpoint_status = Endpoint_Status.objects.create(finding=finding, endpoint=endpoint)
        # Do the counting
        current_finding_count = Finding.objects.filter(test=test).count()
        current_endpoint_finding_count = endpoint.findings_count
        current_endpoint_count = Endpoint.objects.all().count()
        current_endpoint_status_count = Endpoint_Status.objects.filter(endpoint=endpoint).count()
        # Do the copy
        finding_copy = finding.copy(test=test)
        # Make sure the copy was made without error
        self.assertEqual(current_finding_count + 1, Finding.objects.filter(test=test).count())
        # Make sure the number of endpoints stayed the same
        self.assertEqual(current_endpoint_count, Endpoint.objects.all().count())
        # Make sure the number of findings on the endpoint grew
        self.assertEqual(current_endpoint_finding_count + 1, endpoint.findings_count)
        # Make sure the number of endpoint status objects grew
        self.assertEqual(current_endpoint_status_count + 1, Endpoint_Status.objects.filter(endpoint=endpoint).count())
        # Make sure the endpoint status objects point at different findings
        self.assertNotEqual(endpoint_status, finding_copy.status_finding.all().first())


class TestCopyTestModel(DojoTestCase, EqualityHelpers):

    def test_duplicate_test_same_enagagement(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        # Do the counting
        current_test_count = Test.objects.filter(engagement=engagement).count()
        current_test_finding_count = Finding.objects.filter(test=test).count()
        current_engagement_finding_count = Finding.objects.filter(test__engagement=engagement).count()
        # Do the copy
        test_copy = test.copy(engagement=engagement)
        # Make sure the copy was made without error
        self.assertEqual(current_test_count + 1, Test.objects.filter(engagement=engagement).count())
        # Do the tests have the same number of findings
        self.assertEqual(current_test_finding_count, Finding.objects.filter(test=test_copy).count())
        # Make sure the engagement has more findings
        self.assertEqual(current_engagement_finding_count + 1, Finding.objects.filter(test__engagement=engagement).count())

    def test_duplicate_tests_different_engagements(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement1 = self.create_engagement("eng1", product)
        engagement2 = self.create_engagement("eng2", product)
        test = self.create_test(engagement=engagement1, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        # Do the counting
        product_finding_count = Finding.objects.filter(test__engagement__product=product).count()
        # Do the copy
        test_copy = test.copy(engagement=engagement2)
        # Make sure the copy was made without error
        self.assertEqual(Test.objects.filter(engagement=engagement1).count(), Test.objects.filter(engagement=engagement2).count())
        # Do the enagements have the same number of findings
        self.assertEqual(Finding.objects.filter(test__engagement=engagement1).count(), Finding.objects.filter(test__engagement=engagement2).count())
        # Are the tests equal
        self.assertEqual(test.title, test_copy.title)
        self.assertEqual(test.scan_type, test_copy.scan_type)
        self.assertEqual(test.test_type, test_copy.test_type)
        # Does the product thave more findings
        self.assertEqual(product_finding_count + 1, Finding.objects.filter(test__engagement__product=product).count())

    def test_duplicate_test_with_tags(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        test.unsaved_tags = ["test_tag"]
        test.save()
        # Do the counting
        current_test_count = Test.objects.filter(engagement=engagement).count()
        # Do the copy
        test_copy = test.copy(engagement=engagement)
        # Make sure the copy was made without error
        self.assertEqual(current_test_count + 1, Test.objects.filter(engagement=engagement).count())
        # Do the tags match
        self.assertEqual(test.tags, test_copy.tags)

    def test_duplicate_test_with_notes(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        test.unsaved_notes = ["test_note"]
        test.save()
        # Do the counting
        current_test_count = Test.objects.filter(engagement=engagement).count()
        # Do the copy
        test_copy = test.copy(engagement=engagement)
        # Make sure the copy was made without error
        self.assertEqual(current_test_count + 1, Test.objects.filter(engagement=engagement).count())
        # Do the notes match
        self.assertTrue(self.compare_querysets(test.notes.all(), test_copy.notes.all()))

    def test_duplicate_test_with_tags_and_notes(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        test.unsaved_tags = ["test_tag"]
        test.unsaved_notes = ["test_note"]
        test.save()
        # Do the counting
        current_test_count = Test.objects.filter(engagement=engagement).count()
        # Do the copy
        test_copy = test.copy(engagement=engagement)
        # Make sure the copy was made without error
        self.assertEqual(current_test_count + 1, Test.objects.filter(engagement=engagement).count())
        # Do the notes match
        self.assertTrue(self.compare_querysets(test.notes.all(), test_copy.notes.all()))
        # Do the tags match
        self.assertEqual(test.tags, test_copy.tags)


class TestCopyEngagementModel(DojoTestCase, EqualityHelpers):

    def test_duplicate_engagement(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        # Do the counting
        current_product_count = Product.objects.filter(prod_type=product_type).count()
        current_engagement_finding_count = Finding.objects.filter(test__engagement=engagement).count()
        current_engagement_product_finding_count = Finding.objects.filter(test__engagement__product=product).count()
        # Do the copy
        engagement_copy = engagement.copy()
        # Make sure the copy was made without error
        self.assertEqual(current_product_count + 1, Engagement.objects.filter(product=product).count())
        # Do the tests have the same number of findings
        self.assertEqual(current_engagement_finding_count, Finding.objects.filter(test__engagement=engagement_copy).count())
        # Make sure the product has more findings
        self.assertEqual(current_engagement_product_finding_count + 1, Finding.objects.filter(test__engagement__product=product).count())

    def test_duplicate_engagement_with_tags(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        engagement.unsaved_tags = ["test_tag"]
        engagement.save()
        # Do the counting
        current_engagement_count = Engagement.objects.filter(product=product).count()
        # Do the copy
        engagement_copy = engagement.copy()
        # Make sure the copy was made without error
        self.assertEqual(current_engagement_count + 1, Engagement.objects.filter(product=product).count())
        # Do the tags match
        self.assertEqual(engagement.tags, engagement_copy.tags)

    def test_duplicate_engagement_with_notes(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        engagement.unsaved_notes = ["test_note"]
        engagement.save()
        # Do the counting
        current_engagement_count = Engagement.objects.filter(product=product).count()
        # Do the copy
        engagement_copy = engagement.copy()
        # Make sure the copy was made without error
        self.assertEqual(current_engagement_count + 1, Engagement.objects.filter(product=product).count())
        # Do the notes match
        self.assertTrue(self.compare_querysets(engagement.notes.all(), engagement_copy.notes.all()))

    def test_duplicate_engagement_with_tags_and_notes(self):
        # Set the scene
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("prod_type")
        product = self.create_product("test_deuplicate_test", prod_type=product_type)
        engagement = self.create_engagement("eng", product)
        test = self.create_test(engagement=engagement, scan_type="NPM Audit Scan", title="test")
        _ = Finding.objects.create(test=test, reporter=user)
        engagement.unsaved_tags = ["test_tag"]
        engagement.unsaved_notes = ["test_note"]
        engagement.save()
        # Do the counting
        current_engagement_count = Engagement.objects.filter(product=product).count()
        # Do the copy
        engagement_copy = engagement.copy()
        # Make sure the copy was made without error
        self.assertEqual(current_engagement_count + 1, Engagement.objects.filter(product=product).count())
        # Do the notes match
        self.assertTrue(self.compare_querysets(engagement.notes.all(), engagement_copy.notes.all()))
        # Do the tags match
        self.assertEqual(engagement.tags, engagement_copy.tags)
