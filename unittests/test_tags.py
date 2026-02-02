import logging
import random
from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse

from dojo.models import Finding, Product, Test
from dojo.product.helpers import propagate_tags_on_product_sync
from unittests.dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path, versioned_fixtures

logger = logging.getLogger(__name__)


@versioned_fixtures
class TagTests(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self, *args, **kwargs):
        super().setUp()
        self.login_as_admin()
        self.zap_sample5_filename = get_unit_tests_scans_path("zap") / "5_zap_sample_one.xml"
        self.generic_sample_with_tags_filename = get_unit_tests_scans_path("generic") / "generic_report1.json"
        self.generic_sample_with_more_tags_filename = get_unit_tests_scans_path("generic") / "generic_report1_more_tags.json"

    def test_create_product_with_tags(self, expected_status_code: int = 201):
        product_id = Product.objects.all().first().id
        product_details = self.get_product_api(product_id)

        del product_details["id"]

        product_details["name"] = "tags test " + str(random.randint(1, 9999))  # noqa: S311
        product_details["tags"] = ["tag1", "tag2"]
        response = self.post_new_product_api(product_details, expected_status_code=expected_status_code)

        self.assertEqual(response["tags"], product_details["tags"])

    def test_put_product_with_tags(self):
        product_id = Product.objects.all().first().id
        product_details = self.get_product_api(product_id)

        del product_details["id"]

        product_details["name"] = "tags test " + str(random.randint(1, 9999))  # noqa: S311
        product_details["tags"] = ["tag4", "tag5"]
        response = self.put_product_api(product_id, product_details, expected_status_code=200)

        self.assertEqual(response["tags"], product_details["tags"])

    def test_patch_product_with_tags(self):
        product_id = Product.objects.all().first().id
        product_details = self.get_product_api(product_id)

        del product_details["id"]

        product_details["tags"] = ["tag9", "tag10"]
        response = self.patch_product_api(product_id, product_details, expected_status_code=200)

        self.assertEqual(response["tags"], product_details["tags"])

    def test_patch_product_with_invalid_tags(self):
        product_id = Product.objects.all().first().id

        product_details = {"tags": ["'tag9"]}
        self.patch_product_api(product_id, product_details, expected_status_code=400)
        product_details["tags"] = ["tag 10"]
        self.patch_product_api(product_id, product_details, expected_status_code=400)
        product_details["tags"] = ["tagA,tagB"]
        # since https://github.com/DefectDojo/django-DefectDojo/pull/12434 tags are split again by commas
        response = self.patch_product_api(product_id, product_details, expected_status_code=200)
        self.assertEqual(response["tags"], ["tagA", "tagB"])

    def create_finding_with_tags(self, tags: list[str], expected_status_code: int = 201):
        finding_id = Finding.objects.all().first().id
        finding_details = self.get_finding_api(finding_id)

        del finding_details["id"]

        finding_details["title"] = "tags test " + str(random.randint(1, 9999))  # noqa: S311
        finding_details["tags"] = tags
        response = self.post_new_finding_api(finding_details, expected_status_code=expected_status_code)

        return response["id"] if expected_status_code == 201 else 0

    def test_finding_get_tags(self):
        tags = ["tag1", "tag2"]
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        self.assertEqual(len(tags), len(response.get("tags", None)))
        for tag in tags:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertIn(tag, response["tags"])

    def test_finding_filter_tags(self):
        tags = ["tag1", "tag2"]
        self.create_finding_with_tags(tags)

        tags2 = ["tag1", "tag3"]
        self.create_finding_with_tags(tags2)

        response = self.get_finding_api_filter_tags("tag1")
        self.assertEqual(response["count"], 2)

        response = self.get_finding_api_filter_tags("tag2")
        self.assertEqual(response["count"], 1)

        response = self.get_finding_api_filter_tags("tag2,tag3")
        self.assertEqual(response["count"], 2)

        response = self.get_finding_api_filter_tags("tag4")
        self.assertEqual(response["count"], 0)
        # Test the tags__and filter for a case with no matches
        response = self.get_finding_api_filter_tags("tag2,tag3", parameter="tags__and")
        self.assertEqual(response["count"], 0)
        # Test the tags__and filter for a case with one exact match
        response = self.get_finding_api_filter_tags("tag1,tag2", parameter="tags__and")
        self.assertEqual(response["count"], 1)

    def test_finding_post_tags(self):
        # create finding
        tags = ["tag1", "tag2"]
        finding_id = self.create_finding_with_tags(tags)

        # post tags. POST will ADD tags to existing tags (which is possibly not REST compliant?)
        tags_new = ["tag3", "tag4"]
        response = self.post_finding_tags_api(finding_id, tags_new)
        tags_merged = list(set(tags) | set(tags_new))
        self.assertEqual(len(tags_merged), len(response.get("tags")))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertIn(tag, response["tags"])

    def test_finding_post_tags_overlap(self):
        # create finding
        tags = ["tag1", "tag2"]
        finding_id = self.create_finding_with_tags(tags)

        # post tags. POST will ADD tags to existing tags (which is possibly not REST compliant?)
        tags_new = ["tag2", "tag3"]
        response = self.post_finding_tags_api(finding_id, tags_new)
        tags_merged = list(set(tags) | set(tags_new))
        self.assertEqual(len(tags_merged), len(response.get("tags")))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertIn(tag, response["tags"])

    def test_finding_put_remove_tags(self):
        # create finding
        tags = ["tag1", "tag2"]
        finding_id = self.create_finding_with_tags(tags)

        # post tags. PUT will remove any tags that exist
        tags_remove = ["tag1"]
        response = self.put_finding_remove_tags_api(finding_id, tags_remove)

        # for some reason this method returns just a message, not the remaining tags
        self.assertEqual(response["success"], "Tag(s) Removed")

        # retrieve finding and check
        tags_merged = list(set(tags) - set(tags_remove))
        response = self.get_finding_tags_api(finding_id)
        self.assertEqual(len(tags_merged), len(response.get("tags")))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertIn(tag, response["tags"])

    def test_finding_put_remove_tags_all(self):
        # create finding
        tags = ["tag1", "tag2"]
        finding_id = self.create_finding_with_tags(tags)

        # post tags. PUT will remove any tags that exist
        tags_remove = tags
        response = self.put_finding_remove_tags_api(finding_id, tags_remove)

        # for some reason this method returns just a message, not the remaining tags
        self.assertEqual(response["success"], "Tag(s) Removed")

        # retrieve finding and check
        tags_merged = list(set(tags) - set(tags_remove))
        response = self.get_finding_tags_api(finding_id)
        self.assertEqual(len(tags_merged), len(response.get("tags")))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertIn(tag, response["tags"])

    def test_finding_put_remove_tags_non_existent(self):
        # create finding
        tags = ["tag1", "tag2"]
        finding_id = self.create_finding_with_tags(tags)

        # post tags. PUT will throw an error on non-existent tag to be removed (which is maybe not what we want?)
        tags_remove = ["tag5"]
        response = self.put_finding_remove_tags_api(finding_id, tags_remove, expected_response_status_code=400)

        # for some reason this method returns just a message, not the remaining tags
        self.assertEqual(response["error"], "'tag5' is not a valid tag in list '['tag1', 'tag2']'")

        # retrieve finding and check
        tags_merged = list(set(tags) - set(tags_remove))
        response = self.get_finding_tags_api(finding_id)
        self.assertEqual(len(tags_merged), len(response.get("tags")))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertIn(tag, response["tags"])

    def test_finding_patch_remove_tags(self):
        # has same logic as PUT
        return self.test_finding_put_remove_tags()

    def test_finding_patch_remove_tags_all(self):
        return self.test_finding_put_remove_tags_all()

    def test_finding_patch_remove_tags_non_existent(self):
        return self.test_finding_put_remove_tags_non_existent()

    def test_finding_create_tags_with_commas(self):
        tags = ["one,two"]
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        # since https://github.com/DefectDojo/django-DefectDojo/pull/12434 tags are split again by commas
        self.assertEqual(["one", "two"], response.get("tags"))
        self.assertEqual(2, len(response.get("tags")))
        self.assertIn("one", str(response["tags"]))
        self.assertIn("two", str(response["tags"]))

    def test_finding_create_tags_with_spaces(self):
        tags = ["one two"]
        self.create_finding_with_tags(tags, expected_status_code=400)

    def test_finding_create_tags_with_double_quotes(self):
        tags = ['"one-two"']
        self.create_finding_with_tags(tags, expected_status_code=400)

    def test_finding_create_tags_with_single_quotes(self):
        tags = ["'one-two'"]
        self.create_finding_with_tags(tags, expected_status_code=400)

    def test_finding_create_tags_with_slashes(self):
        tags = ["a/b/c"]
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        self.assertEqual(len(tags), len(response.get("tags", None)))
        for tag in tags:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertIn(tag, response["tags"])

    def test_import_multipart_tags(self):
        """API-specific test for multipart form data tag handling."""
        with (self.zap_sample5_filename).open(encoding="utf-8") as testfile:
            data = {
                "engagement": [1],
                "file": [testfile],
                "scan_type": ["ZAP Scan"],
                "tags": ["bug,security", "urgent"],  # Attempting to mimic the two "tag" fields (-F 'tags=tag1' -F 'tags=tag2')
            }
            response = self.import_scan(data, 201)
            # Make sure the serializer returns the correct tags
            success_tags = ["bug", "security", "urgent"]
            self.assertEqual(response["tags"], success_tags)
            # Check that the test has the same issue
            test_id = response["test"]
            response = self.get_test_api(test_id)
            self.assertEqual(len(success_tags), len(response.get("tags")))
            for tag in success_tags:
                self.assertIn(tag, response["tags"])


class TagImportMixin:

    """Mixin containing import/reimport tag tests that can be run via API or UI."""

    def setUp(self):
        self.zap_sample5_filename = get_unit_tests_scans_path("zap") / "5_zap_sample_one.xml"
        self.generic_sample_with_tags_filename = get_unit_tests_scans_path("generic") / "generic_report1.json"
        self.generic_sample_with_more_tags_filename = get_unit_tests_scans_path("generic") / "generic_report1_more_tags.json"

    def test_import_and_reimport_with_tags(self):
        """Test that tags passed as import parameter are applied to the test."""
        tags = ["tag1", "tag2"]
        import0 = self.import_scan_with_params(self.zap_sample5_filename, tags=tags)
        test_id = import0["test"]

        response = self.get_test_api(test_id)

        self.assertEqual(len(tags), len(response.get("tags")))
        for tag in tags:
            self.assertIn(tag, response["tags"])

        # reimport, do not specify tags: should retain tags
        self.reimport_scan_with_params(test_id, self.zap_sample5_filename)
        self.assertEqual(len(tags), len(response.get("tags")))
        for tag in tags:
            self.assertIn(tag, response["tags"])

        # reimport, specify tags others: currently reimport doesn't do anything with tags param and silently ignores them
        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, tags=["tag3", "tag4"])
        self.assertEqual(len(tags), len(response.get("tags")))
        for tag in tags:
            self.assertIn(tag, response["tags"])

    def test_import_report_with_tags(self):
        """Test that parser-generated tags on findings are preserved during import/reimport."""
        def assert_tags_in_findings(findings: list[dict], expected_finding_count: int, desired_tags: list[str]) -> None:
            self.assertEqual(expected_finding_count, len(findings))
            for finding in findings:
                self.assertEqual(len(desired_tags), len(finding.get("tags")))
                for tag in desired_tags:
                    self.assertIn(tag, finding["tags"])

        # Import a report with findings that have tags
        import0 = self.import_scan_with_params(self.generic_sample_with_tags_filename, scan_type="Generic Findings Import")
        test_id = import0["test"]
        response = self.get_test_findings_api(test_id)
        findings = response["results"]
        # Make sure we have what we are looking for
        assert_tags_in_findings(findings, 2, ["security", "network"])
        # Reimport with a different report that has more tags
        self.reimport_scan_with_params(test_id, self.generic_sample_with_more_tags_filename, scan_type="Generic Findings Import")
        response = self.get_test_findings_api(test_id)
        findings = response["results"]
        # Make sure we have what we are looking for
        assert_tags_in_findings(findings, 2, ["security", "network", "hardened"])


@versioned_fixtures
class TagImportTestAPI(DojoAPITestCase, TagImportMixin):

    """Test tag handling during import/reimport via API."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        TagImportMixin.setUp(self)


@versioned_fixtures
class TagImportTestUI(DojoAPITestCase, TagImportMixin):

    """Test tag handling during import/reimport via UI."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        self.client_ui = Client()
        self.client_ui.force_login(self.get_test_admin())
        TagImportMixin.setUp(self)

    def import_scan_with_params(self, filename, scan_type="ZAP Scan", engagement=1, minimum_severity="Low", *,
                                active=True, verified=False, tags=None, close_old_findings=False, **kwargs):
        """Override to use UI import instead of API."""
        with Path(filename).open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "active": "force_to_true" if active else "force_to_false",
                "verified": "force_to_true" if verified else "force_to_false",
                "scan_type": scan_type,
                "file": testfile,
                "environment": 1,
                "close_old_findings": close_old_findings,
            }
            if tags is not None:
                # Tagulous form field expects comma-separated string
                payload["tags"] = ",".join(tags) if isinstance(tags, list) else tags

            response = self.client_ui.post(reverse("import_scan_results", args=(engagement,)), payload)
            self.assertEqual(302, response.status_code, response.content[:1000])
            test_id = int(response.url.split("/")[-1])
            return {"test": test_id}

    def reimport_scan_with_params(self, test_id, filename, scan_type="ZAP Scan", minimum_severity="Low", *,
                                  active=True, verified=False, tags=None, close_old_findings=True, **kwargs):
        """Override to use UI reimport instead of API."""
        with Path(filename).open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "active": "force_to_true" if active else "force_to_false",
                "verified": "force_to_true" if verified else "force_to_false",
                "scan_type": scan_type,
                "file": testfile,
                "close_old_findings": close_old_findings,
            }
            if tags is not None:
                # Tagulous form field expects comma-separated string
                payload["tags"] = ",".join(tags) if isinstance(tags, list) else tags

            response = self.client_ui.post(reverse("re_import_scan_results", args=(test_id,)), payload)
            self.assertEqual(302, response.status_code, response.content[:1000])
            new_test_id = int(response.url.split("/")[-1])
            return {"test": new_test_id}


@versioned_fixtures
class InheritedTagsTests(DojoAPITestCase):

    """Non-import tests for inherited tags functionality."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self, *args, **kwargs):
        super().setUp()
        self.login_as_admin()
        self.system_settings(enable_product_tag_inheritance=True)
        self.product = self.create_product("Inherited Tags Test", tags=["inherit", "these", "tags"])
        self.scans_path = get_unit_tests_scans_path("zap")
        self.zap_sample5_filename = self.scans_path / "5_zap_sample_one.xml"

    def _convert_instance_tags_to_list(self, instance) -> list:
        return [tag.name for tag in instance.tags.all()]

    def test_new_engagement_then_add_tag_to_engagement_then_remove_tag_to_engagement(self):
        # Create the engagement
        engagement = self.create_engagement("Inherited Tags Engagement", self.product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan")
        # Check to see if tags match the product
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(engagement))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(test))
        # Add a tag on the engagement)
        engagement_tags_before_addition = self._convert_instance_tags_to_list(engagement)
        engagement.tags.add("engagement_only_tag")
        # Check to see that the update was successful
        self.assertEqual(["engagement_only_tag", *engagement_tags_before_addition], self._convert_instance_tags_to_list(engagement))
        # Check to see that tests were not impacted
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(test))
        # remove a tag on the engagement
        engagement_tags_before_removal = self._convert_instance_tags_to_list(engagement)
        engagement.tags.remove("engagement_only_tag")
        # Check to see that the update was successful
        engagement_tags_before_removal.remove("engagement_only_tag")
        self.assertEqual(engagement_tags_before_removal, self._convert_instance_tags_to_list(engagement))
        # Check to see that tests were not impacted
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(test))

    def test_new_engagement_then_remove_inherited_tag(self):
        # Create the engagement
        engagement = self.create_engagement("Inherited Tags Engagement", self.product)
        # Check to see if tags match the product
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(engagement))
        # Remove an inherited tag
        engagement_tags_before_removal = self._convert_instance_tags_to_list(engagement)
        engagement.tags.remove("inherit")
        # Check to see that the inherited tag could not be removed
        self.assertEqual(engagement_tags_before_removal, self._convert_instance_tags_to_list(engagement))


class InheritedTagsImportMixin:

    """Mixin containing inherited tags import/reimport tests that can be run via API or UI."""

    def setUp(self):
        self.system_settings(enable_product_tag_inheritance=True)
        self.product = self.create_product("Inherited Tags Test", tags=["inherit", "these", "tags"])
        self.scans_path = get_unit_tests_scans_path("zap")
        self.zap_sample5_filename = self.scans_path / "5_zap_sample_one.xml"

    def _convert_instance_tags_to_list(self, instance) -> list:
        return [tag.name for tag in instance.tags.all()]

    def _import_and_return_objects(self, test_id=None, *, reimport=False, tags=None) -> dict:
        # Import some findings to create all objects
        engagement = self.create_engagement("Inherited Tags Engagement", self.product)
        if reimport:
            response = self.reimport_scan_with_params(test_id, self.zap_sample5_filename, tags=tags)
        else:
            response = self.import_scan_with_params(self.zap_sample5_filename, engagement=engagement.id, tags=tags)

        test_id = response["test"]
        test = Test.objects.get(id=test_id)
        finding = Finding.objects.filter(test=test).first()
        location = self._get_location(finding)
        return {
            "engagement": engagement,
            "location": location,
            "test": test,
            "finding": finding,
        }

    def _get_location(self, finding):
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            return finding.endpoints.all().first()
        return finding.locations.all().first().location

    def test_import_without_tags(self):
        # Import some findings to create all objects
        objects = self._import_and_return_objects()
        # Check that the tags all match what the product has
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))

    def test_import_with_tags_then_reimport_with_different_tag(self):
        # Import some findings to create all objects
        objects = self._import_and_return_objects(tags=["import_tag"])
        # Check that the tags all match what the product has
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(["import_tag", *product_tags], self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))
        # Reimport now
        objects = self._import_and_return_objects(test_id=objects.get("test").id, reimport=True, tags=["reimport_tag"])
        # Check that the tags all match what the product has
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))
        # Make a copy of the list becase of the need for the lists to be exact (index for index)
        product_tags_plus_reimport_tag = product_tags.copy()
        product_tags_plus_reimport_tag.insert(1, "reimport_tag")
        self.assertEqual(product_tags_plus_reimport_tag, self._convert_instance_tags_to_list(objects.get("test")))

    def test_remove_tag_from_product_then_add_tag_to_product(self):
        # Import some findings to create all objects
        objects = self._import_and_return_objects()
        # Check that the tags all match what the product has
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))
        # Remove a tag from the product
        self.product.tags.remove("inherit")
        # This triggers an async function with celery that will fail, so run it manually here
        propagate_tags_on_product_sync(self.product)
        # Save the tags post removal
        product_tags_post_removal = self._convert_instance_tags_to_list(self.product)
        # Check that the tags all match what the product has
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("finding")))
        # Add a tag from the product
        self.product.tags.add("more", "tags!")
        # This triggers an async function with celery that will fail, so run it manually here
        propagate_tags_on_product_sync(self.product)
        # Save the tags post removal
        product_tags_post_addition = self._convert_instance_tags_to_list(self.product)
        # Check that the tags all match what the product has
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("finding")))


@versioned_fixtures
class InheritedTagsImportTestAPI(DojoAPITestCase, InheritedTagsImportMixin):

    """Test inherited tags during import/reimport via API."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        InheritedTagsImportMixin.setUp(self)


@versioned_fixtures
class InheritedTagsImportTestUI(DojoAPITestCase, InheritedTagsImportMixin):

    """Test inherited tags during import/reimport via UI."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        self.client_ui = Client()
        self.client_ui.force_login(self.get_test_admin())
        InheritedTagsImportMixin.setUp(self)

    def import_scan_with_params(self, filename, scan_type="ZAP Scan", engagement=1, minimum_severity="Low", *,
                                active=True, verified=False, tags=None, close_old_findings=False, **kwargs):
        """Override to use UI import instead of API."""
        with Path(filename).open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "active": "force_to_true" if active else "force_to_false",
                "verified": "force_to_true" if verified else "force_to_false",
                "scan_type": scan_type,
                "file": testfile,
                "environment": 1,
                "close_old_findings": close_old_findings,
            }
            if tags is not None:
                # Tagulous form field expects comma-separated string
                payload["tags"] = ",".join(tags) if isinstance(tags, list) else tags

            response = self.client_ui.post(reverse("import_scan_results", args=(engagement,)), payload)
            self.assertEqual(302, response.status_code, response.content[:1000])
            test_id = int(response.url.split("/")[-1])
            return {"test": test_id}

    def reimport_scan_with_params(self, test_id, filename, scan_type="ZAP Scan", minimum_severity="Low", *,
                                  active=True, verified=False, tags=None, close_old_findings=True, **kwargs):
        """Override to use UI reimport instead of API."""
        with Path(filename).open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "active": "force_to_true" if active else "force_to_false",
                "verified": "force_to_true" if verified else "force_to_false",
                "scan_type": scan_type,
                "file": testfile,
                "close_old_findings": close_old_findings,
            }
            if tags is not None:
                # Tagulous form field expects comma-separated string
                payload["tags"] = ",".join(tags) if isinstance(tags, list) else tags

            response = self.client_ui.post(reverse("re_import_scan_results", args=(test_id,)), payload)
            self.assertEqual(302, response.status_code, response.content[:1000])
            new_test_id = int(response.url.split("/")[-1])
            return {"test": new_test_id}
