from datetime import datetime, timedelta

from crum import impersonate

from dojo.models import DojoMeta, Engagement, Finding, Test, User

from .dojo_test_case import DojoTestCase


class TestFindingModel(DojoTestCase):

    def test_get_sast_source_file_path_with_link_no_file_path(self):
        finding = Finding()
        self.assertEqual(None, finding.get_sast_source_file_path_with_link())

    def test_get_sast_source_file_path_with_link_no_source_code_management_uri(self):
        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.sast_source_file_path = "SastSourceFilePath"
        self.assertEqual("SastSourceFilePath", finding.get_sast_source_file_path_with_link())

    def test_get_sast_source_file_path_with_link_and_source_code_management_uri(self):
        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.sast_source_file_path = "SastSourceFilePath"
        engagement.source_code_management_uri = "URL"
        self.assertEqual('<a href="URL/SastSourceFilePath" target="_blank" title="SastSourceFilePath">SastSourceFilePath</a>', finding.get_sast_source_file_path_with_link())

    def test_get_file_path_with_link_no_file_path(self):
        finding = Finding()
        self.assertEqual(None, finding.get_file_path_with_link())

    def test_get_file_path_with_link_no_source_code_management_uri(self):
        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.file_path = "FilePath"
        self.assertEqual("FilePath", finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri(self):
        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.file_path = "FilePath"
        engagement.source_code_management_uri = "URL"
        self.assertEqual('<a href="URL/FilePath" target="_blank" title="FilePath">FilePath</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_github_no_scm_type_with_details_and_line(self):
        # checks that for github.com in uri dojo makes correct url to browse on github

        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        engagement.commit_hash = "some-commit-hash"
        engagement.branch_tag = "some-branch"
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432
        engagement.source_code_management_uri = "https://github.com/some-test-account/some-test-repo"
        self.assertEqual('<a href="https://github.com/some-test-account/some-test-repo/blob/some-commit-hash/some-folder/some-file.ext#L5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_github_with_scm_type_with_details_and_line(self):
        # checks that for github in custom field dojo makes correct url to browse on github

        # create scm-type custom field with value "github"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="github")
        product_metadata.save()

        # create finding with scm uri and commit hash, branch and line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        engagement.commit_hash = "some-commit-hash"
        engagement.branch_tag = "some-branch"
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://github.com/some-test-account/some-test-repo"
        self.assertEqual('<a href="https://github.com/some-test-account/some-test-repo/blob/some-commit-hash/some-folder/some-file.ext#L5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_bitbucket_public_project_with_no_details_and_line(self):
        # checks that for public bitbucket (bitbucket.org) in custom field
        # dojo makes correct url to browse on public bitbucket (for project uri)

        # create scm-type custom field with value "bitbucket"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="bitbucket")
        product_metadata.save()

        # create finding with scm uri line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://bb.example.com/some-test-user/some-test-repo.git"
        self.assertEqual('<a href="https://bb.example.com/some-test-user/some-test-repo/src/master/some-folder/some-file.ext#lines-5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_bitbucket_public_project_with_commithash_and_line(self):
        # checks that for public bitbucket (bitbucket.org) in custom field  and existing commit hash in finding
        # dojo makes correct url to browse on public bitbucket (for project uri)

        # create scm-type custom field with value "bitbucket"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="bitbucket")
        product_metadata.save()

        # create finding with scm uri and commit hash, branch and line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        engagement.commit_hash = "some-commit-hash"
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://bb.example.com/some-test-user/some-test-repo.git"
        self.assertEqual('<a href="https://bb.example.com/some-test-user/some-test-repo/src/some-commit-hash/some-folder/some-file.ext#lines-5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_bitbucket_standalone_project_with_commithash_and_line(self):
        # checks that for standalone bitbucket in custom field  and existing commit hash in finding
        # dojo makes correct url to browse on standalone/onpremise bitbucket (for project uri)

        # create scm-type custom field with value "bitbucket-standalone"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="bitbucket-standalone")
        product_metadata.save()

        # create finding with scm uri and commit hash, branch and line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        engagement.commit_hash = "some-commit-hash"
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://bb.example.com/scm/some-test-project/some-test-repo.git"
        self.assertEqual('<a href="https://bb.example.com/projects/some-test-project/repos/some-test-repo/browse/some-folder/some-file.ext?at=some-commit-hash#5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_bitbucket_standalone_project_with_branchtag_and_line(self):
        # checks that for standalone bitbucket in custom field  and existing branch/tag in finding
        # dojo makes correct url to browse on standalone/onpremise bitbucket (for project uri)

        # create scm-type custom field with value "bitbucket-standalone"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="bitbucket-standalone")
        product_metadata.save()

        # create finding with scm uri and commit hash, branch and line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        engagement.branch_tag = "some-branch"
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://bb.example.com/scm/some-test-project/some-test-repo.git"
        self.assertEqual('<a href="https://bb.example.com/projects/some-test-project/repos/some-test-repo/browse/some-folder/some-file.ext?at=some-branch#5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_bitbucket_standalone_user_with_branchtag_and_line(self):
        # checks that for standalone bitbucket in custom field  and existing branch/tag in finding
        # dojo makes correct url to browse on standalone/onpremise bitbucket (for user uri)

        # create scm-type custom field with value "bitbucket-standalone"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="bitbucket-standalone")
        product_metadata.save()

        # create finding with scm uri and commit hash, branch and line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        engagement.branch_tag = "some-branch"
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://bb.example.com/scm/~some-user/some-test-repo.git"

        self.assertEqual('<a href="https://bb.example.com/users/some-user/repos/some-test-repo/browse/some-folder/some-file.ext?at=some-branch#5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_gitea_or_codeberg_project_with_no_details_and_line(self):
        # checks that for gitea and codeberg in custom field
        # dojo makes correct url

        # create scm-type custom field with value "gitea"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="gitea")
        product_metadata.save()

        # create finding with scm uri line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://bb.example.com/some-test-user/some-test-repo.git"
        self.assertEqual('<a href="https://bb.example.com/some-test-user/some-test-repo/src/master/some-folder/some-file.ext#L5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri_gitea_or_codeberg_project_with_commithash_and_line(self):
        # checks that for gitea and codeberg in custom field  and existing commit hash in finding
        # dojo makes correct url

        # create scm-type custom field with value "gitea"
        product_type = self.create_product_type("test_product_type")
        product = self.create_product(name="test_product", prod_type=product_type)
        product_metadata = DojoMeta(product=product, name="scm-type", value="gitea")
        product_metadata.save()

        # create finding with scm uri and commit hash, branch and line
        test = Test()
        engagement = Engagement()
        engagement.product = product
        test.engagement = engagement
        engagement.commit_hash = "some-commit-hash"
        finding = Finding()
        finding.test = test
        finding.file_path = "some-folder/some-file.ext"
        finding.line = 5432

        engagement.source_code_management_uri = "https://bb.example.com/some-test-user/some-test-repo.git"
        self.assertEqual('<a href="https://bb.example.com/some-test-user/some-test-repo/src/some-commit-hash/some-folder/some-file.ext#L5432" target="_blank" title="some-folder/some-file.ext">some-folder/some-file.ext</a>', finding.get_file_path_with_link())

    def test_get_file_path_with_xss_attack(self):
        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.file_path = "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>"
        engagement.source_code_management_uri = "<IMG SRC=javascript:alert('XSS')>"
        self.assertEqual('<a href="&lt;IMG SRC=javascript:alert(\'XSS\')>/&lt;SCRIPT SRC=http://xss.rocks/xss.js>&lt;/SCRIPT>" target="_blank" title="&lt;SCRIPT SRC=http://xss.rocks/xss.js>&lt;/SCRIPT>">&lt;SCRIPT SRC=http://xss.rocks/xss.js&gt;&lt;/SCRIPT&gt;</a>', finding.get_file_path_with_link())

    def test_get_references_with_links_no_references(self):
        finding = Finding()
        self.assertEqual(None, finding.get_references_with_links())

    def test_get_references_with_links_no_links(self):
        finding = Finding()
        finding.references = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr"
        self.assertEqual("Lorem ipsum dolor sit amet, consetetur sadipscing elitr", finding.get_references_with_links())

    def test_get_references_with_links_simple_url(self):
        finding = Finding()
        finding.references = "URL: https://www.example.com"
        self.assertEqual('URL: <a href="https://www.example.com" target="_blank" title="https://www.example.com">https://www.example.com</a>', finding.get_references_with_links())

    def test_get_references_with_links_url_with_port(self):
        finding = Finding()
        finding.references = "http://www.example.com:8080"
        self.assertEqual('<a href="http://www.example.com:8080" target="_blank" title="http://www.example.com:8080">http://www.example.com:8080</a>', finding.get_references_with_links())

    def test_get_references_with_links_url_with_path(self):
        finding = Finding()
        finding.references = "URL https://www.example.com/path/part2 behind URL"
        self.assertEqual('URL <a href="https://www.example.com/path/part2" target="_blank" title="https://www.example.com/path/part2">https://www.example.com/path/part2</a> behind URL', finding.get_references_with_links())

    def test_get_references_with_links_complicated_url_with_parameter(self):
        finding = Finding()
        finding.references = "URL:https://www.example.com/path?param1=abc&_param2=xyz"
        self.assertEqual('URL:<a href="https://www.example.com/path?param1=abc&amp;_param2=xyz" target="_blank" title="https://www.example.com/path?param1=abc&amp;_param2=xyz">https://www.example.com/path?param1=abc&amp;_param2=xyz</a>', finding.get_references_with_links())

    def test_get_references_with_links_two_urls(self):
        finding = Finding()
        finding.references = "URL1: https://www.example.com URL2: https://info.example.com"
        self.assertEqual('URL1: <a href="https://www.example.com" target="_blank" title="https://www.example.com">https://www.example.com</a> URL2: <a href="https://info.example.com" target="_blank" title="https://info.example.com">https://info.example.com</a>', finding.get_references_with_links())

    def test_get_references_with_links_linebreak(self):
        finding = Finding()
        finding.references = "https://www.example.com\nhttps://info.example.com"
        self.assertEqual('<a href="https://www.example.com" target="_blank" title="https://www.example.com">https://www.example.com</a>\n<a href="https://info.example.com" target="_blank" title="https://info.example.com">https://info.example.com</a>', finding.get_references_with_links())

    def test_get_references_with_links_markdown(self):
        finding = Finding()
        finding.references = "URL: [https://www.example.com](https://www.example.com)"
        self.assertEqual("URL: [https://www.example.com](https://www.example.com)", finding.get_references_with_links())


class TestFindingSLAExpiration(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def run(self, result=None):
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.save()

        # unit tests are running without any user, which will result in actions like dedupe happening in the celery process
        # this doesn't work in unittests as unittests are using an in memory sqlite database and celery can't see the data
        # so we're running the test under the admin user context and set block_execution to True
        with impersonate(testuser):
            super().run(result)

    def test_sla_expiration_date(self):
        """
        Tests if the SLA expiration date and SLA days remaining are calculated correctly
        after a finding's severity is updated
        """
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("test_product_type")
        sla_config = self.create_sla_configuration(name="test_sla_config")
        product = self.create_product(name="test_product", prod_type=product_type)
        product.sla_configuration = sla_config
        product.save()
        engagement = self.create_engagement("test_eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan", title="test_test")
        finding = Finding.objects.create(
            test=test,
            reporter=user,
            title="test_finding",
            severity="Critical",
            date=datetime.now().date())
        finding.set_sla_expiration_date()

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

    def test_sla_expiration_date_after_finding_severity_updated(self):
        """
        Tests if the SLA expiration date and SLA days remaining are calculated correctly
        after a finding's severity is updated
        """
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("test_product_type")
        sla_config = self.create_sla_configuration(name="test_sla_config")
        product = self.create_product(name="test_product", prod_type=product_type)
        product.sla_configuration = sla_config
        product.save()
        engagement = self.create_engagement("test_eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan", title="test_test")
        finding = Finding.objects.create(
            test=test,
            reporter=user,
            title="test_finding",
            severity="Critical",
            date=datetime.now().date())
        finding.set_sla_expiration_date()

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

        finding.severity = "Medium"
        finding.set_sla_expiration_date()

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

    def test_sla_expiration_date_after_product_updated(self):
        """
        Tests if the SLA expiration date and SLA days remaining are calculated correctly
        after a product changed from one SLA configuration to another
        """
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("test_product_type")
        sla_config_1 = self.create_sla_configuration(name="test_sla_config_1")
        sla_config_2 = self.create_sla_configuration(
            name="test_sla_config_2",
            critical=1,
            high=2,
            medium=3,
            low=4)
        product = self.create_product(name="test_product", prod_type=product_type)
        product.sla_configuration = sla_config_1
        product.save()
        engagement = self.create_engagement("test_eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan", title="test_test")
        finding = Finding.objects.create(
            test=test,
            reporter=user,
            title="test_finding",
            severity="Critical",
            date=datetime.now().date())

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

        product.sla_configuration = sla_config_2
        product.save()

        finding.set_sla_expiration_date()

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

    def test_sla_expiration_date_after_sla_configuration_updated(self):
        """
        Tests if the SLA expiration date and SLA days remaining are calculated correctly
        after the SLA configuration on a product was updated to a different number of SLA days
        """
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("test_product_type")
        sla_config = self.create_sla_configuration(name="test_sla_config")
        product = self.create_product(name="test_product", prod_type=product_type)
        product.sla_configuration = sla_config
        product.save()
        engagement = self.create_engagement("test_eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan", title="test_test")
        finding = Finding.objects.create(
            test=test,
            reporter=user,
            title="test_finding",
            severity="Critical",
            date=datetime.now().date())

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

        sla_config.critical = 10
        sla_config.save()

        finding.set_sla_expiration_date()

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

    def test_sla_expiration_date_after_sla_not_enforced(self):
        """
        Tests if the SLA expiration date is none after the after the SLA configuration on a
        product was updated to not enforce all SLA remediation days
        """
        user, _ = User.objects.get_or_create(username="admin")
        product_type = self.create_product_type("test_product_type")
        sla_config = self.create_sla_configuration(name="test_sla_config")
        product = self.create_product(name="test_product", prod_type=product_type)
        product.sla_configuration = sla_config
        product.save()
        engagement = self.create_engagement("test_eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan", title="test_test")
        finding = Finding.objects.create(
            test=test,
            reporter=user,
            title="test_finding",
            severity="Critical",
            date=datetime.now().date())

        expected_sla_days = getattr(product.sla_configuration, finding.severity.lower(), None)
        self.assertEqual(finding.sla_expiration_date, datetime.now().date() + timedelta(days=expected_sla_days))
        self.assertEqual(finding.sla_days_remaining(), expected_sla_days)

        sla_config.enforce_critical = False
        sla_config.save()

        finding.set_sla_expiration_date()

        self.assertEqual(finding.sla_expiration_date, None)
        self.assertEqual(finding.sla_days_remaining(), None)
        self.assertEqual(finding.sla_deadline(), None)
