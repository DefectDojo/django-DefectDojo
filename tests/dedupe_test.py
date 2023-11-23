import logging
import os
import sys
import time
import unittest

from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

from base_test_class import (BaseTestCase, on_exception_html_source_logger,
                             set_suite_settings)
from product_test import ProductTest

logger = logging.getLogger(__name__)

dir_path = os.path.dirname(os.path.realpath(__file__))


class DedupeTest(BaseTestCase):
    # --------------------------------------------------------------------------------------------------------
    # Initialization
    # --------------------------------------------------------------------------------------------------------
    def setUp(self):
        super().setUp()
        self.relative_path = dir_path = os.path.dirname(os.path.realpath(__file__))

    def check_nb_duplicates(self, expected_number_of_duplicates):
        logger.debug("checking duplicates...")
        driver = self.driver
        retries = 0
        for i in range(0, 18):
            time.sleep(5)  # wait bit for celery dedupe task which can be slow on travis
            self.goto_all_findings_list(driver)
            dupe_count = 0
            # iterate over the rows of the findings table and concatenates all columns into td.text
            trs = driver.find_elements(By.XPATH, '//*[@id="open_findings"]/tbody/tr')
            for row in trs:
                concatRow = ' '.join([td.text for td in row.find_elements(By.XPATH, ".//td")])
                # print(concatRow)
                if '(DUPE)' and 'Duplicate' in concatRow:
                    dupe_count += 1

            if (dupe_count != expected_number_of_duplicates):
                logger.debug("duplicate count mismatch, let's wait a bit for the celery dedupe task to finish and try again (5s)")
            else:
                break

        if (dupe_count != expected_number_of_duplicates):
            findings_table = driver.find_element(By.ID, 'open_findings')
            print(findings_table.get_attribute('innerHTML'))

        self.assertEqual(dupe_count, expected_number_of_duplicates)

    @on_exception_html_source_logger
    def test_enable_deduplication(self):
        logger.debug("enabling deduplication...")
        driver = self.driver
        driver.get(self.base_url + 'system_settings')
        if not driver.find_element(By.ID, 'id_enable_deduplication').is_selected():
            driver.find_element(By.XPATH, '//*[@id="id_enable_deduplication"]').click()
            # save settings
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            # check if it's enabled after reload
            driver.get(self.base_url + 'system_settings')
            self.assertTrue(driver.find_element(By.ID, 'id_enable_deduplication').is_selected())

    @on_exception_html_source_logger
    def test_delete_findings(self):
        logger.debug("removing previous findings...")
        driver = self.driver
        driver.get(self.base_url + "finding?page=1")

        if self.element_exists_by_id("no_findings"):
            text = driver.find_element(By.ID, "no_findings").text
            if 'No findings found.' in text:
                return

        driver.find_element(By.ID, "select_all").click()
        driver.find_element(By.CSS_SELECTOR, "i.fa-solid.fa-trash").click()
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present(),
                                        'Timed out waiting for finding delete ' +
                                        'confirmation popup to appear.')
            driver.switch_to.alert.accept()
        except TimeoutException:
            self.fail('Confirmation dialogue not shown, cannot delete previous findings')

        logger.debug("page source when checking for no_findings element")
        logger.debug(self.driver.page_source)
        text = driver.find_element(By.ID, "no_findings").text

        self.assertIsNotNone(text)
        self.assertTrue('No findings found.' in text)
        # check that user was redirect back to url where it came from based on return_url
        self.assertTrue(driver.current_url.endswith('page=1'))


# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on engagement
#   Test deduplication for Bandit SAST scanner
# --------------------------------------------------------------------------------------------------------
    @on_exception_html_source_logger  # noqa: E301
    def test_add_path_test_suite(self):
        logger.debug("Same scanner deduplication - Deduplication on engagement - static. Creating tests...")
        # Create engagement
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Dedupe Path Test")
        driver.find_element(By.XPATH, '//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element(By.NAME, "_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))
        # Add the tests
        # Test 1
        driver.find_element(By.ID, "id_title").send_keys("Path Test 1")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Bandit Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.NAME, "_Add Another Test").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))
        # Test 2
        driver.find_element(By.ID, "id_title").send_keys("Path Test 2")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Bandit Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))

    @on_exception_html_source_logger
    def test_import_path_tests(self):
        """
        Re-upload dedupe_path_1.json bandit report into "Path Test 1" empty test (nothing uploaded before)
        Then do the same with dedupe_path_2.json / "Path Test 2"
        """
        logger.debug("importing reports...")
        # First test
        # the first report have 3 duplicates of the same finding
        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Path Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 1").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_path_1.json")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        # 'Bandit Scan processed a total of 1 findings created 1 findings did not touch 1 findings.'
        self.assertTrue(self.is_success_message_present(text='a total of 1 findings'))

        # Second test
        # the second report have 2 findings (same vuln_id same file but different line number)
        # one the findings is the same in the first and the second report
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Path Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 2").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_path_2.json")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        # 'Bandit Scan processed a total of 2 findings created 2 findings did not touch 1 findings.'
        self.assertTrue(self.is_success_message_present(text='a total of 2 findings'))

    @on_exception_html_source_logger
    def test_check_path_status(self):
        # comparing tests/dedupe_scans/dedupe_path_1.json and tests/dedupe_scans/dedupe_path_2.json
        # Counts the findings that have on the same line "(DUPE)" (in the title) and "Duplicate" (marked as duplicate by DD)
        # We have imported 3 findings twice, but one only is a duplicate because for the 2 others, we have changed either the line number or the file_path
        self.check_nb_duplicates(1)

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on engagement
#   Test deduplication for Immuniweb dynamic scanner
# --------------------------------------------------------------------------------------------------------
    @on_exception_html_source_logger
    def test_add_endpoint_test_suite(self):
        logger.debug("Same scanner deduplication - Deduplication on engagement - dynamic. Creating tests...")
        # Create engagement

        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Dedupe Endpoint Test")
        driver.find_element(By.XPATH, '//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element(By.NAME, "_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))
        # Add the tests
        # Test 1
        driver.find_element(By.ID, "id_title").send_keys("Endpoint Test 1")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.NAME, "_Add Another Test").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))
        # Test 2
        driver.find_element(By.ID, "id_title").send_keys("Endpoint Test 2")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))

    @on_exception_html_source_logger
    def test_import_endpoint_tests(self):
        logger.debug("Importing reports...")
        # First test : Immuniweb Scan (dynamic)

        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Endpoint Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Endpoint Test 1").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 3 findings'))

        # Second test : Immuniweb Scan (dynamic)
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Endpoint Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Endpoint Test 2").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_2.xml")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 3 findings'))

    @on_exception_html_source_logger
    def test_check_endpoint_status(self):
        # comparing dedupe_endpoint_1.xml and dedupe_endpoint_2.xml
        # Counts the findings that have on the same line "(DUPE)" (in the title) and "Duplicate" (marked as duplicate by DD)
        # We have imported 3 findings twice, but one only is a duplicate because for the 2 others, we have changed either (the URL) or (the name and cwe)
        self.check_nb_duplicates(1)

    @on_exception_html_source_logger
    def test_add_same_eng_test_suite(self):
        logger.debug("Test different scanners - same engagement - dynamic; Adding tests on the same engagement...")
        # Create engagement

        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Dedupe Same Eng Test")
        driver.find_element(By.XPATH, '//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element(By.NAME, "_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))
        # Add the tests
        # Test 1
        driver.find_element(By.ID, "id_title").send_keys("Same Eng Test 1")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.NAME, "_Add Another Test").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))
        # Test 2
        driver.find_element(By.ID, "id_title").send_keys("Same Eng Test 2")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Generic Findings Import")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))

    @on_exception_html_source_logger
    def test_import_same_eng_tests(self):
        """Test different scanners - different engagement - dynamic"""
        driver = self.driver
        self.goto_active_engagements_overview(driver)

        # First test : Immuniweb Scan (dynamic)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Same Eng Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Same Eng Test 1").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 3 findings'))

        # Second test : Generic Findings Import with Url (dynamic)
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Same Eng Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Same Eng Test 2").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_cross_1.csv")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 3 findings'))

    @on_exception_html_source_logger
    def test_check_same_eng_status(self):
        # comparing dedupe_endpoint_1.xml and dedupe_endpoint_2.xml
        # Counts the findings that have on the same line "(DUPE)" (in the title) and "Duplicate" (marked as duplicate by DD)
        # We have imported 3 findings twice, but one only is a duplicate because for the 2 others, we have changed either (the URL) or (the name and cwe)
        self.check_nb_duplicates(1)

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on engagement
#   Test deduplication for Checkmarx SAST Scan with custom hash_code computation
#   Upon import, Checkmarx Scan aggregates on : categories, cwe, name, sinkFilename
#   That test shows that the custom hash_code (excluding line number, see settings.py)
#     makes it possible to detect the duplicate even if the line number has changed (which will occur in a normal software lifecycle)
# --------------------------------------------------------------------------------------------------------
    def test_add_path_test_suite_checkmarx_scan(self):
        logger.debug("Same scanner deduplication - Deduplication on engagement. Test dedupe on checkmarx aggregated with custom hash_code computation")
        # Create engagement

        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Dedupe on hash_code only")
        driver.find_element(By.XPATH, '//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element(By.NAME, "_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))
        # Add the tests
        # Test 1
        driver.find_element(By.ID, "id_title").send_keys("Path Test 1")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Checkmarx Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.NAME, "_Add Another Test").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))
        # Test 2
        driver.find_element(By.ID, "id_title").send_keys("Path Test 2")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Checkmarx Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))

    def test_import_path_tests_checkmarx_scan(self):
        # First test

        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe on hash_code only").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 1").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        # os.path.realpath makes the path canonical
        driver.find_element(By.ID, 'id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings.xml"))
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 2 findings'))

        # Second test
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe on hash_code only").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 2").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings_line_changed.xml"))
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 2 findings'))

    def test_check_path_status_checkmarx_scan(self):
        # After aggregation, it's only two findings. Both are duplicates even though the line number has changed
        # because we ignore the line number when computing the hash_code for this scanner
        # (so that findings keep being found as duplicate even if the code changes slightly)
        self.check_nb_duplicates(2)

# --------------------------------------------------------------------------------------------------------
# Cross scanners deduplication - product-wide deduplication
#   Test deduplication for Generic Findings Import with URL (dynamic) vs Immuniweb dynamic scanner
# --------------------------------------------------------------------------------------------------------
    def test_add_cross_test_suite(self):
        logger.debug("Cross scanners deduplication dynamic; generic finding vs immuniweb. Creating tests...")
        # Create generic engagement

        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Dedupe Generic Test")
        # driver.find_element(By.XPATH, '//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element(By.NAME, "_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))
        # Test
        driver.find_element(By.ID, "id_title").send_keys("Generic Test")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Generic Findings Import")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))

        # Create immuniweb engagement
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Dedupe Immuniweb Test")
        # driver.find_element(By.XPATH, '//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element(By.NAME, "_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))
        # Test
        driver.find_element(By.ID, "id_title").send_keys("Immuniweb Test")
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Test added successfully'))

    def test_import_cross_test(self):
        logger.debug("Importing findings...")
        # First test : Immuniweb Scan (dynamic)

        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Immuniweb Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Immuniweb Test").click()
        driver.find_element(By.CSS_SELECTOR, "i.fa-solid.fa-ellipsis-vertical").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan Results").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 3 findings'))

        # Second test : generic scan with url (dynamic)
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe Generic Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Generic Test").click()
        driver.find_element(By.CSS_SELECTOR, "i.fa-solid.fa-ellipsis-vertical").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan Results").click()
        driver.find_element(By.ID, 'id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_cross_1.csv")
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='a total of 3 findings'))

    def test_check_cross_status(self):
        self.check_nb_duplicates(1)

# --------------------------------------------------------------------------------------------------------
# Deduplication with and without service attribute in finding
# --------------------------------------------------------------------------------------------------------
    def test_import_no_service(self):
        logger.debug("Importing findings...")

        driver = self.driver

        # We reuse the engagement and test for Checkmarx, because we need a parser with hash_code deduplication
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe on hash_code only").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 1").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings.xml"))
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='Checkmarx Scan processed a total of 2 findings created 2 findings.'))

        # Import the same findings a second time - they should all be duplicates
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe on hash_code only").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 2").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings.xml"))
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='Checkmarx Scan processed a total of 2 findings created 2 findings.'))

    def test_check_no_service(self):
        # Since we imported the same report twice, we should have 2 duplicates
        self.check_nb_duplicates(2)

    def test_import_service(self):
        logger.debug("Importing findings...")

        driver = self.driver

        # We reuse the engagement and test for Checkmarx, because we need a parser with hash_code deduplication
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe on hash_code only").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 1").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_service').send_keys("service_1")
        driver.find_element(By.ID, 'id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings.xml"))
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='Checkmarx Scan processed a total of 2 findings created 2 findings.'))

        # Import the same findings a second time with a different service - they should all be new findings
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Dedupe on hash_code only").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Path Test 2").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Re-Upload Scan").click()
        driver.find_element(By.ID, 'id_service').send_keys("service_2")
        driver.find_element(By.ID, 'id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings.xml"))
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text='Checkmarx Scan processed a total of 2 findings created 2 findings.'))

    def test_check_service(self):
        # Since we imported the same report twice but with different service names, we should have no duplicates
        self.check_nb_duplicates(0)


def add_dedupe_tests_to_suite(suite, jira=False, github=False, block_execution=False):
    suite.addTest(BaseTestCase('test_login'))
    set_suite_settings(suite, jira=jira, github=github, block_execution=block_execution)

    if jira:
        suite.addTest(BaseTestCase('enable_jira'))
    else:
        suite.addTest(BaseTestCase('disable_jira'))
    if github:
        suite.addTest(BaseTestCase('enable_github'))
    else:
        suite.addTest(BaseTestCase('disable_github'))
    if block_execution:
        suite.addTest(BaseTestCase('enable_block_execution'))
    else:
        suite.addTest(BaseTestCase('disable_block_execution'))

    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(DedupeTest('test_enable_deduplication'))
    # Test same scanners - same engagement - static - dedupe
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_add_path_test_suite'))
    suite.addTest(DedupeTest('test_import_path_tests'))
    suite.addTest(DedupeTest('test_check_path_status'))
    # Test same scanners - same engagement - dynamic - dedupe
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_add_endpoint_test_suite'))
    suite.addTest(DedupeTest('test_import_endpoint_tests'))
    suite.addTest(DedupeTest('test_check_endpoint_status'))
    # Test different scanners - same engagement - dynamic - dedupe
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_add_same_eng_test_suite'))
    suite.addTest(DedupeTest('test_import_same_eng_tests'))
    suite.addTest(DedupeTest('test_check_same_eng_status'))
    # Test same scanners - same engagement - static - dedupe with custom hash_code
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_add_path_test_suite_checkmarx_scan'))
    suite.addTest(DedupeTest('test_import_path_tests_checkmarx_scan'))
    suite.addTest(DedupeTest('test_check_path_status_checkmarx_scan'))
    # Test different scanners - different engagement - dynamic - dedupe
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_add_cross_test_suite'))
    suite.addTest(DedupeTest('test_import_cross_test'))
    suite.addTest(DedupeTest('test_check_cross_status'))
    # Test deduplication with and without service in findings
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_import_no_service'))
    suite.addTest(DedupeTest('test_check_no_service'))
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_import_service'))
    suite.addTest(DedupeTest('test_check_service'))
    # Clean up
    suite.addTest(ProductTest('test_delete_product'))
    return suite


def suite():
    suite = unittest.TestSuite()
    add_dedupe_tests_to_suite(suite, jira=False, github=False, block_execution=False)
    add_dedupe_tests_to_suite(suite, jira=True, github=True, block_execution=True)
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
