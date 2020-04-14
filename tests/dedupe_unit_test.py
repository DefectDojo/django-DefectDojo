from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import unittest
import re
import sys
import os
from base_test_class import BaseTestCase, on_exception_html_source_logger
from Product_unit_test import ProductTest
import time

dir_path = os.path.dirname(os.path.realpath(__file__))


class DedupeTest(BaseTestCase):
    # --------------------------------------------------------------------------------------------------------
    # Initialization
    # --------------------------------------------------------------------------------------------------------
    def setUp(self):
        super().setUp()
        self.relative_path = dir_path = os.path.dirname(os.path.realpath(__file__))

    def check_nb_duplicates(self, expected_number_of_duplicates):
        print("checking duplicates...")
        retries = 0
        for i in range(0, 18):
            time.sleep(5)  # wait bit for celery dedupe task which can be slow on travis
            driver = self.login_page()
            driver.get(self.base_url + "finding")
            dupe_count = 0
            # iterate over the rows of the findings table and concatenates all columns into td.text
            trs = driver.find_elements_by_xpath('//*[@id="open_findings"]/tbody/tr')
            for row in trs:
                concatRow = ' '.join([td.text for td in row.find_elements_by_xpath(".//td")])
                # print(concatRow)
                if '(DUPE)' and 'Duplicate' in concatRow:
                    dupe_count += 1

            if (dupe_count != expected_number_of_duplicates):
                print("duplicate count mismatch, let's wait a bit for the celery dedupe task to finish and try again (5s)")
            else:
                break

        if (dupe_count != expected_number_of_duplicates):
            findings_table = driver.find_element_by_id('open_findings')
            print(findings_table.get_attribute('innerHTML'))

        self.assertEqual(dupe_count, expected_number_of_duplicates)

    @on_exception_html_source_logger
    def test_enable_deduplication(self):
        print("enabling deduplication...")
        driver = self.login_page()
        driver.get(self.base_url + 'system_settings')
        if not driver.find_element_by_id('id_enable_deduplication').is_selected():
            driver.find_element_by_xpath('//*[@id="id_enable_deduplication"]').click()
            # save settings
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Temporary fix for the caching issue, see https://github.com/DefectDojo/django-DefectDojo/issues/2164
            time.sleep(30)
            # check if it's enabled after reload
            driver.get(self.base_url + 'system_settings')
            self.assertTrue(driver.find_element_by_id('id_enable_deduplication').is_selected())

    # def test_enable_block_execution(self):
    #     # we set the admin user (ourselves) to have block_execution checked
    #     # this will force dedupe to happen synchronously as the celeryworker is not reliable in travis
    #     print("setting admin user to have block_execution checked....")
    #     driver = self.login_page()
    #     driver.get(self.base_url + 'profile')
    #     if not driver.find_element_by_id('id_block_execution').is_selected():
    #         driver.find_element_by_xpath('//*[@id="id_block_execution"]').click()
    #         # save settings
    #         driver.find_element_by_css_selector("input.btn.btn-primary").click()
    #         # check if it's enabled after reload
    #         self.assertTrue(driver.find_element_by_id('id_block_execution').is_selected())

    @on_exception_html_source_logger
    def test_delete_findings(self):
        print("removing previous findings...")
        driver = self.login_page()
        driver.get(self.base_url + "finding")
        text = driver.find_element_by_tag_name("BODY").text
        if 'No findings found.' in text:
            return
        else:
            driver.find_element_by_id("select_all").click()
            driver.find_element_by_css_selector("i.fa.fa-trash").click()
            try:
                WebDriverWait(driver, 1).until(EC.alert_is_present(),
                                            'Timed out waiting for PA creation ' +
                                            'confirmation popup to appear.')
                driver.switch_to.alert.accept()
            except TimeoutException:
                self.fail('Confirmation dialogue not shown, cannot delete previous findings')

        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'No findings found.', text))

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on engagement
#   Test deduplication for Bandit SAST scanner
# --------------------------------------------------------------------------------------------------------
    @on_exception_html_source_logger
    def test_add_path_test_suite(self):
        print("Same scanner deduplication - Deduplication on engagement - static. Creating tests...")
        # Create engagement
        driver = self.login_page()
        self.goto_product_overview(driver)
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Dedupe Path Test")
        driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', text))
        # Add the tests
        # Test 1
        driver.find_element_by_id("id_title").send_keys("Path Test 1")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Bandit Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_name("_Add Another Test").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))
        # Test 2
        driver.find_element_by_id("id_title").send_keys("Path Test 2")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Bandit Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))

    @on_exception_html_source_logger
    def test_import_path_tests(self):
        print("importing reports...")
        # First test
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Path Test").click()
        driver.find_element_by_partial_link_text("Path Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        # active and verified:
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_path_1.json")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

        # Second test
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Path Test").click()
        driver.find_element_by_partial_link_text("Path Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_path_2.json")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

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
        print("Same scanner deduplication - Deduplication on engagement - dynamic. Creating tests...")
        # Create engagement
        driver = self.login_page()
        self.goto_product_overview(driver)
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Dedupe Endpoint Test")
        driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', text))
        # Add the tests
        # Test 1
        driver.find_element_by_id("id_title").send_keys("Endpoint Test 1")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_name("_Add Another Test").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))
        # Test 2
        driver.find_element_by_id("id_title").send_keys("Endpoint Test 2")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))

    @on_exception_html_source_logger
    def test_import_endpoint_tests(self):
        print("Importing reports...")
        # First test : Immuniweb Scan (dynamic)
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Endpoint Test").click()
        driver.find_element_by_partial_link_text("Endpoint Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        # active and verified
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

        # Second test : Immuniweb Scan (dynamic)
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Endpoint Test").click()
        driver.find_element_by_partial_link_text("Endpoint Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        # active and verified
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_2.xml")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

    @on_exception_html_source_logger
    def test_check_endpoint_status(self):
        # comparing dedupe_endpoint_1.xml and dedupe_endpoint_2.xml
        # Counts the findings that have on the same line "(DUPE)" (in the title) and "Duplicate" (marked as duplicate by DD)
        # We have imported 3 findings twice, but one only is a duplicate because for the 2 others, we have changed either (the URL) or (the name and cwe)
        self.check_nb_duplicates(1)

    @on_exception_html_source_logger
    def test_add_same_eng_test_suite(self):
        print("Test different scanners - same engagement - dynamic; Adding tests on the same engagement...")
        # Create engagement
        driver = self.login_page()
        self.goto_product_overview(driver)
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Dedupe Same Eng Test")
        driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', text))
        # Add the tests
        # Test 1
        driver.find_element_by_id("id_title").send_keys("Same Eng Test 1")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_name("_Add Another Test").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))
        # Test 2
        driver.find_element_by_id("id_title").send_keys("Same Eng Test 2")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Generic Findings Import")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))

    @on_exception_html_source_logger
    def test_import_same_eng_tests(self):
        print("Importing reports")
        # First test : Immuniweb Scan (dynamic)
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Same Eng Test").click()
        driver.find_element_by_partial_link_text("Same Eng Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

        # Second test : Generic Findings Import with Url (dynamic)
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Same Eng Test").click()
        driver.find_element_by_partial_link_text("Same Eng Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_cross_1.csv")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

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
        print("Same scanner deduplication - Deduplication on engagement. Test dedupe on checkmarx aggregated with custom hash_code computation")
        # Create engagement
        driver = self.login_page()
        self.goto_product_overview(driver)
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Dedupe on hash_code only")
        driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', text))
        # Add the tests
        # Test 1
        driver.find_element_by_id("id_title").send_keys("Path Test 1")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Checkmarx Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_name("_Add Another Test").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))
        # Test 2
        driver.find_element_by_id("id_title").send_keys("Path Test 2")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Checkmarx Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))

    def test_import_path_tests_checkmarx_scan(self):
        # First test
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe on hash_code only").click()
        driver.find_element_by_partial_link_text("Path Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        # os.path.realpath makes the path canonical
        driver.find_element_by_id('id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings.xml"))
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 2 findings were processed', text))

        # Second test
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe on hash_code only").click()
        driver.find_element_by_partial_link_text("Path Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(os.path.realpath(self.relative_path + "/dedupe_scans/multiple_findings_line_changed.xml"))
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 2 findings were processed', text))

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
        print("Cross scanners deduplication dynamic; generic finding vs immuniweb. Creating tests...")
        # Create generic engagement
        driver = self.login_page()
        self.goto_product_overview(driver)
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Dedupe Generic Test")
        # driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', text))
        # Test
        driver.find_element_by_id("id_title").send_keys("Generic Test")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Generic Findings Import")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))

        # Create immuniweb engagement
        self.goto_product_overview(driver)
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Dedupe Immuniweb Test")
        # driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', text))
        # Test
        driver.find_element_by_id("id_title").send_keys("Immuniweb Test")
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Immuniweb Scan")
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Test added successfully', text))

    def test_import_cross_test(self):
        print("Importing findings...")
        # First test : Immuniweb Scan (dynamic)
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Immuniweb Test").click()
        driver.find_element_by_partial_link_text("Immuniweb Test").click()
        driver.find_element_by_css_selector("b.fa.fa-ellipsis-v").click()
        driver.find_element_by_link_text("Re-Upload Scan Results").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

        # Second test : generic scan with url (dynamic)
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Generic Test").click()
        driver.find_element_by_partial_link_text("Generic Test").click()
        driver.find_element_by_css_selector("b.fa.fa-ellipsis-v").click()
        driver.find_element_by_link_text("Re-Upload Scan Results").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_cross_1.csv")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'a total of 3 findings were processed', text))

    def test_check_cross_status(self):
        self.check_nb_duplicates(1)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(DedupeTest('test_enable_deduplication'))
    # suite.addTest(DedupeTest('test_enable_block_execution'))
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
    # Clean up
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
