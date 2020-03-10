from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import unittest
import re
import sys
import os

dir_path = os.path.dirname(os.path.realpath(__file__))
try:  # First Try for python 3
    import importlib.util
    product_unit_test_module = importlib.util.spec_from_file_location("Product_unit_test",
        os.path.join(dir_path, 'Product_unit_test.py'))  # using ',' allows python to determine the type of separator to use.
    product_unit_test = importlib.util.module_from_spec(product_unit_test_module)
    product_unit_test_module.loader.exec_module(product_unit_test)
except:  # This will work for python2 if above fails
    import imp
    product_unit_test = imp.load_source('Product_unit_test',
        os.path.join(dir_path, 'Product_unit_test.py'))


class DedupeTest(unittest.TestCase):
    # --------------------------------------------------------------------------------------------------------
    # Initialization
    # --------------------------------------------------------------------------------------------------------
    def setUp(self):
        self.options = Options()
        self.options.add_argument("--headless")
        # self.options.add_experimental_option("detach", True)
        self.options.add_argument("--window-size=1280,768")
        # self.options.add_argument("--no-sandbox")

        desired = webdriver.DesiredCapabilities.CHROME
        desired['loggingPrefs'] = {'browser': 'ALL'}

        self.driver = webdriver.Chrome('chromedriver', chrome_options=self.options, desired_capabilities=desired)
        self.driver.implicitly_wait(30)
        self.base_url = os.environ['DD_BASE_URL']
        self.verificationErrors = []
        self.accept_next_alert = True
        self.relative_path = dir_path = os.path.dirname(os.path.realpath(__file__))

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        # os.environ['DD_ADMIN_USER']
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def check_nb_duplicates(self, expected_number_of_duplicates):
        print("checking duplicates...")
        driver = self.login_page()
        driver.get(self.base_url + "finding")
        dupe_count = 0
        # iterate over the rows of the findings table and concatenates all columns into td.text
        trs = driver.find_elements_by_xpath('//*[@id="open_findings"]/tbody/tr')
        for row in trs:
            concatRow = ' '.join([td.text for td in row.find_elements_by_xpath(".//td")])
            if '(DUPE)' and 'Duplicate' in concatRow:
                dupe_count += 1
        self.assertEqual(dupe_count, expected_number_of_duplicates)

    def test_enable_deduplication(self):
        print("enabling deduplication...")
        driver = self.login_page()
        driver.get(self.base_url + 'system_settings')
        if not driver.find_element_by_id('id_enable_deduplication').is_selected():
            driver.find_element_by_xpath('//*[@id="id_enable_deduplication"]').click()
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            self.assertTrue(driver.find_element_by_id('id_enable_deduplication').is_selected())

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
                print("Alert did not show.")
        text = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'No findings found.', text))

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on engagement
#   Test deduplication for Bandit SAST scanner
# --------------------------------------------------------------------------------------------------------
    def test_add_path_test_suite(self):
        print("Same scanner deduplication - Deduplication on engagement - static. Creating tests...")
        # Create engagement
        driver = self.login_page()
        driver.get(self.base_url + "product")
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

    def test_import_path_tests(self):
        print("importing reports...")
        # First test
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Path Test").click()
        driver.find_element_by_partial_link_text("Path Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_path_1.json")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
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

    def test_check_path_status(self):
        # comparing tests/dedupe_scans/dedupe_path_1.json and tests/dedupe_scans/dedupe_path_2.json
        # Counts the findings that have on the same line "(DUPE)" (in the title) and "Duplicate" (marked as duplicate by DD)
        # We have imported 3 findings twice, but one only is a duplicate because for the 2 others, we have changed either the line number or the file_path
        self.check_nb_duplicates(1)

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on engagement
#   Test deduplication for Immuniweb dynamic scanner
# --------------------------------------------------------------------------------------------------------
    def test_add_endpoint_test_suite(self):
        print("Same scanner deduplication - Deduplication on engagement - dynamic. Creating tests...")
        # Create engagement
        driver = self.login_page()
        driver.get(self.base_url + "product")
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

    def test_import_endpoint_tests(self):
        print("Importing reports...")
        # First test : Immuniweb Scan (dynamic)
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Endpoint Test").click()
        driver.find_element_by_partial_link_text("Endpoint Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        # Second test : Immuniweb Scan (dynamic)
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Endpoint Test").click()
        driver.find_element_by_partial_link_text("Endpoint Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(self.relative_path + "/dedupe_scans/dedupe_endpoint_2.xml")
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()

    def test_check_endpoint_status(self):
        # comparing dedupe_endpoint_1.xml and dedupe_endpoint_2.xml
        # Counts the findings that have on the same line "(DUPE)" (in the title) and "Duplicate" (marked as duplicate by DD)
        # We have imported 3 findings twice, but one only is a duplicate because for the 2 others, we have changed either (the URL) or (the name and cwe)
        self.check_nb_duplicates(1)

    def test_add_same_eng_test_suite(self):
        print("Test different scanners - same engagement - dynamic; Adding tests on the same engagement...")
        # Create engagement
        driver = self.login_page()
        driver.get(self.base_url + "product")
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
        driver.get(self.base_url + "product")
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
        driver.find_element_by_id('id_file').send_keys(os.path.realpath(self.relative_path + "/../dojo/unittests/scans/checkmarx/multiple_findings.xml"))
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        # Second test
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe on hash_code only").click()
        driver.find_element_by_partial_link_text("Path Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys(os.path.realpath(self.relative_path + "/../dojo/unittests/scans/checkmarx/multiple_findings_line_changed.xml"))
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()

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
        driver.get(self.base_url + "product")
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
        driver.get(self.base_url + "product")
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

    def test_check_cross_status(self):
        self.check_nb_duplicates(1)

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(product_unit_test.ProductTest('test_create_product'))
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
    # Clean up
    suite.addTest(product_unit_test.ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
