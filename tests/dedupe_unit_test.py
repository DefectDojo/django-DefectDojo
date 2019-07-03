from selenium import webdriver
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver
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
    def setUp(self):
        self.driver = webdriver.Chrome('chromedriver')
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:8080/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        # os.environ['DD_ADMIN_USER']
        driver.find_element_by_id("id_username").send_keys('admin')
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys('admin')
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_delete_findings(self):
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

    def test_add_path_test_suite(self):
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
        # First test
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Path Test").click()
        driver.find_element_by_partial_link_text("Path Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys("/Users/codymaffucci/Desktop/dedupe/tests/dedupe_scans/dedupe_path_1.json")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Second test
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Path Test").click()
        driver.find_element_by_partial_link_text("Path Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys("/Users/codymaffucci/Desktop/dedupe/tests/dedupe_scans/dedupe_path_2.json")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()

    def test_check_path_status(self):
        driver = self.login_page()
        driver.get(self.base_url + "finding")
        text = driver.find_element_by_tag_name("BODY").text.split('\n')

        start = text.index('Severity  Name  CWE Date  Age SLA Reporter Found By Status Product ') + 1
        text = text[start:(start + 6)]
        dupe_count = 0
        for finding in text:
            if '(DUPE)' and 'Duplicate' in finding:
                dupe_count += 1
        self.assertEqual(dupe_count, 1)

    def test_add_endpoint_test_suite(self):
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
        # First test
        driver = self.login_page()
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Endpoint Test").click()
        driver.find_element_by_partial_link_text("Endpoint Test 1").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys("/Users/codymaffucci/Desktop/dedupe/tests/dedupe_scans/dedupe_endpoint_1.xml")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Second test
        driver.get(self.base_url + "engagement")
        driver.find_element_by_partial_link_text("Dedupe Endpoint Test").click()
        driver.find_element_by_partial_link_text("Endpoint Test 2").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Re-Upload Scan").click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[3]/div/div').click()
        driver.find_element_by_xpath('//*[@id="base-content"]/form/div[4]/div/div').click()
        driver.find_element_by_id('id_file').send_keys("/Users/codymaffucci/Desktop/dedupe/tests/dedupe_scans/dedupe_endpoint_2.xml")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()

    def test_check_endpoint_status(self):
        driver = self.login_page()
        driver.get(self.base_url + "finding")
        text = driver.find_element_by_tag_name("BODY").text.split('\n')

        start = text.index('Severity  Name  CWE Date  Age SLA Reporter Found By Status Product ') + 1
        text = text[start:(start + 8)]
        dupe_count = 0
        for finding in text:
            if '(DUPE)' and 'Duplicate' in finding:
                dupe_count += 1
        self.assertEqual(dupe_count, 2)

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(product_unit_test.ProductTest('test_create_product'))
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_add_path_test_suite'))
    suite.addTest(DedupeTest('test_import_path_tests'))
    suite.addTest(DedupeTest('test_delete_findings'))
    suite.addTest(DedupeTest('test_add_endpoint_test_suite'))
    suite.addTest(DedupeTest('test_import_endpoint_tests'))
    suite.addTest(DedupeTest('test_check_endpoint_status'))
    suite.addTest(product_unit_test.ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
