from selenium.webdriver.support.ui import Select
import unittest
import re
import sys
import os
from base_test_class import BaseTestCase
from Product_unit_test import ProductTest


dir_path = os.path.dirname(os.path.realpath(__file__))


class IBMAppScanTest(BaseTestCase):

    def test_import_ibm_app_scan_result(self):
        # Login to the site.
        # Username and password will be gotten from environ
        driver = self.login_page()
        # Navigate to the Endpoint page
        driver.get(self.base_url + "product")
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the Finding Drop down
        driver.find_element_by_partial_link_text("Findings").click()
        # "Click" the New Endpoint
        driver.find_element_by_link_text("Import Scan Results").click()
        # Select scan type
        Select(driver.find_element_by_id("id_scan_type")).select_by_visible_text("IBM AppScan DAST")
        # Upload Scan result file
        scanner_file = os.path.join(dir_path, "ibm_appscan_xml_file.xml")
        driver.find_element_by_name("file").send_keys(scanner_file)
        # click on upload button
        driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert the query to determine status or failure
        self.assertTrue(re.search(r'IBM AppScan DAST processed, a total of 27 findings were processed', productTxt))


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(IBMAppScanTest('test_import_ibm_app_scan_result'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
