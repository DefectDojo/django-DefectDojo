from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.action_chains import ActionChains

import unittest
import sys
import os
from base_test_class import BaseTestCase
from Product_unit_test import ProductTest

dir_path = os.path.dirname(os.path.realpath(__file__))


class ReportBuilderTest(BaseTestCase):

    # Move the report blocks from Available Widgets to Report Format
    def move_blocks(self, driver):
        in_use = driver.find_element_by_id("sortable2")
        available_widgets = driver.find_element_by_id("sortable1").find_elements_by_tag_name("li")
        for widget in available_widgets:
            ActionChains(driver).drag_and_drop(widget, in_use).perform()

    # Fill in the boxes
    def enter_values(self, driver):
        in_use = driver.find_element_by_id("sortable2").find_elements_by_tag_name("li")
        for widget in in_use:
            class_names = widget.get_attribute("class")
            if 'cover-page' in class_names:
                inputs = widget.find_elements_by_tag_name("input")
                for field in inputs:
                    field.send_keys('cover words')
            if 'wysiwyg-content' in class_names:
                content = widget.find_element_by_class_name("editor").send_keys('wysiwyg')

    def generate_HTML_report(self):
        driver = self.login_page()
        driver.get(self.base_url + "reports/builder")
        self.move_blocks(driver)
        self.enter_values(driver)
        Select(driver.find_element_by_id("id_report_type")).select_by_visible_text("HTML")
        driver.find_element_by_id("id_report_name").send_keys('Test Report')
        driver.find_elements_by_class_name("run_report")[1].click()
        self.assertTrue(driver.current_url == self.base_url + "reports/custom")

    def generate_AsciiDoc_report(self):
        driver = self.login_page()
        driver.get(self.base_url + "reports/builder")
        self.move_blocks(driver)
        self.enter_values(driver)
        Select(driver.find_element_by_id("id_report_type")).select_by_visible_text("AsciiDoc")
        driver.find_element_by_id("id_report_name").send_keys('Test Report')
        driver.find_elements_by_class_name("run_report")[1].click()
        self.assertTrue(driver.current_url == self.base_url + "reports/custom")


def add_finding_tests_to_suite(suite):

    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(ProductTest('test_add_product_finding'))
    suite.addTest(ReportBuilderTest('generate_HTML_report'))
    suite.addTest(ReportBuilderTest('generate_AsciiDoc_report'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


def suite():
    suite = unittest.TestSuite()
    add_finding_tests_to_suite(suite)
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
