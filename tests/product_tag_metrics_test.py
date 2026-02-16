import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class ProductTagMetricsTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_product_tag_counts_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "metrics/product/tag/counts")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_product_tag_counts_with_filter(self):
        driver = self.driver
        driver.get(self.base_url + "metrics/product/tag/counts")
        # Verify the page has filter or content elements
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)
        # Try applying a filter if available
        filter_inputs = driver.find_elements(By.CSS_SELECTOR, "select, input[type='text']")
        if len(filter_inputs) > 0:
            # Submit the filter form if present
            submit_buttons = driver.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit']")
            if len(submit_buttons) > 0:
                submit_buttons[0].click()
                self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTagMetricsTest("test_product_tag_counts_page_loads"))
    suite.addTest(ProductTagMetricsTest("test_product_tag_counts_with_filter"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
