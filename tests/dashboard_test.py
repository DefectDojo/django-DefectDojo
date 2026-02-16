import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class DashboardTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_dashboard_loads(self):
        driver = self.driver
        driver.get(self.base_url)
        # Verify the page loaded by checking for dashboard content
        self.assertTrue(self.is_text_present_on_page(text="Active Engagements"))

    @on_exception_html_source_logger
    def test_dashboard_explicit_url(self):
        driver = self.driver
        driver.get(self.base_url + "dashboard")
        self.assertTrue(self.is_text_present_on_page(text="Active Engagements"))

    @on_exception_html_source_logger
    def test_support_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "support")
        self.assertTrue(self.is_text_present_on_page(text="Support"))

    @on_exception_html_source_logger
    def test_dashboard_contains_widgets(self):
        driver = self.driver
        driver.get(self.base_url + "dashboard")
        # Verify dashboard contains key elements
        body_text = driver.find_element(By.TAG_NAME, "body").text
        # The dashboard should display some metrics or status info
        self.assertIsNotNone(body_text)
        self.assertTrue(len(body_text) > 0)

    @on_exception_html_source_logger
    def test_dashboard_with_product_data(self):
        driver = self.driver
        driver.get(self.base_url + "dashboard")
        # After product and finding creation, dashboard should reflect data
        self.assertTrue(self.is_text_present_on_page(text="Active Engagements"))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(DashboardTest("test_dashboard_loads"))
    suite.addTest(DashboardTest("test_dashboard_explicit_url"))
    suite.addTest(DashboardTest("test_support_page_loads"))
    suite.addTest(DashboardTest("test_dashboard_contains_widgets"))
    suite.addTest(DashboardTest("test_dashboard_with_product_data"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
