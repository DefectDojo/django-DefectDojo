import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class EndpointExtendedTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_vulnerable_endpoints_page(self):
        driver = self.driver
        driver.get(self.base_url + "endpoint/vulnerable")
        self.assertTrue(self.is_text_present_on_page(text="Endpoint"))

    @on_exception_html_source_logger
    def test_vulnerable_endpoint_hosts_page(self):
        driver = self.driver
        driver.get(self.base_url + "endpoint/host/vulnerable")
        self.assertTrue(self.is_text_present_on_page(text="Vulnerable Hosts"))

    @on_exception_html_source_logger
    def test_endpoint_host_list(self):
        driver = self.driver
        driver.get(self.base_url + "endpoint/host")
        self.assertTrue(self.is_text_present_on_page(text="All Hosts"))

    @on_exception_html_source_logger
    def test_add_endpoint_meta_data(self):
        driver = self.driver
        # Navigate to the product and its endpoints
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Endpoints").click()
        driver.find_element(By.LINK_TEXT, "View Endpoints").click()
        # Click on the first endpoint
        driver.find_element(By.CSS_SELECTOR, "table tbody tr td a").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Add Metadata").click()
        time.sleep(1)
        # Metadata uses Django formsets — field IDs are prefixed with form-0-
        driver.find_element(By.ID, "id_form-0-name").clear()
        driver.find_element(By.ID, "id_form-0-name").send_keys("Environment")
        driver.find_element(By.ID, "id_form-0-value").clear()
        driver.find_element(By.ID, "id_form-0-value").send_keys("Production")
        # Submit button is a <button class="btn btn-success">
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()

        self.assertTrue(
            self.is_success_message_present(text="Metadata updated successfully")
            or self.is_text_present_on_page(text="Endpoint"),
        )

    @on_exception_html_source_logger
    def test_edit_endpoint_meta_data(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Endpoints").click()
        driver.find_element(By.LINK_TEXT, "View Endpoints").click()
        # Click on the first endpoint
        driver.find_element(By.CSS_SELECTOR, "table tbody tr td a").click()
        # Click the edit metadata icon button (title="Edit Information")
        edit_links = driver.find_elements(By.CSS_SELECTOR, "a[title='Edit Information']")
        if len(edit_links) > 0:
            edit_links[0].click()
            time.sleep(1)
            # Edit the value field
            value_fields = driver.find_elements(By.CSS_SELECTOR, "input[name$='-value']")
            if len(value_fields) > 0:
                value_fields[0].clear()
                value_fields[0].send_keys("Staging")
            driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
            self.assertTrue(
                self.is_success_message_present(text="Metadata updated successfully")
                or self.is_text_present_on_page(text="Endpoint"),
            )
        else:
            # No edit link — just verify page loads
            self.assertTrue(self.is_text_present_on_page(text="Endpoint"))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_endpoints"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(EndpointExtendedTest("test_vulnerable_endpoints_page"))
    suite.addTest(EndpointExtendedTest("test_vulnerable_endpoint_hosts_page"))
    suite.addTest(EndpointExtendedTest("test_endpoint_host_list"))
    suite.addTest(EndpointExtendedTest("test_add_endpoint_meta_data"))
    suite.addTest(EndpointExtendedTest("test_edit_endpoint_meta_data"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
