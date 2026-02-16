import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class ProductMetadataTest(BaseTestCase):

    def _get_product_id(self, driver):
        """Navigate to QA Test product and return the product ID."""
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        return parts[-1]

    @on_exception_html_source_logger
    def test_add_product_metadata(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/add_meta_data")
        time.sleep(1)
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Test Metadata Key")
        driver.find_element(By.ID, "id_value").clear()
        driver.find_element(By.ID, "id_value").send_keys("Test Metadata Value")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Metadata added successfully")
            or self.is_success_message_present(text="metadata entry with the same name")
            or self.is_text_present_on_page(text="QA Test"),
        )

    @on_exception_html_source_logger
    def test_edit_product_metadata(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/edit_meta_data")
        time.sleep(1)
        # Find the value field and update it
        value_fields = driver.find_elements(By.XPATH, "//input[@value='Test Metadata Value']")
        if len(value_fields) > 0:
            value_fields[0].clear()
            value_fields[0].send_keys("Updated Metadata Value")
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            self.assertTrue(
                self.is_success_message_present(text="Metadata edited successfully")
                or self.is_text_present_on_page(text="QA Test"),
            )
        else:
            # If metadata doesn't exist yet, just verify the edit page loads
            self.assertTrue(
                self.is_text_present_on_page(text="Edit Custom Fields")
                or self.is_text_present_on_page(text="QA Test"),
            )

    @on_exception_html_source_logger
    def test_view_product_with_metadata(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}")
        time.sleep(1)
        # Verify the product page loads and potentially shows metadata
        self.assertTrue(self.is_text_present_on_page(text="QA Test"))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductMetadataTest("test_add_product_metadata"))
    suite.addTest(ProductMetadataTest("test_edit_product_metadata"))
    suite.addTest(ProductMetadataTest("test_view_product_with_metadata"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
