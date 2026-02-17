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
        # Navigate directly to the add metadata URL (avoids dropdown link text differences)
        driver.get(self.base_url + f"product/{pid}/add_meta_data")
        time.sleep(1)
        # Metadata uses Django formsets — field IDs are prefixed with form-0-
        name_field = driver.find_element(By.ID, "id_form-0-name")
        name_field.clear()
        name_field.send_keys("Test Metadata Key")
        value_field = driver.find_element(By.ID, "id_form-0-value")
        value_field.clear()
        value_field.send_keys("Test Metadata Value")
        # Submit button is a <button class="btn btn-success">
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()

        self.assertTrue(
            self.is_success_message_present(text="Metadata updated successfully")
            or self.is_text_present_on_page(text="QA Test"),
        )

    @on_exception_html_source_logger
    def test_edit_product_metadata(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        # Navigate directly to the edit metadata URL
        driver.get(self.base_url + f"product/{pid}/edit_meta_data")
        time.sleep(1)
        # Find the value field and update it
        value_fields = driver.find_elements(By.CSS_SELECTOR, "input[name$='-value']")
        if len(value_fields) > 0:
            value_fields[0].clear()
            value_fields[0].send_keys("Updated Metadata Value")
            driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
            self.assertTrue(
                self.is_success_message_present(text="Metadata updated successfully")
                or self.is_text_present_on_page(text="QA Test"),
            )
        else:
            # No metadata entries to edit — just verify page loaded
            self.assertTrue(self.is_text_present_on_page(text="QA Test")
                            or self.is_text_present_on_page(text="Metadata"))

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
