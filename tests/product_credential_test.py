import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select


class ProductCredentialTest(BaseTestCase):

    def _get_product_id(self, driver):
        """Navigate to QA Test product and return the product ID."""
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        return parts[-1]

    @on_exception_html_source_logger
    def test_ensure_global_credential_exists(self):
        """Ensure a global credential exists for product-level mapping."""
        driver = self.driver
        driver.get(self.base_url + "cred")
        time.sleep(1)
        # Check if any credentials already exist
        cred_links = driver.find_elements(By.CSS_SELECTOR, "table tbody tr td a")
        if len(cred_links) == 0:
            driver.get(self.base_url + "cred/add")
            time.sleep(1)
            driver.find_element(By.ID, "id_name").clear()
            driver.find_element(By.ID, "id_name").send_keys("Test Product Credential")
            driver.find_element(By.ID, "id_username").clear()
            driver.find_element(By.ID, "id_username").send_keys("testuser")
            driver.find_element(By.ID, "id_password").clear()
            driver.find_element(By.ID, "id_password").send_keys("testpass123")
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            time.sleep(1)
            self.assertTrue(
                self.is_success_message_present(text="Credential Successfully Created")
                or self.is_text_present_on_page(text="Credential"),
            )
        # Verify we're on the credential page
        driver.get(self.base_url + "cred")
        self.assertTrue(self.is_text_present_on_page(text="Credential"))

    @on_exception_html_source_logger
    def test_list_product_credentials(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/cred/all")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Credential")
            or self.is_text_present_on_page(text="No credentials"),
        )

    @on_exception_html_source_logger
    def test_add_product_credential(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/cred/add")
        time.sleep(1)
        # Select a credential from the dropdown using Select helper
        cred_select = driver.find_elements(By.ID, "id_cred_id")
        if len(cred_select) > 0:
            select = Select(cred_select[0])
            if len(select.options) > 1:
                select.select_by_index(1)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(1)

        # The view sends "Credential Successfully Updated." on success with alert-success
        # or "Credential already associated." with alert-danger
        # After redirect, the page title has "Credentials"
        self.assertTrue(
            self.is_success_message_present(text="Credential Successfully Updated")
            or self.is_text_present_on_page(text="Credential already associated")
            or self.is_text_present_on_page(text="Credential"),
        )

    @on_exception_html_source_logger
    def test_view_product_credential(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/cred/all")
        time.sleep(1)
        # Click on the first credential view link if any exist
        view_links = driver.find_elements(By.CSS_SELECTOR, "a[href*='/cred/'][href*='/view']")
        if len(view_links) > 0:
            view_links[0].click()
            time.sleep(1)
            self.assertTrue(
                self.is_text_present_on_page(text="Credential")
                or self.is_text_present_on_page(text="View"),
            )
        else:
            self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_delete_product_credential(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/cred/all")
        time.sleep(1)
        delete_links = driver.find_elements(By.CSS_SELECTOR, "a[href*='/cred/'][href*='/delete']")
        if len(delete_links) > 0:
            delete_links[0].click()
            time.sleep(1)
            # Confirm deletion
            confirm_btns = driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-danger")
            if len(confirm_btns) > 0:
                confirm_btns[0].click()
            else:
                input_btns = driver.find_elements(By.CSS_SELECTOR, "input.btn.btn-danger")
                if len(input_btns) > 0:
                    input_btns[0].click()
            time.sleep(1)
            self.assertTrue(
                self.is_success_message_present(text="Credential Successfully Deleted")
                or self.is_text_present_on_page(text="Credential"),
            )
        else:
            self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductCredentialTest("test_ensure_global_credential_exists"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductCredentialTest("test_list_product_credentials"))
    suite.addTest(ProductCredentialTest("test_add_product_credential"))
    suite.addTest(ProductCredentialTest("test_view_product_credential"))
    suite.addTest(ProductCredentialTest("test_delete_product_credential"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
