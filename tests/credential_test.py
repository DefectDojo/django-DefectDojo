import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select


class CredentialTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_list_credentials(self):
        driver = self.driver
        driver.get(self.base_url + "cred")
        self.assertTrue(self.is_text_present_on_page(text="Credential"))

    @on_exception_html_source_logger
    def test_add_credential(self):
        driver = self.driver
        driver.get(self.base_url + "cred")
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Add Credential").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Test Credential")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys("test_user")
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys("test_password")
        driver.find_element(By.ID, "id_role").clear()
        driver.find_element(By.ID, "id_role").send_keys("Admin")
        Select(driver.find_element(By.ID, "id_authentication")).select_by_visible_text("Form Authentication")
        driver.find_element(By.ID, "id_url").clear()
        driver.find_element(By.ID, "id_url").send_keys("https://example.com/login")
        Select(driver.find_element(By.ID, "id_environment")).select_by_index(1)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="Credential Successfully Created."))

    @on_exception_html_source_logger
    def test_view_credential(self):
        driver = self.driver
        driver.get(self.base_url + "cred")
        # The cred list table has View/Edit/Delete links per row
        driver.find_element(By.LINK_TEXT, "View").click()
        self.assertTrue(self.is_text_present_on_page(text="Test Credential"))

    @on_exception_html_source_logger
    def test_edit_credential(self):
        driver = self.driver
        driver.get(self.base_url + "cred")
        # Click the Edit link in the credential list table
        driver.find_element(By.LINK_TEXT, "Edit").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Edited Test Credential")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="Credential Successfully Updated."))

    @on_exception_html_source_logger
    def test_delete_credential(self):
        driver = self.driver
        driver.get(self.base_url + "cred")
        # Click the Delete link in the credential list table
        driver.find_element(By.LINK_TEXT, "Delete").click()
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()

        self.assertTrue(self.is_success_message_present(text="Credential Successfully Deleted."))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(CredentialTest("test_list_credentials"))
    suite.addTest(CredentialTest("test_add_credential"))
    suite.addTest(CredentialTest("test_view_credential"))
    suite.addTest(CredentialTest("test_edit_credential"))
    suite.addTest(CredentialTest("test_delete_credential"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
