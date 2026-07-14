import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select


class ThreatModelTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_create_engagement_for_threatmodel(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "Add New Interactive Engagement").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Threat Model Engagement")
        driver.find_element(By.ID, "id_name").send_keys(Keys.TAB, "Engagement for threat model testing.")
        Select(driver.find_element(By.ID, "id_lead")).select_by_visible_text("Admin User (admin)")
        Select(driver.find_element(By.ID, "id_status")).select_by_visible_text("In Progress")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertTrue(self.is_success_message_present(text="Engagement added successfully"))

    @on_exception_html_source_logger
    def test_view_threatmodel_upload_page(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Threat Model Engagement").click()
        # Click the dropdown to find the Upload Threat Model link
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Upload Threat Model").click()
        # We should be on the upload page
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)
        self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ThreatModelTest("test_create_engagement_for_threatmodel"))
    suite.addTest(ThreatModelTest("test_view_threatmodel_upload_page"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
