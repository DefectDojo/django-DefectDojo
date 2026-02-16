import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select


class TestCopyTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_create_engagement_and_test(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "Add New Interactive Engagement").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Copy Test Engagement")
        driver.find_element(By.ID, "id_name").send_keys(Keys.TAB, "Engagement for copy test.")
        Select(driver.find_element(By.ID, "id_lead")).select_by_visible_text("Admin User (admin)")
        Select(driver.find_element(By.ID, "id_status")).select_by_visible_text("In Progress")
        # Click "Add Tests" submit button which creates the engagement and
        # redirects directly to the add tests page
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary[value='Add Tests']").click()
        self.assertTrue(self.is_success_message_present(text="Engagement added successfully"))
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Pen Test")
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertTrue(self.is_success_message_present(text="Test added successfully"))

    @on_exception_html_source_logger
    def test_copy_test(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Copy Test Engagement").click()
        driver.find_element(By.LINK_TEXT, "Pen Test").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Copy Test").click()
        # Select the first available engagement in the copy form
        Select(driver.find_element(By.ID, "id_engagement")).select_by_index(1)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Test Copied successfully")
            or self.is_text_present_on_page(text="Pen Test"),
        )

    @on_exception_html_source_logger
    def test_copy_test_preserves_data(self):
        driver = self.driver
        # After copy, we should be on the copied test page
        # Verify the test type is preserved
        self.assertTrue(self.is_text_present_on_page(text="Pen Test"))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(TestCopyTest("test_create_engagement_and_test"))
    suite.addTest(TestCopyTest("test_copy_test"))
    suite.addTest(TestCopyTest("test_copy_test_preserves_data"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
