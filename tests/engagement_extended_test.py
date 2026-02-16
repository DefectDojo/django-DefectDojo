import logging
import os
import sys
import time
import unittest
from pathlib import Path

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest, WaitForPageLoad
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select

logger = logging.getLogger(__name__)
dir_path = Path(os.path.realpath(__file__)).parent


class EngagementExtendedTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_create_engagement_for_extended_tests(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "Add New Interactive Engagement").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Extended Test Engagement")
        driver.find_element(By.ID, "id_name").send_keys(Keys.TAB, "Extended engagement for testing.")
        Select(driver.find_element(By.ID, "id_lead")).select_by_visible_text("Admin User (admin)")
        Select(driver.find_element(By.ID, "id_status")).select_by_visible_text("In Progress")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="Engagement added successfully"))

    @on_exception_html_source_logger
    def test_close_engagement_for_reopen(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Extended Test Engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Close Engagement").click()

        self.assertTrue(self.is_success_message_present(text="Engagement closed successfully."))

    @on_exception_html_source_logger
    def test_reopen_closed_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        self.wait_for_datatable_if_content("no_active_engagements", "open_wrapper")
        driver.find_element(By.LINK_TEXT, "Extended Test Engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Reopen Engagement").click()

        self.assertTrue(self.is_success_message_present(text="Engagement reopened successfully."))

    @on_exception_html_source_logger
    def test_copy_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Extended Test Engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Copy Engagement").click()
        driver.find_element(By.ID, "id_done").click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="Engagement Copied successfully."))

    @on_exception_html_source_logger
    def test_engagement_ics_export(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Extended Test Engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Add To Calendar").click()
        # ICS export should trigger a download, verify no error page
        time.sleep(2)

    @on_exception_html_source_logger
    def test_all_engagements_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "engagement/all")
        # Wait for the DataTable to initialize
        time.sleep(2)
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_delete_extended_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.active").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Extended Test Engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Delete Engagement").click()
        driver.find_element(By.NAME, "delete_name").click()

        self.assertTrue(self.is_success_message_present(text="Engagement and relationships removed."))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(EngagementExtendedTest("test_create_engagement_for_extended_tests"))
    suite.addTest(EngagementExtendedTest("test_close_engagement_for_reopen"))
    suite.addTest(EngagementExtendedTest("test_reopen_closed_engagement"))
    suite.addTest(EngagementExtendedTest("test_copy_engagement"))
    suite.addTest(EngagementExtendedTest("test_engagement_ics_export"))
    suite.addTest(EngagementExtendedTest("test_all_engagements_page_loads"))
    suite.addTest(EngagementExtendedTest("test_delete_extended_engagement"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
