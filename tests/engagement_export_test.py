import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class EngagementExportTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_all_engagements_page_export_links(self):
        """Verify the all engagements page has export links."""
        driver = self.driver
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Engagement")
            or self.is_text_present_on_page(text="engagements"),
        )
        # Check that CSV/Excel export links exist on the page
        csv_links = driver.find_elements(By.CSS_SELECTOR, "a[href*='csv_export']")
        excel_links = driver.find_elements(By.CSS_SELECTOR, "a[href*='excel_export']")
        self.assertTrue(
            len(csv_links) > 0 or len(excel_links) > 0
            or self.is_text_present_on_page(text="Export"),
        )

    @on_exception_html_source_logger
    def test_active_engagements_page(self):
        """Test the active engagements page loads correctly."""
        driver = self.driver
        driver.get(self.base_url + "engagement/active")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Engagement")
            or self.is_text_present_on_page(text="Active"),
        )

    @on_exception_html_source_logger
    def test_all_engagements_page(self):
        """Test the all engagements page loads correctly."""
        driver = self.driver
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Engagement")
            or self.is_text_present_on_page(text="Beta Test"),
        )

    @on_exception_html_source_logger
    def test_engagement_detail_page(self):
        """Navigate to a specific engagement detail page."""
        driver = self.driver
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        eng_links = driver.find_elements(By.LINK_TEXT, "Beta Test")
        if len(eng_links) > 0:
            eng_links[0].click()
            time.sleep(1)
            self.assertTrue(
                self.is_text_present_on_page(text="Beta Test")
                or self.is_text_present_on_page(text="Engagement"),
            )
        else:
            self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_engagement"))
    suite.addTest(EngagementExportTest("test_all_engagements_page_export_links"))
    suite.addTest(EngagementExportTest("test_active_engagements_page"))
    suite.addTest(EngagementExportTest("test_all_engagements_page"))
    suite.addTest(EngagementExportTest("test_engagement_detail_page"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
