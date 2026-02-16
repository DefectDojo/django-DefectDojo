import sys
import time
import unittest
from pathlib import Path

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest, WaitForPageLoad
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select

dir_path = Path(__file__).parent


class ReimportScanTest(BaseTestCase):

    def _get_engagement_id(self, driver):
        """Navigate to the Beta Test engagement and return its ID."""
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        eng_links = driver.find_elements(By.LINK_TEXT, "Beta Test")
        if len(eng_links) > 0:
            eng_links[0].click()
            time.sleep(1)
            current_url = driver.current_url
            parts = current_url.rstrip("/").split("/")
            for i, part in enumerate(parts):
                if part == "engagement" and i + 1 < len(parts):
                    return parts[i + 1]
            return parts[-1]
        return None

    @on_exception_html_source_logger
    def test_import_scan_page_loads(self):
        """Test the import scan results page loads from product."""
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        pid = parts[-1]
        driver.get(self.base_url + f"product/{pid}/import_scan_results")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Import")
            or self.is_text_present_on_page(text="Scan"),
        )

    @on_exception_html_source_logger
    def test_import_scan_from_engagement(self):
        """Test the import scan results page loads from engagement."""
        driver = self.driver
        eid = self._get_engagement_id(driver)
        self.assertIsNotNone(eid, "Could not find Beta Test engagement")
        driver.get(self.base_url + f"engagement/{eid}/import_scan_results")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Import")
            or self.is_text_present_on_page(text="Scan"),
        )

    @on_exception_html_source_logger
    def test_reimport_page_loads(self):
        """Test the reimport page loads for an existing test."""
        driver = self.driver
        eid = self._get_engagement_id(driver)
        self.assertIsNotNone(eid, "Could not find Beta Test engagement")
        # Navigate to the engagement page and find a test
        driver.get(self.base_url + f"engagement/{eid}")
        time.sleep(1)
        # Look for test links in the engagement detail page
        test_links = driver.find_elements(By.CSS_SELECTOR, "a[href*='/test/']")
        if len(test_links) > 0:
            test_links[0].click()
            time.sleep(1)
            current_url = driver.current_url
            parts = current_url.rstrip("/").split("/")
            test_id = parts[-1]
            driver.get(self.base_url + f"test/{test_id}/re_import_scan_results")
            time.sleep(1)
            self.assertTrue(
                self.is_text_present_on_page(text="Re-Import")
                or self.is_text_present_on_page(text="Import")
                or self.is_text_present_on_page(text="Scan"),
            )
        else:
            # No tests available to reimport
            self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_engagement"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(ReimportScanTest("test_import_scan_page_loads"))
    suite.addTest(ReimportScanTest("test_import_scan_from_engagement"))
    suite.addTest(ReimportScanTest("test_reimport_page_loads"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
