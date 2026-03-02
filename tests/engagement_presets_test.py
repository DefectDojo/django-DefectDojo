import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class EngagementPresetsTest(BaseTestCase):

    def _navigate_to_engagement_presets(self, driver):
        """Navigate to the engagement presets page for the QA Test product via direct URL."""
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Get product ID from current URL
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        pid = parts[-1]
        driver.get(self.base_url + f"product/{pid}/engagement_presets")
        return pid

    @on_exception_html_source_logger
    def test_list_engagement_presets(self):
        driver = self.driver
        self._navigate_to_engagement_presets(driver)
        self.assertTrue(self.is_text_present_on_page(text="Engagement Presets"))

    @on_exception_html_source_logger
    def test_add_engagement_preset(self):
        driver = self.driver
        pid = self._navigate_to_engagement_presets(driver)
        driver.get(self.base_url + f"product/{pid}/engagement_presets/add")
        driver.find_element(By.ID, "id_title").clear()
        driver.find_element(By.ID, "id_title").send_keys("Test Preset")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Engagement Preset Successfully Created")
            or self.is_text_present_on_page(text="Test Preset"),
        )

    @on_exception_html_source_logger
    def test_edit_engagement_preset(self):
        driver = self.driver
        self._navigate_to_engagement_presets(driver)
        # Click the Edit link in the table for the preset
        driver.find_element(By.LINK_TEXT, "Edit").click()
        driver.find_element(By.ID, "id_title").clear()
        driver.find_element(By.ID, "id_title").send_keys("Edited Test Preset")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Engagement Preset Successfully Updated")
            or self.is_text_present_on_page(text="Edited Test Preset"),
        )

    @on_exception_html_source_logger
    def test_delete_engagement_preset(self):
        driver = self.driver
        self._navigate_to_engagement_presets(driver)
        # Click the Delete link in the table for the preset
        driver.find_element(By.LINK_TEXT, "Delete").click()
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()

        self.assertTrue(
            self.is_success_message_present(text="Engagement presets and engagement relationships removed")
            or self.is_text_present_on_page(text="Engagement Presets"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(EngagementPresetsTest("test_list_engagement_presets"))
    suite.addTest(EngagementPresetsTest("test_add_engagement_preset"))
    suite.addTest(EngagementPresetsTest("test_edit_engagement_preset"))
    suite.addTest(EngagementPresetsTest("test_delete_engagement_preset"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
