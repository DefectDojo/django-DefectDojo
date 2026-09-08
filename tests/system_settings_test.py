import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from selenium.webdriver.common.by import By


class SystemSettingsTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_system_settings_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        # Verify the settings page loads with the form
        self.assertTrue(self.is_element_by_css_selector_present("input.btn.btn-primary"))

    @on_exception_html_source_logger
    def test_toggle_deduplication(self):
        # Disable deduplication first, then re-enable it
        # (always end with enabled to avoid breaking dedupe_test.py)
        self.disable_system_setting("id_enable_deduplication")
        self.enable_system_setting("id_enable_deduplication")

    @on_exception_html_source_logger
    def test_toggle_false_positive_history(self):
        # Disable then re-enable to test both states
        # (always end with disabled since that's the default)
        #
        # False positive history and deduplication are mutually exclusive: the
        # settings view refuses the save outright with "Deduplicate findings and
        # False positive history can not be set at the same time", and the
        # deduplication toggle above deliberately ends with deduplication ON. So
        # turn deduplication off for the duration and put it back afterwards,
        # the way dedupe_test.py expects to find it.
        self.disable_system_setting("id_enable_deduplication")
        self.enable_system_setting("id_false_positive_history")
        self.disable_system_setting("id_false_positive_history")
        self.enable_system_setting("id_enable_deduplication")

    @on_exception_html_source_logger
    def test_toggle_jira_integration(self):
        # Enable JIRA
        self.enable_jira()
        # Disable JIRA
        self.disable_jira()

    @on_exception_html_source_logger
    def test_toggle_github_integration(self):
        # Enable GitHub
        self.enable_github()
        # Disable GitHub
        self.disable_github()

    @on_exception_html_source_logger
    def test_change_max_dupes_setting(self):
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        # Find and modify max duplicates field
        max_dupes_field = driver.find_element(By.ID, "id_max_dupes")
        original_value = max_dupes_field.get_attribute("value")
        max_dupes_field.clear()
        max_dupes_field.send_keys("10")
        self.click_submit(driver)
        # Verify saved
        driver.get(self.base_url + "system_settings")
        self.assertEqual(driver.find_element(By.ID, "id_max_dupes").get_attribute("value"), "10")
        # Reset to original
        driver.find_element(By.ID, "id_max_dupes").clear()
        driver.find_element(By.ID, "id_max_dupes").send_keys(original_value)
        self.click_submit(driver)

    @on_exception_html_source_logger
    def test_settings_save_and_reload(self):
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        # Just verify the page loads and save button works
        self.click_submit(driver)
        # After save, the page should reload without errors
        self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(SystemSettingsTest("test_system_settings_page_loads"))
    suite.addTest(SystemSettingsTest("test_toggle_deduplication"))
    suite.addTest(SystemSettingsTest("test_toggle_false_positive_history"))
    suite.addTest(SystemSettingsTest("test_toggle_jira_integration"))
    suite.addTest(SystemSettingsTest("test_toggle_github_integration"))
    suite.addTest(SystemSettingsTest("test_change_max_dupes_setting"))
    suite.addTest(SystemSettingsTest("test_settings_save_and_reload"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
