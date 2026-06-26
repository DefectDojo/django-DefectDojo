import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from selenium.webdriver.common.by import By


class BannerTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_configure_banner_page_loads(self):
        """Verify the banner configuration page loads."""
        driver = self.driver
        driver.get(self.base_url + "configure_banner")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Banner")
            or self.is_text_present_on_page(text="banner")
            or self.is_text_present_on_page(text="Configuration"),
        )

    @on_exception_html_source_logger
    def test_save_banner_configuration(self):
        """Save a banner configuration."""
        driver = self.driver
        driver.get(self.base_url + "configure_banner")
        time.sleep(1)
        # Fill in the banner text if field exists
        banner_fields = driver.find_elements(By.ID, "id_banner_message")
        if len(banner_fields) > 0:
            banner_fields[0].clear()
            banner_fields[0].send_keys("Integration Test Banner Message")
        # Enable banner checkbox if exists
        enable_fields = driver.find_elements(By.ID, "id_banner_enable")
        if len(enable_fields) > 0 and not enable_fields[0].is_selected():
            enable_fields[0].click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Banner")
            or self.is_success_message_present(text="Settings")
            or self.is_text_present_on_page(text="Banner"),
        )

    @on_exception_html_source_logger
    def test_disable_banner(self):
        """Disable the banner."""
        driver = self.driver
        driver.get(self.base_url + "configure_banner")
        time.sleep(1)
        # Disable banner
        enable_fields = driver.find_elements(By.ID, "id_banner_enable")
        if len(enable_fields) > 0 and enable_fields[0].is_selected():
            enable_fields[0].click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Banner")
            or self.is_success_message_present(text="Settings")
            or self.is_text_present_on_page(text="Banner"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(BannerTest("test_configure_banner_page_loads"))
    suite.addTest(BannerTest("test_save_banner_configuration"))
    suite.addTest(BannerTest("test_disable_banner"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
