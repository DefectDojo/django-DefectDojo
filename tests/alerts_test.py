import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from selenium.webdriver.common.by import By


class AlertsTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_alerts_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "alerts")
        self.assertTrue(self.is_text_present_on_page(text="Alerts"))

    @on_exception_html_source_logger
    def test_alerts_page_with_no_alerts(self):
        driver = self.driver
        driver.get(self.base_url + "alerts")
        # Page should load successfully even with no alerts
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_delete_all_alerts(self):
        driver = self.driver
        driver.get(self.base_url + "delete_alerts")
        # After deleting all alerts, verify we're redirected or get success
        # The page should redirect back to alerts
        self.assertTrue(
            self.is_text_present_on_page(text="Alerts")
            or self.is_success_message_present(text="Alerts removed"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(AlertsTest("test_alerts_page_loads"))
    suite.addTest(AlertsTest("test_alerts_page_with_no_alerts"))
    suite.addTest(AlertsTest("test_delete_all_alerts"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
