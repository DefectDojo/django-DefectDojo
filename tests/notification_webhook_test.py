import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait

# Local go-httpbin mock wired into the integration-test stack (see
# docker-compose.override.integration_tests.yml). DefectDojo pings this URL
# synchronously when a webhook is saved, so it must resolve from the uwsgi
# container. Never point this at a public service (e.g. httpbin.org): that adds
# an external network dependency and makes this test flaky.
WEBHOOK_ENDPOINT_URL = "http://webhook.endpoint:8080/post"


class NotificationWebhookTest(BaseTestCase):

    def wait_for_alert(self):
        """Wait for a Bootstrap alert to render after a form submit."""
        WebDriverWait(self.driver, 30).until(
            expected_conditions.presence_of_element_located(
                (By.CSS_SELECTOR, ".alert-success, .alert-danger"),
            ),
        )

    @on_exception_html_source_logger
    def test_enable_webhook_notifications(self):
        """Enable webhook notifications in system settings."""
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        webhook_checkbox = driver.find_element(By.ID, "id_enable_webhooks_notifications")
        if not webhook_checkbox.is_selected():
            webhook_checkbox.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_list_webhooks_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "notifications/webhooks")
        self.assertTrue(self.is_text_present_on_page(text="Webhook"))

    @on_exception_html_source_logger
    def test_add_notification_webhook(self):
        driver = self.driver
        driver.get(self.base_url + "notifications/webhooks/add")
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Test Webhook")
        driver.find_element(By.ID, "id_url").clear()
        driver.find_element(By.ID, "id_url").send_keys(WEBHOOK_ENDPOINT_URL)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.wait_for_alert()
        self.assertFalse(self.is_error_message_present())
        self.assertTrue(self.is_success_message_present(text="Notification Webhook added successfully."))
        self.assertTrue(self.is_text_present_on_page(text="Test Webhook"))

    @on_exception_html_source_logger
    def test_edit_notification_webhook(self):
        driver = self.driver
        driver.get(self.base_url + "notifications/webhooks")
        # Click Edit link from the webhooks list (link text is "Edit / activate / deactivate")
        edit_links = driver.find_elements(By.CSS_SELECTOR, "a.btn.btn-warning")
        if len(edit_links) == 0:
            self.fail("No Edit link found for webhook")
        edit_links[0].click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Edited Test Webhook")
        # Ensure the endpoint stays pointed at the local mock so the save-time ping succeeds.
        driver.find_element(By.ID, "id_url").clear()
        driver.find_element(By.ID, "id_url").send_keys(WEBHOOK_ENDPOINT_URL)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.wait_for_alert()
        self.assertFalse(self.is_error_message_present())
        self.assertTrue(self.is_success_message_present(text="Notification Webhook updated successfully."))
        self.assertTrue(self.is_text_present_on_page(text="Edited Test Webhook"))

    @on_exception_html_source_logger
    def test_delete_notification_webhook(self):
        driver = self.driver
        driver.get(self.base_url + "notifications/webhooks")
        # Click Delete link from the webhooks list
        delete_links = driver.find_elements(By.CSS_SELECTOR, "a.btn.btn-danger")
        if len(delete_links) == 0:
            self.fail("No Delete link found for webhook")
        delete_links[0].click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-danger").click()

        self.wait_for_alert()
        self.assertFalse(self.is_error_message_present())
        self.assertTrue(self.is_success_message_present(text="Notification Webhook deleted successfully."))

    @on_exception_html_source_logger
    def test_disable_webhook_notifications(self):
        """Disable webhook notifications to reset system settings."""
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        webhook_checkbox = driver.find_element(By.ID, "id_enable_webhooks_notifications")
        if webhook_checkbox.is_selected():
            webhook_checkbox.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(NotificationWebhookTest("test_enable_webhook_notifications"))
    suite.addTest(NotificationWebhookTest("test_list_webhooks_page_loads"))
    suite.addTest(NotificationWebhookTest("test_add_notification_webhook"))
    suite.addTest(NotificationWebhookTest("test_edit_notification_webhook"))
    suite.addTest(NotificationWebhookTest("test_delete_notification_webhook"))
    suite.addTest(NotificationWebhookTest("test_disable_webhook_notifications"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
