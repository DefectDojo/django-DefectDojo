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
        """
        Wait for a Bootstrap alert to render after a form submit.

        This is the barrier that tells us the POST response has been rendered,
        so the caller is looking at the saved page rather than the pre-submit
        one. base.html only emits .alert markup for the messages framework, so
        nothing else on the page can satisfy this wait.

        .alert-warning is included because a rejected save is a warning, not an
        error: the system settings view answers "Settings cannot be saved: ..."
        with messages.WARNING. Waiting only for success or danger would sit here
        for the full timeout and then report a TimeoutException, instead of
        letting the caller's assertions name what actually went wrong.
        """
        WebDriverWait(self.driver, 30).until(
            expected_conditions.presence_of_element_located(
                (By.CSS_SELECTOR, ".alert-success, .alert-danger, .alert-warning"),
            ),
        )

    @on_exception_html_source_logger
    def test_enable_webhook_notifications(self):
        """
        Enable webhook notifications in system settings.

        Wait for the save to land before returning. click_submit() only clicks:
        it does not wait for the POST response, and is_error_message_present()
        is an emptiness check on .alert-danger that the pre-submit page passes
        just as happily as the saved one. Without a barrier the next test in the
        suite can navigate away while the POST is still in flight, the setting
        is never persisted, and /notifications/webhooks then 404s (see
        NotificationWebhooksView.check_webhooks_enabled). The failure surfaces
        in the NEXT test's teardown as a SEVERE console error, which blames the
        wrong test. The sibling tests below already wait, so do the same here.
        """
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        webhook_checkbox = driver.find_element(By.ID, "id_enable_webhooks_notifications")
        if not webhook_checkbox.is_selected():
            webhook_checkbox.click()
        self.click_submit(driver)

        self.wait_for_alert()
        self.assertFalse(self.is_error_message_present())
        self.assertTrue(self.is_success_message_present(text="Settings saved."))

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
        self.click_submit(driver)

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
        self.click_submit(driver)

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
        self.click_submit(driver, "input.btn.btn-danger")

        self.wait_for_alert()
        self.assertFalse(self.is_error_message_present())
        self.assertTrue(self.is_success_message_present(text="Notification Webhook deleted successfully."))

    @on_exception_html_source_logger
    def test_disable_webhook_notifications(self):
        """
        Disable webhook notifications to reset system settings.

        Same barrier as test_enable_webhook_notifications: this test claims to
        reset the setting, so it has to confirm the reset actually saved.
        """
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        webhook_checkbox = driver.find_element(By.ID, "id_enable_webhooks_notifications")
        if webhook_checkbox.is_selected():
            webhook_checkbox.click()
        self.click_submit(driver)

        self.wait_for_alert()
        self.assertFalse(self.is_error_message_present())
        self.assertTrue(self.is_success_message_present(text="Settings saved."))


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
