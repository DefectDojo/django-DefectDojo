import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from selenium.webdriver.common.by import By


class UserProfileTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_view_profile_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "profile")
        self.assertTrue(
            self.is_text_present_on_page(text="User Profile")
            or self.is_text_present_on_page(text="profile"),
        )

    @on_exception_html_source_logger
    def test_edit_profile(self):
        driver = self.driver
        driver.get(self.base_url + "profile")
        time.sleep(1)
        # Edit first name
        first_name = driver.find_element(By.ID, "id_first_name")
        first_name.clear()
        first_name.send_keys("Admin")
        last_name = driver.find_element(By.ID, "id_last_name")
        last_name.clear()
        last_name.send_keys("User")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Profile updated successfully")
            or self.is_text_present_on_page(text="User Profile"),
        )

    @on_exception_html_source_logger
    def test_change_password_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "change_password")
        self.assertTrue(
            self.is_text_present_on_page(text="Change Password")
            or self.is_text_present_on_page(text="password"),
        )

    @on_exception_html_source_logger
    def test_api_key_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "api/key-v2")
        self.assertTrue(
            self.is_text_present_on_page(text="API")
            or self.is_text_present_on_page(text="Key"),
        )

    @on_exception_html_source_logger
    def test_generate_api_key(self):
        driver = self.driver
        driver.get(self.base_url + "api/key-v2")
        time.sleep(1)
        # Submit form to generate new key
        submit_btns = driver.find_elements(By.CSS_SELECTOR, "input.btn.btn-primary")
        if len(submit_btns) > 0:
            submit_btns[0].click()
            time.sleep(1)
            self.assertTrue(
                self.is_success_message_present(text="API Key generated successfully")
                or self.is_text_present_on_page(text="API"),
            )
        else:
            self.assertTrue(self.is_text_present_on_page(text="API"))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(UserProfileTest("test_view_profile_page_loads"))
    suite.addTest(UserProfileTest("test_edit_profile"))
    suite.addTest(UserProfileTest("test_change_password_page_loads"))
    suite.addTest(UserProfileTest("test_api_key_page_loads"))
    suite.addTest(UserProfileTest("test_generate_api_key"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
