import os
import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from selenium.webdriver.common.by import By


class LoginTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_login_page_loads(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        # Verify login form elements are present
        self.assertTrue(self.is_element_by_id_present("id_username"))
        self.assertTrue(self.is_element_by_id_present("id_password"))
        self.assertTrue(self.is_element_by_css_selector_present("button.btn.btn-success"))

    @on_exception_html_source_logger
    def test_login_valid_credentials(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys(os.environ["DD_ADMIN_USER"])
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys(os.environ["DD_ADMIN_PASSWORD"])
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        # Should not see error message after successful login
        self.assertFalse(
            self.is_element_by_css_selector_present(
                ".alert-danger", "Please enter a correct username and password",
            ),
        )

    @on_exception_html_source_logger
    def test_login_invalid_password(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys(os.environ["DD_ADMIN_USER"])
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys("wrong_password_12345")
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        # Should see error message
        self.assertTrue(
            self.is_element_by_css_selector_present(
                ".alert-danger", "Please enter a correct username and password",
            ),
        )

    @on_exception_html_source_logger
    def test_login_invalid_username(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys("nonexistent_user_xyz")
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys("some_password")
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        # Should see error message
        self.assertTrue(
            self.is_element_by_css_selector_present(
                ".alert-danger", "Please enter a correct username and password",
            ),
        )

    @on_exception_html_source_logger
    def test_login_empty_credentials(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        # Should stay on login page - HTML5 form validation prevents submission
        self.assertTrue(self.is_element_by_id_present("id_username"))

    @on_exception_html_source_logger
    def test_logout_redirects_to_login(self):
        # First login
        self.login_page()
        # Then logout
        driver = self.driver
        driver.get(self.base_url + "logout")
        # Should be redirected to login page
        self.assertTrue(self.is_text_present_on_page("Login"))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(LoginTest("test_login_page_loads"))
    suite.addTest(LoginTest("test_login_valid_credentials"))
    suite.addTest(LoginTest("test_login_invalid_password"))
    suite.addTest(LoginTest("test_login_invalid_username"))
    suite.addTest(LoginTest("test_login_empty_credentials"))
    suite.addTest(LoginTest("test_logout_redirects_to_login"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
