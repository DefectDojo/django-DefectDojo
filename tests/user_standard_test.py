import os
import unittest
import sys
from base_test_class import BaseTestCase
from user_test import UserTest
from django.test import override_settings

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import ActionChains


class UserStandardTest(BaseTestCase):

    def login_standard_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys('propersahm')
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys('Def3ctD0jo&')
        driver.find_element_by_css_selector("button.btn.btn-success").click()

        self.assertFalse(self.is_element_by_css_selector_present('.alert-danger', 'Please enter a correct username and password'))
        return driver

    def test_standard_user_login(self):
        self.login_standard_page()

#    @override_settings(USER_PROFILE_READ_ONLY=True)
    def test_admin_profile_form(self):
        self.driver.get(self.base_url + "profile")
        self.assertTrue(self.driver.find_element_by_id('id_first_name').is_enabled())

#    @override_settings(USER_PROFILE_READ_ONLY=True)
    def test_user_profile_form(self):
        self.driver.get(self.base_url + "profile")
        self.assertFalse(self.driver.find_element_by_id('id_first_name').is_enabled())

def suite():

    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(UserTest('test_create_user'))
    suite.addTest(UserStandardTest('test_admin_profile_form'))
    suite.addTest(BaseTestCase('test_logout'))
    suite.addTest(UserStandardTest('test_standard_user_login'))
    suite.addTest(UserStandardTest('test_user_profile_form'))
    suite.addTest(BaseTestCase('test_logout'))
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(UserTest('test_user_delete'))

    return suite


if __name__ == "__main__":

    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
