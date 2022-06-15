import os
import sys
import unittest

from selenium.webdriver.common.by import By

from base_test_class import BaseTestCase


class SLAConfigurationTest(BaseTestCase):

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        return driver

    def test_add_sla_config(self):
        driver = self.driver
        driver.get(self.base_url + "sla_config")
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Add SLA Configuration").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Test SLA Configuration")
        driver.find_element(By.ID, "id_description").clear()
        driver.find_element(By.ID, "id_description").send_keys("This is a Test SLA Configuration for the purposes of testing")
        driver.find_element(By.ID, "id_critical").clear()
        driver.find_element(By.ID, "id_critical").send_keys("1")
        driver.find_element(By.ID, "id_critical").clear()
        driver.find_element(By.ID, "id_critical").send_keys("2")
        driver.find_element(By.ID, "id_critical").clear()
        driver.find_element(By.ID, "id_critical").send_keys("3")
        driver.find_element(By.ID, "id_critical").clear()
        driver.find_element(By.ID, "id_critical").send_keys("4")
        driver.find_element(By.VALUE, "Submit").click()

        self.assertTrue(self.is_success_message_present(text='SLA configuration Successfully Created.'))

    def test_edit_sla_config(self):
        driver = self.driver
        driver.get(self.base_url + "sla_config")
        driver.find_element(By.LINK_TEXT, "Test SLA Configuration").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Edited Test SLA Configuration test")
        driver.find_element(By.ID, "submit").click()
        self.assertTrue(self.is_success_message_present(text='SLA configuration Successfully Updated.'))

    def test_delete_sla_config(self):
        driver = self.driver
        driver.get(self.base_url + "sla_config")
        driver.find_element(By.LINK_TEXT, "Edited Test SLA Configuration test").click()
        driver.find_element(By.ID, "delete").click()
        self.assertTrue(self.is_success_message_present(text='SLA configuration Deleted.'))

    def test_delete_default_sla(self):
        driver = self.driver
        driver.get(self.base_url + "sla_config")
        driver.find_element(By.LINK_TEXT, "Edited Test SLA Configuration test").click()
        driver.find_element(By.ID, "delete").click()
        self.assertTrue(self.is_error_message_present(text='The Default SLA Configuration cannot be deleted.'))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(BaseTestCase('disable_block_execution'))
    suite.addTest(SLAConfigurationTest('test_add_sla_config'))
    suite.addTest(SLAConfigurationTest('test_edit_sla_config'))
    suite.addTest(SLAConfigurationTest('test_delete_sla_config'))
    suite.addTest(SLAConfigurationTest('test_delete_default_sla'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
