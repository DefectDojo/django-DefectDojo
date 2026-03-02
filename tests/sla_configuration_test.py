import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from selenium.webdriver.common.by import By


class SLAConfigurationTest(BaseTestCase):

    @on_exception_html_source_logger
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
        driver.find_element(By.ID, "id_high").clear()
        driver.find_element(By.ID, "id_high").send_keys("2")
        driver.find_element(By.ID, "id_medium").clear()
        driver.find_element(By.ID, "id_medium").send_keys("3")
        driver.find_element(By.ID, "id_low").clear()
        driver.find_element(By.ID, "id_low").send_keys("4")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="SLA configuration Successfully Created."))

    @on_exception_html_source_logger
    def test_edit_sla_config(self):
        driver = self.driver
        driver.get(self.base_url + "sla_config")
        driver.find_element(By.LINK_TEXT, "Test SLA Configuration").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Edited Test SLA Configuration test")
        driver.find_element(By.ID, "submit").click()
        self.assertTrue(self.is_success_message_present(text="SLA configuration successfully updated"))

    @on_exception_html_source_logger
    def test_delete_sla_config(self):
        driver = self.driver
        driver.get(self.base_url + "sla_config")
        driver.find_element(By.LINK_TEXT, "Edited Test SLA Configuration test").click()
        driver.find_element(By.ID, "delete").click()
        self.assertTrue(self.is_success_message_present(text="SLA Configuration Deleted."))

    @on_exception_html_source_logger
    def test_delete_default_sla(self):
        driver = self.driver
        driver.get(self.base_url + "sla_config")
        driver.find_element(By.LINK_TEXT, "Default").click()
        driver.find_element(By.ID, "delete").click()
        self.assertTrue(self.is_error_message_present(text="The Default SLA Configuration cannot be deleted."))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(BaseTestCase("disable_block_execution"))
    suite.addTest(SLAConfigurationTest("test_add_sla_config"))
    suite.addTest(SLAConfigurationTest("test_edit_sla_config"))
    suite.addTest(SLAConfigurationTest("test_delete_sla_config"))
    suite.addTest(SLAConfigurationTest("test_delete_default_sla"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
