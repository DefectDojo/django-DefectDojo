import unittest
import sys
import os
from base_test_class import BaseTestCase
from selenium.webdriver.common.by import By


class RegulationTest(BaseTestCase):

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        return driver

    def test_create_regulation(self):
        driver = self.driver
        driver.get(self.base_url + "regulations")
        driver.find_element(By.LINK_TEXT, "Regulations").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Add regulation").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("PSA_TEST")
        driver.find_element(By.ID, "id_acronym").clear()
        driver.find_element(By.ID, "id_acronym").send_keys("PSA_TEST")
        driver.find_element(By.CSS_SELECTOR, "option:nth-child(6)").click()
        driver.find_element(By.ID, "id_jurisdiction").clear()
        driver.find_element(By.ID, "id_jurisdiction").send_keys("Europe")
        driver.find_element(By.ID, "id_description").clear()
        driver.find_element(By.ID, "id_description").send_keys("Few words abot PSA")
        driver.find_element(By.ID, "id_reference").clear()
        driver.find_element(By.ID, "id_reference").send_keys("http://www.psa.eu")
        driver.find_element(By.CSS_SELECTOR, ".col-sm-offset-2 > .btn").click()

        self.assertTrue(self.is_success_message_present(text='Regulation Successfully Created.'))

    def test_edit_regulation(self):
        driver = self.driver
        driver.get(self.base_url + "regulations")
        driver.find_element(By.LINK_TEXT, "Regulations").click()
        driver.find_element(By.LINK_TEXT, "PSA_TEST").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Edited PSA test")
        driver.find_element(By.ID, "submit").click()
        self.assertTrue(self.is_success_message_present(text='Regulation Successfully Updated.'))

    def test_delete_regulation(self):
        driver = self.driver
        driver.get(self.base_url + "regulations")
        driver.find_element(By.LINK_TEXT, "Regulations").click()
        driver.find_element(By.LINK_TEXT, "Edited PSA test").click()
        driver.find_element(By.ID, "delete").click()

        self.assertTrue(self.is_success_message_present(text='Regulation Deleted.'))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(BaseTestCase('disable_block_execution'))
    suite.addTest(RegulationTest('test_create_regulation'))
    suite.addTest(RegulationTest('test_edit_regulation'))
    suite.addTest(RegulationTest('test_delete_regulation'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
