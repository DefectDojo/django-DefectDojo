import unittest
import sys
import os

from base_test_class import BaseTestCase


class RegulationTest(BaseTestCase):

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_disable_scanner(self):
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        driver.find_element_by_link_text("Burp Scan").click()
        checkbox = driver.find_element_by_id("id_enabled")
        if checkbox.is_selected():
            checkbox.click()

        driver.find_element_by_css_selector(".col-sm-offset-2 > .btn").click()
        self.assertTrue((self.is_success_message_present(text="Tool Type Successfully Updated.") and
                         driver.find_element_by_css_selector("tr:nth-child(9) > td > b").text == "Disabled"
                         ))

    def test_delete_scanner(self):
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        driver.find_element_by_xpath("//table[@id='products']/tbody/tr/td[4]/div/a[2]").click()
        self.assertTrue(self.is_success_message_present(text="Tool Type Successfully Deleted."))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(RegulationTest('test_disable_scanner'))
<<<<<<< HEAD
    suite.addTest(RegulationTest('test_delete_scanner'))
=======
    # suite.addTest(RegulationTest('test_edit_regulation'))
    # suite.addTest(RegulationTest('test_delete_regulation'))
>>>>>>> Add: Disable Nexpose test
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
