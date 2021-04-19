import unittest
import sys
import os

from base_test_class import BaseTestCase


class ScanTypeTest(BaseTestCase):

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_disable_Acunetix_Scan_scanner(self):
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        driver.find_element_by_link_text("Acunetix Scan").click()
        checkbox = driver.find_element_by_id("id_enabled")
        if checkbox.is_selected():
            checkbox.click()

        driver.find_element_by_css_selector(".col-sm-offset-2 > .btn").click()
        self.assertTrue(self.is_success_message_present(text="Tool Type Successfully Updated."))

    def test_enable_Acunetix_Scan_scanner(self):
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        driver.find_element_by_link_text("Acunetix Scan").click()
        checkbox = driver.find_element_by_id("id_enabled")
        if not checkbox.get_attribute('checked'):
            checkbox.click()

        driver.find_element_by_css_selector(".col-sm-offset-2 > .btn").click()
        self.assertTrue(self.is_success_message_present(text="Tool Type Successfully Updated."))

    def test_Acunetix_Scan_visibility(self):
        driver = self.driver

        self.test_disable_Acunetix_Scan_scanner

        self.goto_product_overview(driver)
        driver.find_element_by_css_selector(".dropdown-toggle.pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Dedupe Path Test")
        driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))

        driver.find_element_by_id("id_title").send_keys("Path Test 1")
    #    print(driver.find_element_by_id("id_test_type").text)
        self.assertTrue("Acunetix_Scan" not in self.driver.find_element_by_id("id_test_type").text)

    def test_Acunetix_Scan_visibility_enable(self):
        self.test_disable_Acunetix_Scan_scanner()
        self.test_enable_Acunetix_Scan_scanner()

        driver = self.driver

        self.goto_product_overview(driver)
        driver.find_element_by_css_selector(".dropdown-toggle.pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("Test disabled Acunetix_Scan")
        driver.find_element_by_xpath('//*[@id="id_deduplication_on_engagement"]').click()
        driver.find_element_by_name("_Add Tests").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))

        driver.find_element_by_id("id_title").send_keys("Test Acunetix_Scan")
        self.assertTrue("Acunetix Scan" in self.driver.find_element_by_id("id_test_type").text)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(ScanTypeTest('test_enable_Acunetix_Scan_scanner'))
    suite.addTest(ScanTypeTest('test_Acunetix_Scan_visibility'))
    suite.addTest(ScanTypeTest('test_enable_Acunetix_Scan_scanner'))
    suite.addTest(ScanTypeTest('test_Acunetix_Scan_visibility_enable'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
