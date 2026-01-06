import sys
import unittest

from base_test_class import BaseTestCase
from selenium.webdriver.common.by import By


class VariousPagesTest(BaseTestCase):
    def test_user_status(self):
        driver = self.driver
        driver.get(self.base_url + "user")

    def test_calendar_status(self):
        driver = self.driver
        driver.get(self.base_url + "calendar")
        # click apply to see if this helps webdriver to catch the javascript errors we're seeing
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def test_finding_group_open_status(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/open")

    def test_finding_group_all_status(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/all")

    def test_finding_group_closed_status(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/closed")

    def test_finding_group_open_filtered_status(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/open?name=CVE&severity=Medium&engagement=14&product=6")

    def test_date_filter(self):
        driver = self.driver
        # can result in an error about date not having timezone information
        driver.get(self.base_url + "finding/open?last_status_update=2")


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(VariousPagesTest("test_user_status"))
    suite.addTest(VariousPagesTest("test_calendar_status"))
    suite.addTest(VariousPagesTest("test_finding_group_open_status"))
    suite.addTest(VariousPagesTest("test_finding_group_all_status"))
    suite.addTest(VariousPagesTest("test_finding_group_closed_status"))
    suite.addTest(VariousPagesTest("test_finding_group_open_filtered_status"))
    suite.addTest(VariousPagesTest("test_date_filter"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
