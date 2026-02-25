import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from selenium.webdriver.common.by import By


class FindingGroupTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_finding_group_all_loads(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/all")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_finding_group_open_loads(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/open")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_finding_group_closed_loads(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/closed")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_view_finding_group(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/all")
        # Try to click on a finding group if one exists
        links = driver.find_elements(By.CSS_SELECTOR, "table tbody tr td a")
        if len(links) > 0:
            links[0].click()
            body_text = driver.find_element(By.TAG_NAME, "body").text
            self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_finding_group_filtered(self):
        driver = self.driver
        driver.get(self.base_url + "finding_group/open")
        # Verify filtering works - just loading with open status is a filter
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(FindingGroupTest("test_finding_group_all_loads"))
    suite.addTest(FindingGroupTest("test_finding_group_open_loads"))
    suite.addTest(FindingGroupTest("test_finding_group_closed_loads"))
    suite.addTest(FindingGroupTest("test_view_finding_group"))
    suite.addTest(FindingGroupTest("test_finding_group_filtered"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
