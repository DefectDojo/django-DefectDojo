from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import unittest
import re
import sys
import os


class EnvironmentTest(unittest.TestCase):
    def setUp(self):
        # change path of chromedriver according to which directory you have chromedriver.
        self.options = Options()
        self.options.add_argument("--headless")
        self.driver = webdriver.Chrome('chromedriver', chrome_options=self.options)
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:8080/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_create_environment(self):
        driver = self.login_page()
        driver.get(self.base_url + "dev_env")
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("New Environment").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("environment test")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Environment added successfully.', productTxt))

    def test_edit_environment(self):
        driver = self.login_page()
        driver.get(self.base_url + "dev_env")
        driver.find_element_by_link_text("environment test").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Edited environment test")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Environment updated successfully.', productTxt))

    def test_delete_environment(self):
        driver = self.login_page()
        driver.get(self.base_url + "dev_env")
        driver.find_element_by_link_text("Edited environment test").click()
        driver.find_element_by_css_selector("input.btn.btn-danger").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Environment deleted successfully.', productTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(EnvironmentTest('test_create_environment'))
    suite.addTest(EnvironmentTest('test_edit_environment'))
    suite.addTest(EnvironmentTest('test_delete_environment'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
