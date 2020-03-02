# -*- coding: utf-8 -*-
import os
import re
import time
import unittest
import sys
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoAlertPresentException
from selenium.common.exceptions import NoSuchElementException


class Login(unittest.TestCase):
    def setUp(self):
        # change path of chromedriver according to which directory you have chromedriver.
        self.options = Options()
        self.options.add_argument("--headless")
        # self.options.add_argument("--no-sandbox")
        # self.options.add_argument("--disable-dev-shm-usage")
        self.driver = webdriver.Chrome('chromedriver', chrome_options=self.options)
        self.driver.implicitly_wait(30)
        self.base_url = os.environ['DD_BASE_URL']
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        cred_user_elem = driver.find_element_by_id("id_username")
        cred_user_elem.clear()
        cred_user_elem.send_keys(os.environ['DD_ADMIN_USER'])
        cred_pass_elem = driver.find_element_by_id("id_password")
        cred_pass_elem.clear()
        cred_pass_elem.send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def get_api_key(self):
        driver = self.login_page()
        driver.get(self.base_url + "api/key")
        time.sleep(3)
        api_text = driver.find_element_by_tag_name("BODY").text
        r_pattern = re.compile('Your current API key is (\\w+)')
        r_match = r_pattern.search(api_text)
        return r_match.group(1)

    def test_engagement_status(self):
        api_key = self.get_api_key()
        api_url = self.base_url + "api/v1/engagements"
        user = os.environ['DD_ADMIN_USER']
        headers = {'content-type': 'application/json',
                   'Authorization': 'ApiKey %s:%s' % (user, api_key)}
        r = requests.get(api_url, headers=headers, verify=False)
        self.assertEqual(r.status_code, 200)

    def test_finding_status(self):
        api_key = self.get_api_key()
        api_url = self.base_url + "api/v1/findings"
        user = os.environ['DD_ADMIN_USER']
        headers = {'content-type': 'application/json',
                   'Authorization': 'ApiKey %s:%s' % (user, api_key)}

        r = requests.get(api_url, headers=headers, verify=False)
        self.assertEqual(r.status_code, 200)

    def test_product_status(self):
        api_key = self.get_api_key()
        api_url = self.base_url + "api/v1/products"
        user = os.environ['DD_ADMIN_USER']
        headers = {'content-type': 'application/json',
                   'Authorization': 'ApiKey %s:%s' % (user, api_key)}
        r = requests.get(api_url, headers=headers, verify=False)
        self.assertEqual(r.status_code, 200)

    def test_t_status(self):
        api_key = self.get_api_key()
        api_url = self.base_url + "api/v1/tests"
        user = os.environ['DD_ADMIN_USER']
        headers = {'content-type': 'application/json',
                   'Authorization': 'ApiKey %s:%s' % (user, api_key)}
        r = requests.get(api_url, headers=headers, verify=False)
        self.assertEqual(r.status_code, 200)

    def is_element_present(self, how, what):
        try:
            self.driver.find_element(by=how, value=what)
        except NoSuchElementException as e:
            return False
        return True

    def is_alert_present(self):
        try:
            self.driver.switch_to_alert()
        except NoAlertPresentException as e:
            return False
        return True

    def close_alert_and_get_its_text(self):
        try:
            alert = self.driver.switch_to_alert()
            alert_text = alert.text
            if self.accept_next_alert:
                alert.accept()
            else:
                alert.dismiss()
            return alert_text
        finally:
            self.accept_next_alert = True

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(Login('setUp'))
    suite.addTest(Login('login_page'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
