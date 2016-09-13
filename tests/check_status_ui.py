# -*- coding: utf-8 -*-
from selenium import webdriver
from seleniumrequests import Firefox
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoAlertPresentException
import unittest, time, re
import os
import requests

class Login(unittest.TestCase):
    def setUp(self):
        self.driver = Firefox()
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:8000/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DOJO_ADMIN_USER'])
        driver.find_element_by_id("id_password").send_keys(os.environ['DOJO_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_engagement_status(self):
        driver = self.login_page()
        url = self.base_url+ "engagement"
        r = driver.request('GET', url)
        self.assertEqual(r.status_code, 200)


    def test_product_status(self):
        driver = self.login_page()
        url = self.base_url+ "product"
        r = driver.request('GET', url)
        self.assertEqual(r.status_code, 200)
    """
    def test_finding_status(self):
        api_key = self.get_api_key()
        api_url = self.base_url+ "api/v1/findings"
        user = os.environ['DOJO_ADMIN_USER']
        headers = {'content-type': 'application/json',
                   'Authorization': 'ApiKey %s:%s' % (user, api_key)}
        r = requests.get(api_url, headers=headers, verify=False)
        self.assertEqual(r.status_code, 200)

    def test_t_status(self):
        api_key = self.get_api_key()
        api_url = self.base_url+ "api/v1/tests"
        user = os.environ['DOJO_ADMIN_USER']
        headers = {'content-type': 'application/json',
                   'Authorization': 'ApiKey %s:%s' % (user, api_key)}
        r = requests.get(api_url, headers=headers, verify=False)
        self.assertEqual(r.status_code, 200)


    """
    def is_element_present(self, how, what):
        try: self.driver.find_element(by=how, value=what)
        except NoSuchElementException as e: return False
        return True

    def is_alert_present(self):
        try: self.driver.switch_to_alert()
        except NoAlertPresentException as e: return False
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
        finally: self.accept_next_alert = True

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)

if __name__ == "__main__":
    unittest.main()