# -*- coding: utf-8 -*-
from selenium import webdriver
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
        self.driver = webdriver.Firefox()
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
        cookies = driver.get_cookies()
        url = self.base_url+ "engagement"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_product_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "product"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_finding_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "finding/open"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)


    def test_endpoint_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "endpoint"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_user_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "user"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_calendar_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "calendar"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_product_type_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "metrics/product/type"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_type_count_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "metrics/product/type/counts"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_simple_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "metrics/simple"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_engineer_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "metrics/engineer"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_research_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "metrics/research"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_research_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "metrics/research"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_dashboard_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url+ "metrics?date=5&view=dashboard"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)


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