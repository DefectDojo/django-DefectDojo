# -*- coding: utf-8 -*-
import requests
from base_test_class import BaseTestCase


class Login(BaseTestCase):
    def test_engagement_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "engagement"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_product_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "product"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_finding_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "finding/open"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_endpoint_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "endpoint"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_user_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "user"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_calendar_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "calendar"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_product_type_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "metrics/product/type"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_type_count_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "metrics/product/type/counts"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_simple_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "metrics/simple"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_engineer_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "metrics/engineer"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_research_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "metrics/research"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)

    def test_metric_dashboard_status(self):
        driver = self.login_page()
        cookies = driver.get_cookies()
        url = self.base_url + "metrics?date=5&view=dashboard"
        s = requests.Session()
        for cookie in cookies:
            s.cookies.set(cookie['name'], cookie['value'])
        r = s.get(url)
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        BaseTestCase.tearDownDriver()
