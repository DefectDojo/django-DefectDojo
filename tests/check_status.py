# -*- coding: utf-8 -*-
import os
import re
import time
import unittest
import sys
import requests
from base_test_class import BaseTestCase


class Login(BaseTestCase):

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


def suite():
    suite = unittest.TestSuite()
    suite.addTest(Login('setUp'))
    suite.addTest(Login('login_page'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
