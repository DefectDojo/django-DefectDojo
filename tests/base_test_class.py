from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

import unittest
import os
import re
import time

dd_driver = None
dd_driver_options = None


class BaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global dd_driver
        if not dd_driver:
            # setupModule and tearDownModule are not working in our scenario, so for now we use setupClass and a global variable
            # global variables are dirty, but in unit tests scenario's like these they are acceptable
            print('launching browser for: ', cls.__name__)
            global dd_driver_options
            dd_driver_options = Options()

            # headless means no UI, if you want to see what is happening remove headless. Adding detach will leave the window open after the test
            dd_driver_options.add_argument("--headless")
            # dd_driver_options.add_experimental_option("detach", True)

            # the next 2 maybe needed in some scenario's for example on WSL or other headless situations
            dd_driver_options.add_argument("--no-sandbox")
            # dd_driver_options.add_argument("--disable-dev-shm-usage")

            # start maximized or at least with sufficient with because datatables will hide certain controls when the screen is too narrow
            dd_driver_options.add_argument("--window-size=1280,1024")
            # dd_driver_options.add_argument("--start-maximized")

            dd_driver_options.set_capability("acceptInsecureCerts", True)

            # some extra logging can be turned on if you want to query the browser javascripe console in your tests
            desired = webdriver.DesiredCapabilities.CHROME
            desired['goog:loggingPrefs'] = {'browser': 'ALL'}

            # change path of chromedriver according to which directory you have chromedriver.
            print('starting chromedriver with options: ', vars(dd_driver_options), desired)
            dd_driver = webdriver.Chrome('chromedriver', chrome_options=dd_driver_options, desired_capabilities=desired)
            dd_driver.implicitly_wait(30)

        cls.driver = dd_driver
        cls.base_url = os.environ['DD_BASE_URL']

    def setUp(self):
        self.verificationErrors = []
        self.accept_next_alert = True
        self.accept_javascript_errors = False
        self.driver.execute_script("console.clear()")
        # clear browser console logs?

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        text = driver.find_element_by_tag_name("BODY").text
        self.assertFalse(re.search(r'Please enter a correct username and password', text))
        return driver

    def goto_product_overview(self, driver):
        driver.get(self.base_url + "product")
        body = driver.find_element_by_tag_name("BODY").text
        # print('BODY:')
        # print(body)
        # print('re.search:', re.search(r'No products found', body))

        if re.search(r'No products found', body):
            return driver

        # wait for product_wrapper div as datatables javascript modifies the DOM on page load.
        WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "products_wrapper")))

    def goto_active_engagements_overview(self, driver):
        # return self.goto_engagements_internal(driver, 'engagement')
        # engagement overview doesn't seem to have the datatables yet modifying the DOM
        # https://github.com/DefectDojo/django-DefectDojo/issues/2173
        driver.get(self.base_url + 'engagement')
        return driver

    def goto_all_engagements_overview(self, driver):
        return self.goto_engagements_internal(driver, 'engagements_all')

    def goto_engagements_internal(self, driver, rel_url):
        driver.get(self.base_url + rel_url)
        body = driver.find_element_by_tag_name("BODY").text
        # print('BODY:')
        # print(body)
        # print('re.search:', re.search(r'No products found', body))

        if re.search(r'No engagements found', body):
            return driver

        # wait for engagements_wrapper div as datatables javascript modifies the DOM on page load.
        WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "engagements_wrapper")))
        return driver

    def set_code_mirror_text(self, nth, text):
        # the codemirror editors do NOT have ids or name, so have to find them by class and select the n-th one.
        self.driver.execute_script("document.getElementsByClassName('CodeMirror')[" + str(nth) + "].CodeMirror.setValue('" + text + "')")
        # need to wait a little otherwise the hidden form field will still be empty and submit won't work. Welcome in 2020!
        time.sleep(1)

        # do not go xss here :-)

        # javascript is not ideal, but everything else doesn't work reliably

        # text_area = driver.find_element_by_css_selector('.CodeMirror textarea')
        # text_area.click()
        # text_area.send_keys("This is just a test. Be very afraid")

        # code_mirror_div = driver.find_element_by_class_name("CodeMirror")
        # # getting the first line of code inside codemirror and clicking it to bring it in focus
        # code_mirror_line1 = code_mirror_div.find_elements_by_class_name("CodeMirror-line")[0]
        # code_mirror_line1.click()
        # # sending keystokes to textarea once codemirror is in focus
        # text_area = code_mirror_div.find_element_by_css_selector("textarea")
        # text_area.send_keys("This is just a test. Be very afraid")

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

    def assertNoConsoleErrors(self):
        """
        Sample output for levels (i.e. errors are SEVERE)
        {'level': 'DEBUG', 'message': 'http://localhost:8080/product/type/4/edit 560:12 "debug"', 'source': 'console-api', 'timestamp': 1583952828410}
        {'level': 'INFO', 'message': 'http://localhost:8080/product/type/4/edit 561:16 "info"', 'source': 'console-api', 'timestamp': 1583952828410}
        {'level': 'WARNING', 'message': 'http://localhost:8080/product/type/4/edit 562:16 "warning"', 'source': 'console-api', 'timestamp': 1583952828410}
        {'level': 'SEVERE', 'message': 'http://localhost:8080/product/type/4/edit 563:16 "error"', 'source': 'console-api', 'timestamp': 1583952828410}
        """

        for entry in WebdriverOnlyNewLogFacade(self.driver).get_log('browser'):
            """
            images are not working in current docker/travis deployment, so ignore those 404s
            see: https://github.com/DefectDojo/django-DefectDojo/issues/2045
            examples:
            http://localhost:8080/static/dojo/img/zoom-in.cur - Failed to load resource: the server responded with a status of 404 (Not Found)
            http://localhost:8080/media/CACHE/images/finding_images/1bf9c0b1-5ed1-4b4e-9551-bcbfd198b90a/7d8d9af058566b8f2fe6548d96c63237.jpg - Failed to load resource: the server responded with a status of 404 (Not Found)
            """
            accepted_javascript_messages = r'((zoom\-in\.cur.*)|(images\/finding_images\/.*))404\ \(Not\ Found\)'

            if (entry['level'] == 'SEVERE'):
                # print(self.driver.current_url)  # TODO actually this seems to be the previous url
                # self.driver.save_screenshot("C:\\Data\\django-DefectDojo\\tests\\javascript-errors.png")
                # with open("C:\\Data\\django-DefectDojo\\tests\\javascript-errors.html", "w") as f:
                #    f.write(self.driver.page_source)

                print(entry)
                print('There was a SEVERE javascript error in the console, please check all steps fromt the current test to see where it happens')
                print('Currently there is no way to find out at which url the error happened.')
                if self.accept_javascript_errors:
                    print('WARNING: skipping SEVERE javascript error because accept_javascript_errors is True!')
                elif re.search(accepted_javascript_messages, entry['message']):
                    print('WARNING: skipping javascript errors related to finding images, see https://github.com/DefectDojo/django-DefectDojo/issues/2045')
                else:
                    # self.assertNotEqual(entry['level'], 'SEVERE')
                    return True

        return True

    def tearDown(self):
        self.assertNoConsoleErrors()

        self.assertEqual([], self.verificationErrors)

    @classmethod
    def tearDownDriver(cls):
        print('tearDownDriver: ', cls.__name__)
        global dd_driver
        if dd_driver:
            if not dd_driver_options.experimental_options or not dd_driver_options.experimental_options['detach']:
                print('closing browser')
                dd_driver.quit()


class WebdriverOnlyNewLogFacade(object):

    last_timestamp = 0

    def __init__(self, webdriver):
        self._webdriver = webdriver

    def get_log(self, log_type):
        last_timestamp = self.last_timestamp
        entries = self._webdriver.get_log(log_type)
        filtered = []

        for entry in entries:
            # check the logged timestamp against the
            # stored timestamp
            if entry["timestamp"] > self.last_timestamp:
                filtered.append(entry)

                # save the last timestamp only if newer
                # in this set of logs
                if entry["timestamp"] > last_timestamp:
                    last_timestamp = entry["timestamp"]

        # store the very last timestamp
        self.last_timestamp = last_timestamp

        return filtered


def on_exception_html_source_logger(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)

        except Exception as e:
            print(self.driver.page_source)

            with open("selenium_page_source.html", "w", encoding='utf8') as text_file:
                print(self.driver.page_source, file=text_file)

            print("exception url:", self.driver.current_url)
            time.sleep(30)
            raise(e)

    return wrapper
