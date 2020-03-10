from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import unittest
import os

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
            # dd_driver_options.add_argument("--headless")
            dd_driver_options.add_experimental_option("detach", True)

            # the next 2 maybe needed in some scenario's for example on WSL or other headless situations
            # dd_driver_options.add_argument("--no-sandbox")
            # dd_driver_options.add_argument("--disable-dev-shm-usage")

            # start maximized or at least with sufficient with because datatables will hide certain controls when the screen is too narrow
            dd_driver_options.add_argument("--window-size=1280,768")
            # dd_driver_options.add_argument("--start-maximized")

            # some extra logging can be turned on if you want to query the browser javascripe console in your tests
            # desired = webdriver.DesiredCapabilities.CHROME
            # desired['loggingPrefs'] = {'browser': 'ALL'}

            # change path of chromedriver according to which directory you have chromedriver.
            dd_driver = webdriver.Chrome('chromedriver', chrome_options=dd_driver_options)
            dd_driver.implicitly_wait(30)

        cls.driver = dd_driver

        # print('launching browser for: ', cls.__name__)
        # # change path of chromedriver according to which directory you have chromedriver.
        # cls.options = Options()
        # cls.options.add_argument("--headless")
        # # cls.options.add_experimental_option("detach", True)
        # # cls.options.add_argument("--no-sandbox")
        # # cls.options.add_argument("--disable-dev-shm-usage")
        # cls.driver = webdriver.Chrome('chromedriver', chrome_options=cls.options)
        # cls.driver.implicitly_wait(30)
        cls.base_url = os.environ['DD_BASE_URL']

    def setUp(self):
        self.verificationErrors = []
        self.accept_next_alert = True
        # clear browser console logs?

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

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
        self.assertEqual([], self.verificationErrors)

    @classmethod
    def tearDownDriver(cls):
        print('tearDownDriver: ', cls.__name__)
        global dd_driver
        if dd_driver:
            if not dd_driver_options.experimental_options or not dd_driver_options.experimental_options['detach']:
                print('closing browser')
                dd_driver.quit()
