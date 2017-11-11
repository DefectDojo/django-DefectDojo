from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoAlertPresentException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from contextlib import contextmanager
from selenium.webdriver.common.proxy import *
import unittest, time, re
import os

class DojoTests(unittest.TestCase):
    def setUp(self):
        myProxy = "127.0.0.1:8080"

        proxy = Proxy({
        'proxyType': ProxyType.MANUAL,
        'httpProxy': myProxy,
        'ftpProxy': myProxy,
        'sslProxy': myProxy,
        'noProxy':''})

        self.driver = webdriver.Chrome('chromedriver')
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:8000/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DOJO_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DOJO_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_login(self):
        driver = self.login_page()
        loginTxt = driver.find_element_by_tag_name("BODY").text
        #print loginTxt
        self.assertTrue(re.search(r'Team Dashboard', loginTxt))

    def test_create_product(self):
        driver = self.login_page()
        driver.get(self.base_url + "product")
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Add Product").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("QA Test")
        driver.find_element_by_id("id_description").clear()
        driver.find_element_by_id("id_description").send_keys("QA Test 1 Description")
        Select(driver.find_element_by_id("id_prod_type")).select_by_visible_text("Research and Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Product added successfully', productTxt))

    def test_engagement(self):
        driver = self.login_page()
        driver = self.driver
        driver.get(self.base_url + "product")
        driver.find_element_by_link_text("Product List").click()
        driver.find_element_by_xpath("//table[@id='products']/tbody/tr[1]/td[5]/a").click()

        driver.find_element_by_id("id_pen_test").click()
        driver.find_element_by_id("id_check_list").click()

        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("New QA Engagement")
        driver.find_element_by_id("id_target_start").clear()
        driver.find_element_by_id("id_target_start").send_keys("2016-09-01")
        driver.find_element_by_id("id_name").click()
        driver.find_element_by_id("id_target_end").click()
        driver.find_element_by_id("id_target_end").send_keys("2016-09-02")
        driver.find_element_by_link_text("15").click()
        Select(driver.find_element_by_id("id_lead")).select_by_value("1")
        #driver.execute_script("return arguments[0].scrollIntoView();", driver.find_element_by_id("id_check_list"))
        #driver.execute_script("window.scrollBy(0, 250);")
        #wait = WebDriverWait(driver, 10)
        #element = wait.until(EC.element_to_be_clickable((By.ID,'id_pen_test')))

        driver.find_element_by_css_selector("input[name=\"_Add Tests\"]").click()
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Pen Test")
        driver.find_element_by_id("id_target_start").clear()
        driver.find_element_by_id("id_target_start").send_keys("2016-09-01")
        #driver.find_element_by_id("id_target_start").click()
        #driver.find_element_by_link_text("15").click()
        driver.find_element_by_id("id_target_end").click()
        #driver.find_element_by_id("id_target_end").send_keys("2016-09-02")
        driver.find_element_by_link_text("22").click()
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_id("id_percent_complete").clear()
        driver.find_element_by_id("id_percent_complete").send_keys("50")
        #driver.find_element_by_id("id_percent_complete").click()
        driver.find_element_by_css_selector("input[name=\"_Add Findings\"]").click()

        driver.find_element_by_id("id_title").clear()
        driver.find_element_by_id("id_title").send_keys("Test Finding")
        driver.find_element_by_id("id_description").clear()
        driver.find_element_by_id("id_description").send_keys("Description")
        driver.find_element_by_id("id_mitigation").clear()
        driver.find_element_by_id("id_mitigation").send_keys("Mitigation")
        driver.find_element_by_id("id_impact").clear()
        driver.find_element_by_id("id_impact").send_keys("Impact")
        driver.find_element_by_name("_Finished").click()

        findingTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Finding added successfully', findingTxt))

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

def suite():
    suite = unittest.TestSuite()
    suite.addTest(DojoTests('test_login'))
    suite.addTest(DojoTests('test_create_product'))
    #suite.addTest(DojoTests('test_engagement'))
    return suite

if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    runner.run(suite())
