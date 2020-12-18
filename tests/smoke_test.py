from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoAlertPresentException
import unittest
import sys
from base_test_class import BaseTestCase


class DojoTests(BaseTestCase):

    def test_login(self):
        driver = self.login_page()
        self.assertTrue(self.is_text_present_on_page(text='Active Engagements'))

    # not included in suite below for unknown reasons
    def test_create_product(self):
        self.goto_product_overview(driver)
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Add Product").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("QA Test")
        driver.find_element_by_id("id_description").clear()
        driver.find_element_by_id("id_description").send_keys("QA Test 1 Description")
        Select(driver.find_element_by_id("id_prod_type")).select_by_visible_text("Research and Development")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Product added successfully'))

    # not included in suite below for unknown reasons
    def test_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
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

        driver.find_element_by_css_selector("input[name=\"_Add Tests\"]").click()
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Pen Test")
        driver.find_element_by_id("id_target_start").clear()
        driver.find_element_by_id("id_target_start").send_keys("2016-09-01")
        driver.find_element_by_id("id_target_end").click()
        driver.find_element_by_link_text("22").click()
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        driver.find_element_by_id("id_percent_complete").clear()
        driver.find_element_by_id("id_percent_complete").send_keys("50")
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

        self.assertTrue(self.is_success_message_present(text='Finding added successfully'))

    def test_search(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('finding')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_cve(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('cve:CVE-2020-12345')
        driver.find_element_by_id("simple_search_submit").click()

        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('CVE-2020-12345')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_tag(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('tag:magento')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_product_tag(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('product-tag:java')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_engagement_tag(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('engagement-tag:php')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_test_tag(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('test-tag:go')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_tags(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('tags:php')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_product_tags(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('product-tags:java')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_engagement_tags(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('engagement-tags:php')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_test_tags(self):
        # very basic search test to see if it doesn't 500
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('test-tags:go')
        driver.find_element_by_id("simple_search_submit").click()

    def test_search_id(self):
        # very basic search test to see if it doesn't 500
        driver = self.goto_some_page()
        driver.find_element_by_id("simple_search").clear()
        driver.find_element_by_id("simple_search").send_keys('id:1')
        driver.find_element_by_id("simple_search_submit").click()

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


def suite():
    suite = unittest.TestSuite()
    suite.addTest(DojoTests('test_login'))
    suite.addTest(DojoTests('test_search'))
    suite.addTest(DojoTests('test_search_cve'))
    suite.addTest(DojoTests('test_search_tag'))
    suite.addTest(DojoTests('test_search_product_tag'))
    suite.addTest(DojoTests('test_search_engagement_tag'))
    suite.addTest(DojoTests('test_search_test_tag'))
    suite.addTest(DojoTests('test_search_tags'))
    suite.addTest(DojoTests('test_search_product_tags'))
    suite.addTest(DojoTests('test_search_engagement_tags'))
    suite.addTest(DojoTests('test_search_test_tags'))
    suite.addTest(DojoTests('test_search_id'))
    test_search_product_tag
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
