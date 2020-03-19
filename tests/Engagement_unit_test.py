from selenium.webdriver.support.ui import Select
import unittest
import re
import sys
from base_test_class import BaseTestCase
from Product_unit_test import ProductTest


class EngagementTest(BaseTestCase):

    def test_add_new_engagement(self):
        driver = self.login_page()
        driver.get(self.base_url + "product")
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("Add New Engagement").click()
        driver.find_element_by_id("id_name").send_keys("test engagement")
        driver.find_element_by_id("id_name").send_keys("\tthis is engagement test.")
        driver.find_element_by_id("id_test_strategy").clear()
        driver.find_element_by_id('id_test_strategy').send_keys("http://localhost:5000")
        Select(driver.find_element_by_id("id_status")).select_by_visible_text("In Progress")
        driver.find_element_by_css_selector("input[value='Done']").click()
        EngagementTXT = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', EngagementTXT))

    def test_edit_created_new_engagement(self):
        driver = self.login_page()
        driver.get(self.base_url + "product")
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("View Engagements").click()
        driver.find_element_by_link_text("test engagement").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Edit Engagement").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("edited test engagement")
        Select(driver.find_element_by_id("id_status")).select_by_visible_text("In Progress")
        driver.find_element_by_css_selector("input[value='Done']").click()
        EngagementTXT = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement updated successfully.', EngagementTXT))

    def test_close_new_engagement(self):
        driver = self.login_page()
        driver.get(self.base_url + "product")
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text("View Engagements").click()
        driver.find_element_by_link_text("edited test engagement").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Close Engagement").click()
        EngagementTXT = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement closed successfully.', EngagementTXT))

    def test_delete_new_closed_engagement(self):
        driver = self.login_page()
        driver.get(self.base_url + "product")
        driver.find_element_by_class_name("pull-left").click()
        driver.find_element_by_link_text('View Engagements').click()
        driver.find_element_by_link_text("edited test engagement").click()
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text('Delete Engagement').click()
        driver.find_element_by_name('delete_name').click()
        EngagementTXT = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement and relationships removed.', EngagementTXT))

    def test_new_ci_cd_engagement(self):
        driver = self.login_page()
        driver.get(self.base_url + "product")
        driver.find_element_by_link_text('QA Test').click()
        driver.find_element_by_xpath("//a[@class='dropdown-toggle active']//span[@class='hidden-xs']").click()
        driver.find_element_by_link_text('Add New CI/CD Engagement').click()
        driver.find_element_by_id("id_name").send_keys("test new ci/cd engagement")
        driver.find_element_by_id("id_name").send_keys("\ttest new ci/cd engagement")
        driver.find_element_by_id('id_deduplication_on_engagement').get_attribute('checked')
        driver.find_element_by_css_selector("input[value='Done']").click()
        EngagementTXT = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Engagement added successfully.', EngagementTXT))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(EngagementTest('test_add_new_engagement'))
    suite.addTest(EngagementTest('test_edit_created_new_engagement'))
    suite.addTest(EngagementTest('test_close_new_engagement'))
    suite.addTest(EngagementTest('test_delete_new_closed_engagement'))
    suite.addTest(EngagementTest('test_new_ci_cd_engagement'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
