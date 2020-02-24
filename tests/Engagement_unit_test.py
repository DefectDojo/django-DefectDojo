from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import Select
import unittest
import re
import sys
import os


dir_path = os.path.dirname(os.path.realpath(__file__))
try:  # First Try for python 3
    import importlib.util
    product_unit_test_module = importlib.util.spec_from_file_location("Product_unit_test",
        os.path.join(dir_path, 'Product_unit_test.py'))  # using ',' allows python to determine the type of separator to use.
    product_unit_test = importlib.util.module_from_spec(product_unit_test_module)
    product_unit_test_module.loader.exec_module(product_unit_test)
except:  # This will work for python2 if above fails
    import imp
    product_unit_test = imp.load_source('Product_unit_test',
        os.path.join(dir_path, 'Product_unit_test.py'))


class EngagementTest(unittest.TestCase):
    def setUp(self):
        self.options = Options()
        self.options.add_argument("--headless")
        self.driver = webdriver.Chrome('chromedriver', chrome_options=self.options)
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:8080/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

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

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(product_unit_test.ProductTest('test_create_product'))
    suite.addTest(EngagementTest('test_add_new_engagement'))
    suite.addTest(EngagementTest('test_edit_created_new_engagement'))
    suite.addTest(EngagementTest('test_close_new_engagement'))
    suite.addTest(EngagementTest('test_delete_new_closed_engagement'))
    suite.addTest(EngagementTest('test_new_ci_cd_engagement'))
    suite.addTest(product_unit_test.ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
