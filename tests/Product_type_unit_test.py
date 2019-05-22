from selenium import webdriver
import unittest
import re
import sys
import os


class ProductTest(unittest.TestCase):
    def setUp(self):
        # change path of chromedriver according to which directory you have chromedriver.
        self.driver = webdriver.Chrome('chromedriver')
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:8000/"
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

    def test_create_product_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "product/type")
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Add Product Type").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("product test type")
        driver.find_element_by_id("id_critical_product").click()
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Product type added successfully.', productTxt))

    def test_edit_product_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "product/type")
        driver.find_element_by_link_text("Edit Product Type").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Edited product test type")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Product type updated successfully.', productTxt))

    def test_delete_product_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "product/type")
        driver.find_element_by_link_text("Edit Product Type").click()
        driver.find_element_by_css_selector("input.btn.btn-danger").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Product type Deleted successfully.', productTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(ProductTest('test_create_product_type'))
    suite.addTest(ProductTest('test_edit_product_type'))
    suite.addTest(ProductTest('test_delete_product_type'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
