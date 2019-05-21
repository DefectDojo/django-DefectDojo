from selenium import webdriver
from selenium.webdriver.support.ui import Select
import unittest
import re
import sys
Import os


class ProductTest(unittest.TestCase):
    def setUp(self):
        # Initialize the driver
        # When used with Travis, chromdriver is stored in the same
        # directory as the unit tests
        self.driver = webdriver.Chrome('chromedriver')
        # Allow a little time for the driver to initialize
        self.driver.implicitly_wait(30)
        # Set the base address of the dojo
        self.base_url = "http://localhost:8000/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        # Make a member reference to the driver
        driver = self.driver
        # Navigate to the login page
        driver.get(self.base_url + "login")
        # Good practice to clear the entry before typing
        driver.find_element_by_id("id_username").clear()
        # These credentials will be used by Travis when testing new PRs
        # They will not work when testing on your own build
        # Be sure to change them before submitting a PR
        driver.find_element_by_id("id_username").send_keys(os.environ['DOJO_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DOJO_ADMIN_PASSWORD'])
        # "Click" the but the login button
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_create_product(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown button to see options
        driver.find_element_by_id("dropdownMenu1").click()
        # "Click" the add prodcut button
        driver.find_element_by_link_text("Add Product").click()
        # Fill in th product name
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("QA Test")
        # Tab into the description area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_element_by_id("id_name").send_keys("\tThis is just a test. Be very afraid.")
        # Select an option in the poroduct type
        Select(driver.find_element_by_id("id_prod_type")).select_by_visible_text("Research and Development")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Product added successfully', productTxt))

    def test_edit_product_title(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
        # "Click" the edit option
        driver.find_element_by_link_text("Edit").click()
        # Clear the old product name
        driver.find_element_by_id("id_name").clear()
        # Fill in the product name
        driver.find_element_by_id("id_name").send_keys("EDITED QA Test")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Product updated successfully', productTxt))

    def test_delete_product(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
        # "Click" the edit option
        driver.find_element_by_link_text("Delete").click()
        # "Click" the delete button to complete the transaction
        driver.find_element_by_css_selector("button.btn.btn-danger").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Product and relationships removed.', productTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(ProductTest('test_edit_product_title'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
